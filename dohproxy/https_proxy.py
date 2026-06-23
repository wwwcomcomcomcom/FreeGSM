"""Transparent TLS-splitting relay for outbound TCP/443 (SNI/DPI bypass).

Why a relay and not raw packet surgery: defeating an SNI filter that reassembles
the TCP stream requires TLS *record-layer* fragmentation, which inserts a second
5-byte record header into the byte stream. You cannot insert bytes on the raw
WinDivert path without desyncing the client kernel's TCP sequence numbers (the
kernel would RST when the server ACKs bytes it never sent). So, exactly like
Intra, we terminate the connection and reframe it from a process that owns both
sockets.

Wiring reuses the WinDivert redirect trick from `tcp_proxy.py`:
  * Outbound client->server :443 packet -> remember the real server keyed by
    (src_addr, src_port), rewrite the destination to src_addr:HTTPS_PROXY_PORT,
    and inject it INBOUND so the local stack hands it to our listener.
  * relay->client packet (src port == HTTPS_PROXY_PORT) -> rewrite the source
    back to server:443 so the client's socket accepts it, inject INBOUND.

The relay's upstream sockets (relay -> real server) are bound to a reserved
source-port range that the kernel filter excludes, so they travel normally and
are never re-captured (no inject loop, no added capture cost on that leg).

Packet rewriting runs inline on the capture thread (so `_conn_map` needs no
lock); each accepted connection is then served on its own thread.
"""

from __future__ import annotations

import logging
import socket
import socketserver
import threading

from pydivert.consts import Direction

from . import config, dpi

log = logging.getLogger("dohproxy.https")

# (src_addr, src_port) -> (orig_dst_addr, orig_dst_port).
# Written by the capture thread (every client->server packet refreshes it) and
# read by handler threads. Refresh-on-every-packet makes stale entries harmless.
_conn_map: dict[tuple[str, int], tuple[str, int]] = {}


# --------------------------------------------------------------------------- #
# Packet rewriting (capture thread)
# --------------------------------------------------------------------------- #
def handle_packet(packet, send) -> None:
    if packet.is_outbound and packet.dst_port == 443:
        # The relay's own upstream sockets are excluded by the kernel filter, so
        # anything reaching here is a real client connection to redirect.
        _redirect(packet, send)
    elif packet.src_port == config.HTTPS_PROXY_PORT:
        _rewrite_reply(packet, send)
    else:
        send(packet)


def _redirect(packet, send) -> None:
    key = (packet.src_addr, packet.src_port)
    _conn_map[key] = (packet.dst_addr, packet.dst_port)
    if packet.tcp.rst:
        _conn_map.pop(key, None)

    packet.dst_addr = packet.src_addr
    packet.dst_port = config.HTTPS_PROXY_PORT
    packet.direction = Direction.INBOUND
    send(packet)


def _rewrite_reply(packet, send) -> None:
    key = (packet.dst_addr, packet.dst_port)
    server = _conn_map.get(key)
    if server is None:
        return  # unknown/teardown stray; drop
    packet.src_addr, packet.src_port = server
    packet.direction = Direction.INBOUND
    send(packet)

    if packet.tcp.rst or packet.tcp.fin:
        _conn_map.pop(key, None)


# --------------------------------------------------------------------------- #
# Reserved upstream source ports (so the relay's upstream leg is never captured)
# --------------------------------------------------------------------------- #
_port_lock = threading.Lock()
_next_port = config.UPSTREAM_PORT_BASE


def _connect_upstream(server_ip: str, server_port: int) -> socket.socket:
    """Open an upstream socket bound to a port in the reserved range and
    connected to the real server."""
    global _next_port
    base = config.UPSTREAM_PORT_BASE
    hi = base + config.UPSTREAM_PORT_COUNT
    last_err: Exception | None = None

    for _ in range(config.UPSTREAM_PORT_COUNT):
        with _port_lock:
            port = _next_port
            _next_port = port + 1 if port + 1 < hi else base

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
        except OSError as exc:  # port busy -> try the next one
            last_err = exc
            s.close()
            continue
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(config.HTTPS_CONNECT_TIMEOUT)
            s.connect((server_ip, server_port))
            s.settimeout(None)
            return s
        except OSError as exc:
            last_err = exc
            s.close()
            raise

    raise OSError(f"no free upstream port in reserved range ({last_err})")


# --------------------------------------------------------------------------- #
# Local relay server
# --------------------------------------------------------------------------- #
def _pump(src: socket.socket, dst: socket.socket) -> None:
    """Copy src -> dst until EOF, then half-close dst's write side."""
    try:
        while True:
            data = src.recv(65535)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = self.request
        peer = self.client_address
        # Redirected connections always have peer IP == this host's IP. Reject
        # anything else so we never act as an open proxy.
        if peer[0] != client.getsockname()[0]:
            return

        orig = _conn_map.get((peer[0], peer[1]))
        if orig is None:
            return
        server_ip, server_port = orig

        try:
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        try:
            upstream = _connect_upstream(server_ip, server_port)
        except OSError as exc:
            log.warning("[HTTPS] upstream %s:%d failed: %s", server_ip, server_port, exc)
            return

        try:
            self._relay(client, upstream, server_ip, server_port)
        finally:
            upstream.close()

    def _relay(self, client, upstream, server_ip, server_port) -> None:
        # Read the first client segment -- the TLS ClientHello -- and re-emit it
        # fragmented across two TLS records.
        client.settimeout(config.HTTPS_FIRST_READ_TIMEOUT)
        try:
            first = client.recv(65535)
        except (socket.timeout, OSError):
            return
        client.settimeout(None)
        if not first:
            return

        try:
            if first[0] == dpi._TLS_HANDSHAKE:
                segs = dpi.split_hello(first, config.SPLIT_MIN, config.SPLIT_MAX)
                log.info(
                    "[HTTPS] %s:%d  SNI=%s  ClientHello %dB -> %d TLS records",
                    server_ip, server_port, dpi.sni_name(first), len(first), len(segs),
                )
                for seg in segs:
                    upstream.sendall(seg)
            else:
                # Not TLS (e.g. plaintext on 443): forward untouched.
                upstream.sendall(first)
        except OSError as exc:
            log.debug("[HTTPS] %s:%d first write failed: %s", server_ip, server_port, exc)
            return

        # Dumb bidirectional pipe for the rest of the connection.
        reverse = threading.Thread(
            target=_pump, args=(upstream, client), name="https-pump", daemon=True
        )
        reverse.start()
        _pump(client, upstream)
        reverse.join(timeout=2.0)


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_server() -> socketserver.ThreadingTCPServer:
    server = _Server((config.TCP_BIND_HOST, config.HTTPS_PROXY_PORT), _Handler)
    threading.Thread(target=server.serve_forever, name="https-proxy", daemon=True).start()
    log.info(
        "HTTPS splitting relay listening on %s:%d (upstream ports %d-%d)",
        config.TCP_BIND_HOST, config.HTTPS_PROXY_PORT,
        config.UPSTREAM_PORT_BASE, config.UPSTREAM_PORT_BASE + config.UPSTREAM_PORT_COUNT - 1,
    )
    return server
