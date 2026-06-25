"""Transparent UDP relay for outbound QUIC / HTTP-3 (UDP/443).

This uses the same WinDivert redirect trick as the TCP relays:
  * outbound client->server UDP/443 packets are rewritten to this host's
    QUIC_PROXY_PORT and injected inbound so a local UDP socket receives them
  * relay->client packets (src port == QUIC_PROXY_PORT) are rewritten back to
    server:443 so the application's socket accepts them

Unlike the TCP/443 relay, this module does not modify QUIC payload bytes; it
simply forwards them from a userspace socket whose upstream source port lives in
the reserved range excluded by the WinDivert filter.
"""

from __future__ import annotations

import logging
import socket
import socketserver
import threading
import time

from pydivert.consts import Direction

from . import config

log = logging.getLogger("dohproxy.quic")

# (src_addr, src_port) -> (orig_dst_addr, orig_dst_port). Written only on the
# capture thread, read by UDP handler threads.
_conn_map: dict[tuple[str, int], tuple[str, int]] = {}


def handle_packet(packet, send) -> None:
    """Dispatch a captured UDP/443 packet to redirect or reply-rewrite."""
    if packet.is_outbound and packet.dst_port == 443:
        _redirect(packet, send)
    elif packet.src_port == config.QUIC_PROXY_PORT:
        _rewrite_reply(packet, send)
    else:
        send(packet)


def _redirect(packet, send) -> None:
    _conn_map[(packet.src_addr, packet.src_port)] = (packet.dst_addr, packet.dst_port)
    packet.dst_addr = packet.src_addr
    packet.dst_port = config.QUIC_PROXY_PORT
    packet.direction = Direction.INBOUND
    send(packet)


def _rewrite_reply(packet, send) -> None:
    server = _conn_map.get((packet.dst_addr, packet.dst_port))
    if server is None:
        return
    packet.src_addr, packet.src_port = server
    packet.direction = Direction.INBOUND
    send(packet)


_port_lock = threading.Lock()
_next_port = config.UPSTREAM_PORT_BASE


def _connect_upstream(server_ip: str, server_port: int) -> socket.socket:
    """Open a connected UDP socket bound inside the excluded port range."""
    global _next_port
    base = config.UPSTREAM_PORT_BASE
    hi = base + config.UPSTREAM_PORT_COUNT
    last_err: Exception | None = None

    for _ in range(config.UPSTREAM_PORT_COUNT):
        with _port_lock:
            port = _next_port
            _next_port = port + 1 if port + 1 < hi else base

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("0.0.0.0", port))
            sock.connect((server_ip, server_port))
            sock.settimeout(1.0)
            return sock
        except OSError as exc:
            last_err = exc
            sock.close()

    raise OSError(f"no free upstream UDP port in reserved range ({last_err})")


class _Session:
    def __init__(
        self,
        client_addr: tuple[str, int],
        server_addr: tuple[str, int],
        upstream: socket.socket,
        relay_sock: socket.socket,
    ) -> None:
        self.client_addr = client_addr
        self.server_addr = server_addr
        self.upstream = upstream
        self.relay_sock = relay_sock
        self.closed = threading.Event()
        self.last_seen = time.monotonic()
        self.thread = threading.Thread(
            target=self._pump_replies,
            name=f"quic-upstream-{client_addr[1]}",
            daemon=True,
        )
        self.thread.start()

    def touch(self) -> None:
        self.last_seen = time.monotonic()

    def close(self) -> None:
        if self.closed.is_set():
            return
        self.closed.set()
        try:
            self.upstream.close()
        except OSError:
            pass

    def _pump_replies(self) -> None:
        try:
            while not self.closed.is_set():
                if time.monotonic() - self.last_seen > config.QUIC_IDLE_TIMEOUT:
                    return
                try:
                    payload = self.upstream.recv(65535)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if not payload:
                    continue
                self.relay_sock.sendto(payload, self.client_addr)
                self.touch()
        finally:
            _drop_session(self.client_addr, self)


_sessions: dict[tuple[str, int], _Session] = {}
_sessions_lock = threading.Lock()


def _drop_session(client_addr: tuple[str, int], session: _Session) -> None:
    with _sessions_lock:
        current = _sessions.get(client_addr)
        if current is session:
            _sessions.pop(client_addr, None)
    session.close()


def _get_or_create_session(
    client_addr: tuple[str, int],
    server_addr: tuple[str, int],
    relay_sock: socket.socket,
) -> _Session | None:
    with _sessions_lock:
        session = _sessions.get(client_addr)
        if session is not None and session.server_addr == server_addr and not session.closed.is_set():
            session.touch()
            return session

        if session is not None:
            session.close()

        try:
            upstream = _connect_upstream(*server_addr)
        except OSError as exc:
            log.warning("[QUIC] upstream %s:%d failed: %s", server_addr[0], server_addr[1], exc)
            return None

        session = _Session(client_addr, server_addr, upstream, relay_sock)
        _sessions[client_addr] = session
        return session


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        payload, relay_sock = self.request
        if not payload:
            return

        client_addr = (self.client_address[0], self.client_address[1])
        server_addr = _conn_map.get(client_addr)
        if server_addr is None:
            return

        session = _get_or_create_session(client_addr, server_addr, relay_sock)
        if session is None:
            return

        try:
            session.upstream.send(payload)
            session.touch()
        except OSError as exc:
            log.debug("[QUIC] send failed for %s -> %s:%d: %s", client_addr, server_addr[0], server_addr[1], exc)
            _drop_session(client_addr, session)


class _Server(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_server() -> socketserver.ThreadingUDPServer:
    server = _Server((config.TCP_BIND_HOST, config.QUIC_PROXY_PORT), _Handler)
    threading.Thread(target=server.serve_forever, name="quic-proxy", daemon=True).start()
    log.info(
        "QUIC relay listening on %s:%d (upstream ports %d-%d)",
        config.TCP_BIND_HOST,
        config.QUIC_PROXY_PORT,
        config.UPSTREAM_PORT_BASE,
        config.UPSTREAM_PORT_BASE + config.UPSTREAM_PORT_COUNT - 1,
    )
    return server
