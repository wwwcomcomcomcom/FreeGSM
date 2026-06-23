"""TCP/53 handling: transparent redirect to a local DoH-terminating proxy.

A single synthesized packet cannot answer a DNS-over-TCP query (it is a
length-prefixed stream), so instead we redirect the connection to a local
server and let it speak real TCP.

Redirect recipe (proven by mitmproxy's WinDivert transparent proxy):
  * Outbound client->server packet (dst port 53): remember the original server
    keyed by (src_addr, src_port), then rewrite the destination to
    ``src_addr:PROXY_PORT`` and inject it INBOUND. Aiming at the packet's own
    source IP (a real interface address) makes the local stack deliver it to
    our listener; aiming at 127.0.0.1 does not work.
  * Proxy->client packet (src port == PROXY_PORT): look the original server up
    by (dst_addr, dst_port) and rewrite the source back to ``server:53`` so the
    client's socket accepts the reply, then inject it INBOUND.

The rewriting runs inline on the capture thread, so the connection map needs no
locking. The local server resolves each query over DoH on its own worker thread.
"""

from __future__ import annotations

import logging
import socketserver
import struct
import threading

from pydivert.consts import Direction

from . import config, doh
from .dnsutil import describe_query

log = logging.getLogger("dohproxy.tcp")

# (src_addr, src_port) -> (orig_dst_addr, orig_dst_port). Accessed only from the
# capture thread.
_conn_map: dict[tuple[str, int], tuple[str, int]] = {}


# --------------------------------------------------------------------------- #
# Packet rewriting (runs on the capture thread)
# --------------------------------------------------------------------------- #
def handle_packet(packet, send) -> None:
    """Dispatch a captured TCP packet to the redirect or reply-rewrite path."""
    if packet.dst_port == 53 and packet.is_outbound:
        _redirect_to_proxy(packet, send)
    elif packet.src_port == config.TCP_PROXY_PORT:
        _rewrite_reply(packet, send)
    else:
        # Shouldn't happen given the filter; pass it through untouched.
        send(packet)


def _redirect_to_proxy(packet, send) -> None:
    key = (packet.src_addr, packet.src_port)
    _conn_map[key] = (packet.dst_addr, packet.dst_port)
    # Forget the mapping once the client tears the connection down.
    if packet.tcp.rst:
        _conn_map.pop(key, None)

    packet.dst_addr = packet.src_addr
    packet.dst_port = config.TCP_PROXY_PORT
    packet.direction = Direction.INBOUND
    send(packet)


def _rewrite_reply(packet, send) -> None:
    key = (packet.dst_addr, packet.dst_port)
    server = _conn_map.get(key)
    if server is None:
        # Unknown connection (e.g. a stray packet); drop it.
        return
    packet.src_addr, packet.src_port = server
    packet.direction = Direction.INBOUND
    send(packet)

    if packet.tcp.rst or packet.tcp.fin:
        _conn_map.pop(key, None)


# --------------------------------------------------------------------------- #
# Local DoH-terminating TCP server
# --------------------------------------------------------------------------- #
def _recv_exactly(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return bytes(buf)
        buf.extend(chunk)
    return bytes(buf)


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        # Only ever serve the local host itself. Redirected connections always
        # have peer IP == local IP, so this rejects any real external client
        # and prevents acting as an open resolver.
        if self.client_address[0] != sock.getsockname()[0]:
            return

        while True:
            header = _recv_exactly(sock, 2)
            if len(header) < 2:
                return
            (length,) = struct.unpack("!H", header)
            query = _recv_exactly(sock, length)
            if len(query) < length:
                return

            desc = describe_query(query)
            log.info("[INTERCEPT] TCP  %s  (from %s)", desc, self.client_address[0])

            try:
                answer = doh.resolve(query)
            except Exception as exc:  # noqa: BLE001 - fail-closed
                log.warning("[FAILED]    TCP  %s  -> DoH error: %s; closing", desc, exc)
                return  # closing the socket = fail-closed for this query

            log.info("[RESOLVED]  TCP  %s  -> %d bytes", desc, len(answer))
            sock.sendall(struct.pack("!H", len(answer)) + answer)


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_server() -> socketserver.ThreadingTCPServer:
    server = _Server((config.TCP_BIND_HOST, config.TCP_PROXY_PORT), _Handler)
    threading.Thread(target=server.serve_forever, name="tcp-proxy", daemon=True).start()
    log.info("TCP DoH proxy listening on %s:%d", config.TCP_BIND_HOST, config.TCP_PROXY_PORT)
    return server
