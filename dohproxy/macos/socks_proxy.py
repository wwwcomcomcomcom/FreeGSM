"""Local SOCKS5 proxy that fragments the TLS ClientHello (macOS DPI bypass).

In the macOS DPI design, tun2socks reads the utun device, terminates each
outbound TCP flow, and forwards it here as a SOCKS5 CONNECT. This proxy:

  * opens an upstream socket to the real destination, PINNED to the physical
    interface via IP_BOUND_IF so it bypasses utun (no routing loop -- the macOS
    analogue of the WinDivert reserved-port exclusion);
  * for :443, re-emits the first client segment (the ClientHello) as two TLS
    records via dpi.split_hello, so a one-record SNI matcher can't read the
    host; for any other port it just pipes through;
  * then runs a dumb bidirectional pipe.

Only CONNECT is supported. It binds 127.0.0.1 so only local clients (tun2socks)
can reach it. The split/relay logic mirrors the Windows https_proxy relay, but
this module imports no pydivert so it loads on macOS.
"""

from __future__ import annotations

import logging
import socket
import socketserver
import struct
import subprocess
import threading

from .. import config, netutil

log = logging.getLogger("dohproxy.macos.socks")

# macOS socket options to pin a socket to a specific interface (bypass utun).
IP_BOUND_IF = 25
IPV6_BOUND_IF = 125

# Physical interface index that upstream sockets are pinned to. Set at start.
_bound_if_index = 0


def physical_iface() -> str | None:
    """Default-route interface name (e.g. 'en0')."""
    try:
        out = subprocess.run(
            ["route", "-n", "get", "default"], capture_output=True, text=True, check=True
        ).stdout
    except subprocess.CalledProcessError:
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            return line.split()[1]
    return None


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _connect_upstream(host: str, port: int, family: int) -> socket.socket:
    s = socket.socket(family, socket.SOCK_STREAM)
    # Pin to the physical interface so this leg never re-enters utun.
    if _bound_if_index:
        try:
            if family == socket.AF_INET6:
                s.setsockopt(socket.IPPROTO_IPV6, IPV6_BOUND_IF, _bound_if_index)
            else:
                s.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, _bound_if_index)
        except OSError as exc:
            log.debug("IP_BOUND_IF failed: %s", exc)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(config.HTTPS_CONNECT_TIMEOUT)
    s.connect((host, port))
    s.settimeout(None)
    return s


# --------------------------------------------------------------------------- #
# SOCKS5
# --------------------------------------------------------------------------- #
class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        c = self.request
        try:
            self._serve(c)
        except OSError as exc:
            log.debug("socks conn error: %s", exc)

    def _serve(self, c: socket.socket) -> None:
        # Greeting: VER=5, NMETHODS, methods[]
        head = netutil.recv_exactly(c, 2)
        if len(head) < 2 or head[0] != 0x05:
            return
        nmethods = head[1]
        if len(netutil.recv_exactly(c, nmethods)) < nmethods:
            return  # truncated greeting
        c.sendall(b"\x05\x00")  # no authentication

        # Request: VER CMD RSV ATYP DST.ADDR DST.PORT
        req = netutil.recv_exactly(c, 4)
        if len(req) < 4 or req[0] != 0x05:
            return
        cmd, atyp = req[1], req[3]
        if cmd != 0x01:  # only CONNECT
            c.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")  # cmd not supported
            return

        if atyp == 0x01:  # IPv4
            addr = netutil.recv_exactly(c, 4)
            if len(addr) < 4:
                return
            host = socket.inet_ntoa(addr)
            family = socket.AF_INET
        elif atyp == 0x04:  # IPv6
            addr = netutil.recv_exactly(c, 16)
            if len(addr) < 16:
                return
            host = socket.inet_ntop(socket.AF_INET6, addr)
            family = socket.AF_INET6
        elif atyp == 0x03:  # domain name
            dlen = netutil.recv_exactly(c, 1)
            if not dlen:
                return
            name = netutil.recv_exactly(c, dlen[0])
            if len(name) < dlen[0]:
                return  # truncated host name
            try:
                host = name.decode("ascii")  # IDNs arrive as ASCII punycode
            except UnicodeDecodeError:
                # Dropping non-ASCII bytes ("ignore") could turn one host name
                # into a different valid one; reject instead.
                c.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")  # host unreachable
                return
            family = 0  # resolve below
        else:
            c.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")  # atyp not supported
            return
        portb = netutil.recv_exactly(c, 2)
        if len(portb) < 2:
            return  # truncated port
        (port,) = struct.unpack("!H", portb)

        # Resolve domain (tun2socks normally sends an IP, but support both).
        if family == 0:
            try:
                ai = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)[0]
                family, _, _, _, sa = ai
                host = sa[0]
            except OSError:
                c.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")  # host unreachable
                return

        try:
            upstream = _connect_upstream(host, port, family)
        except OSError as exc:
            log.warning("[SOCKS] upstream %s:%d failed: %s", host, port, exc)
            c.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")  # connection refused
            return

        # Success reply (BND.ADDR/PORT are ignored by clients; send zeros).
        c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

        try:
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        try:
            netutil.split_relay(c, upstream, host, port, log, "SOCKS")
        finally:
            upstream.close()


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_server(bound_iface: str | None = None) -> socketserver.ThreadingTCPServer:
    """Start the SOCKS5 splitting proxy. ``bound_iface`` is the physical
    interface (default: auto-detect) that upstream sockets are pinned to.

    Raises RuntimeError if the interface index can't be determined: without the
    IP_BOUND_IF pin the upstream sockets would follow the utun default route and
    loop straight back into this proxy, so we refuse to start (fail-closed)
    rather than serve a routing loop.
    """
    global _bound_if_index
    iface = bound_iface or physical_iface()
    if iface:
        try:
            _bound_if_index = socket.if_nametoindex(iface)
        except OSError:
            _bound_if_index = 0
    if not _bound_if_index:
        raise RuntimeError(
            f"could not determine physical interface index (iface={iface!r}); "
            "refusing to start SOCKS proxy to avoid a utun routing loop"
        )
    log.info("upstream sockets pinned to %s (if_index=%d)", iface, _bound_if_index)

    server = _Server((config.SOCKS_PROXY_HOST, config.SOCKS_PROXY_PORT), _Handler)
    threading.Thread(target=server.serve_forever, name="socks-proxy", daemon=True).start()
    log.info("SOCKS5 splitting proxy listening on %s:%d",
             config.SOCKS_PROXY_HOST, config.SOCKS_PROXY_PORT)
    return server
