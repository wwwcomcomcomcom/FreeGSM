"""Local DoH-terminating DNS resolver (macOS).

Listens on loopback for plaintext DNS (UDP/53 + TCP/53) and re-resolves every
query over DoH. A DNS query and a DoH request body are the same bytes
(RFC 8484), so this is just: receive the query bytes, ``doh.resolve`` them,
return the response bytes -- no DNS parsing.

This replaces the Windows udp_handler/tcp_proxy packet-rewriting handlers
(which import pydivert and cannot load on macOS). Binding to 127.0.0.1 -- not
0.0.0.0 -- means only the local host can reach it, so it is never an open
resolver.

Fail-closed: on any DoH error the query is dropped (UDP: no reply sent;
TCP: connection closed), never answered in plaintext.
"""

from __future__ import annotations

import logging
import socket
import socketserver
import struct
import threading
from concurrent.futures import ThreadPoolExecutor

from .. import config, doh, netutil
from ..dnsutil import describe_query, truncated_response, udp_payload_limit

log = logging.getLogger("dohproxy.macos.resolver")


# --------------------------------------------------------------------------- #
# UDP/53
# --------------------------------------------------------------------------- #
class _UDPResolver:
    """UDP DNS listener. Each query's blocking DoH round-trip runs on a worker
    thread so slow upstreams don't stall other queries."""

    def __init__(self) -> None:
        self._sock: socket.socket | None = None
        self._pool = ThreadPoolExecutor(
            max_workers=config.WORKER_THREADS, thread_name_prefix="doh-udp"
        )
        # Bound in-flight work so a burst of UDP/53 can't grow the executor's
        # queue unboundedly while workers block on slow DoH. Excess queries are
        # dropped (fail-closed) rather than buffered into OOM.
        self._inflight = threading.BoundedSemaphore(config.WORKER_THREADS * 2)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((config.LOCAL_DNS_HOST, config.LOCAL_DNS_PORT))
        self._sock = s
        self._thread = threading.Thread(target=self._serve, name="udp-resolver", daemon=True)
        self._thread.start()
        log.info("UDP DoH resolver listening on %s:%d",
                 config.LOCAL_DNS_HOST, config.LOCAL_DNS_PORT)

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                query, client = self._sock.recvfrom(65535)
            except OSError:
                break  # socket closed by stop()
            if query:
                if self._inflight.acquire(blocking=False):
                    try:
                        self._pool.submit(self._handle, query, client)
                    except RuntimeError:
                        # Pool already shut down (we're stopping): the task that
                        # would have released this permit in its finally never
                        # runs, so release it here to avoid leaking it.
                        self._inflight.release()
                else:
                    log.warning("UDP work queue full; dropping query (fail-closed)")

    def _handle(self, query: bytes, client) -> None:
        try:
            self._resolve_and_reply(query, client)
        finally:
            self._inflight.release()

    def _resolve_and_reply(self, query: bytes, client) -> None:
        desc = describe_query(query)
        log.info("[INTERCEPT] UDP  %s", desc)
        try:
            answer = doh.resolve(query)
        except Exception as exc:  # noqa: BLE001 - fail-closed
            log.warning("[FAILED]    UDP  %s  -> DoH error: %s; dropped", desc, exc)
            return
        log.info("[RESOLVED]  UDP  %s  -> %d bytes", desc, len(answer))
        # Oversized answer -> truncated reply so the client retries over TCP
        # rather than relying on IP fragmentation (often dropped by DPI boxes).
        if len(answer) > udp_payload_limit(query):
            tc = truncated_response(query)
            if tc is not None:
                log.info("[TRUNCATE]  UDP  %s  -> %dB > client limit; TC=1 (retry TCP)",
                         desc, len(answer))
                answer = tc
        assert self._sock is not None
        try:
            self._sock.sendto(answer, client)
        except OSError:
            pass

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self._pool.shutdown(wait=False)


# --------------------------------------------------------------------------- #
# TCP/53 (length-prefixed DNS stream)
# --------------------------------------------------------------------------- #
class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        # Reap a stalled/idle DNS-over-TCP stream so it can't pin a thread; DNS
        # clients reconnect freely (RFC 7766).
        sock.settimeout(config.DNS_TCP_IDLE_TIMEOUT)
        try:
            self._serve(sock)
        except OSError:  # includes socket.timeout
            return

    def _serve(self, sock) -> None:
        while True:
            header = netutil.recv_exactly(sock, 2)
            if len(header) < 2:
                return
            (length,) = struct.unpack("!H", header)
            if length == 0:
                continue  # empty frame; nothing to resolve, keep the stream open
            query = netutil.recv_exactly(sock, length)
            if len(query) < length:
                return

            desc = describe_query(query)
            log.info("[INTERCEPT] TCP  %s", desc)
            try:
                answer = doh.resolve(query)
            except Exception as exc:  # noqa: BLE001 - fail-closed
                log.warning("[FAILED]    TCP  %s  -> DoH error: %s; closing", desc, exc)
                return  # closing the socket = fail-closed for this query
            log.info("[RESOLVED]  TCP  %s  -> %d bytes", desc, len(answer))
            sock.sendall(struct.pack("!H", len(answer)) + answer)


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #
class Resolver:
    """Owns both the UDP and TCP loopback DNS listeners."""

    def __init__(self) -> None:
        self._udp = _UDPResolver()
        self._tcp: _TCPServer | None = None

    def start(self) -> None:
        self._udp.start()
        self._tcp = _TCPServer(
            (config.LOCAL_DNS_HOST, config.LOCAL_DNS_PORT), _TCPHandler
        )
        threading.Thread(
            target=self._tcp.serve_forever, name="tcp-resolver", daemon=True
        ).start()
        log.info("TCP DoH resolver listening on %s:%d",
                 config.LOCAL_DNS_HOST, config.LOCAL_DNS_PORT)

    def stop(self) -> None:
        self._udp.stop()
        if self._tcp is not None:
            try:
                self._tcp.shutdown()
            except Exception:  # noqa: BLE001
                pass
