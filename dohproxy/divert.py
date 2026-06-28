"""WinDivert capture loop and dispatch.

One WinDivert handle drives everything. The capture thread classifies each
packet and either:
  * offloads UDP/53 queries to a thread pool (each does a blocking DoH
    round-trip before injecting the reply), or
  * handles TCP inline (pure, fast packet rewriting -- no DoH on this thread).

Injection (`WinDivert.send`) is funnelled through a lock because pool workers
and the capture thread can inject concurrently.
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

import pydivert

from . import config, https_proxy, quic_proxy, tcp_proxy, udp_handler

log = logging.getLogger("dohproxy.divert")


class Diverter:
    def __init__(self) -> None:
        self._w = pydivert.WinDivert(config.DIVERT_FILTER)
        self._send_lock = threading.Lock()
        self._pool = ThreadPoolExecutor(
            max_workers=config.WORKER_THREADS, thread_name_prefix="doh"
        )
        self._stop = threading.Event()

    def _send(self, packet) -> None:
        """Thread-safe injection."""
        with self._send_lock:
            try:
                self._w.send(packet)
            except Exception as exc:  # noqa: BLE001
                log.debug("send failed: %s", exc)

    def _dispatch(self, packet) -> None:
        if packet.udp is not None and config.DPI_BYPASS and (
            (packet.is_outbound and packet.dst_port == 443)
            or packet.src_port == config.QUIC_PROXY_PORT
        ):
            quic_proxy.handle_packet(packet, self._send)
        elif packet.udp is not None and packet.dst_port == 53 and packet.is_outbound:
            self._pool.submit(udp_handler.handle, packet, self._send)
        elif packet.tcp is not None:
            # HTTPS splitting relay: outbound :443 (to redirect) and the relay's
            # own replies (src == HTTPS_PROXY_PORT). Everything else TCP is DNS.
            if config.DPI_BYPASS and (
                (packet.is_outbound and packet.dst_port == 443)
                or packet.src_port == config.HTTPS_PROXY_PORT
            ):
                https_proxy.handle_packet(packet, self._send)
            else:
                tcp_proxy.handle_packet(packet, self._send)
        else:
            self._send(packet)

    def run(self) -> None:
        self._w.open()
        log.info("WinDivert open; filter: %s", config.DIVERT_FILTER)
        try:
            while not self._stop.is_set():
                try:
                    packet = self._w.recv()
                except Exception:  # noqa: BLE001 - recv() raises when stop() closes the handle
                    if self._stop.is_set():
                        break
                    raise
                try:
                    self._dispatch(packet)
                except Exception as exc:  # noqa: BLE001 - never kill the loop
                    log.error("dispatch error: %s", exc)
                    self._send(packet)
        finally:
            self.close()

    def stop(self) -> None:
        self._stop.set()
        # Unblock a pending recv() by closing the handle.
        try:
            self._w.close()
        except Exception:  # noqa: BLE001
            pass

    def close(self) -> None:
        self._pool.shutdown(wait=False)
        try:
            self._w.close()
        except Exception:  # noqa: BLE001
            pass
