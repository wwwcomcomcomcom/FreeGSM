"""Entry point: wire DoH client, TCP proxy and the WinDivert capture loop.

Run from an elevated context (WinDivert needs Administrator to load its driver).
Leaving the process running == DNS is being upgraded to DoH. Ctrl+C stops it and
restores normal DNS.
"""

from __future__ import annotations

import ctypes
import logging
import sys
import threading
import time

from . import config, divert, doh, https_proxy, tcp_proxy


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    log = logging.getLogger("dohproxy")

    if not _is_admin():
        log.error(
            "Administrator privileges required (WinDivert loads a kernel driver). "
            "Re-run this from an elevated terminal, or use the packaged .exe."
        )
        return 1

    log.info("FreeGSM starting. Upstream: %s  (fail-%s)",
             config.DOH_URL, "open" if config.FAIL_OPEN else "closed")
    if config.DPI_BYPASS:
        log.info("SNI/DPI bypass: ON (TLS record fragmentation via local relay "
                 "on TCP/443)")
    else:
        log.info("SNI/DPI bypass: OFF (set FREEGSM_DPI=1 to enable)")

    doh.start()

    # Probe the upstream BEFORE touching DNS. With fail-closed, starting against
    # an unreachable upstream would kill all DNS; refusing to start keeps the
    # machine's DNS untouched and tells the user how to fix it.
    log.info("Probing DoH upstream...")
    ok, detail = doh.probe()
    if not ok:
        log.error("DoH upstream %s is unreachable (%s).", config.DOH_URL, detail)
        log.error(
            "Not starting (fail-closed would break all DNS). Some networks block "
            "1.1.1.1 specifically. Set a reachable upstream and retry, e.g.:"
        )
        log.error('    set FREEGSM_DOH_URL=https://8.8.8.8/dns-query')
        log.error('    set FREEGSM_DOH_URL=https://9.9.9.9/dns-query')
        doh.stop()
        return 1
    log.info("DoH upstream reachable.")

    server = tcp_proxy.start_server()
    https_server = https_proxy.start_server() if config.DPI_BYPASS else None
    diverter = divert.Diverter()

    # Run the (blocking) capture loop off the main thread so Ctrl+C stays
    # responsive -- a blocking WinDivert recv() in the main thread would swallow
    # SIGINT until the next packet arrived.
    worker = threading.Thread(target=diverter.run, name="capture", daemon=True)
    worker.start()
    log.info("Running. DNS is now upgraded to DoH. Press Ctrl+C to stop.")

    try:
        while worker.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        diverter.stop()
        server.shutdown()
        if https_server is not None:
            https_server.shutdown()
        doh.stop()
        log.info("Stopped. Normal DNS restored.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
