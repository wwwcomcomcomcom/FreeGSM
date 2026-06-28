"""Entry point for the macOS port (DoH + optional SNI/443 DPI bypass).

Run from root (binds loopback:53, changes system DNS, and -- when DPI is on --
creates a utun and rewrites the default route):

    sudo python -m dohproxy.macos.main

Two independent jobs, same as the Windows build:
  * DoH  -- a local resolver terminates DNS and re-resolves over DoH; the system
    DNS is pointed at it and restored on exit (dns_control + resolver).
  * DPI  -- tun2socks routes outbound TCP through a utun to a local SOCKS5 proxy
    that fragments the TLS ClientHello (tunnel + socks_proxy). Toggle with
    FREEGSM_DPI=0. Requires the tun2socks binary; if it's missing we log and run
    DoH-only rather than failing.

Teardown (tunnel routes -> DNS -> servers) is wired to a finally block, signals,
and atexit, and every step is idempotent -- losing the default route or system
DNS would break the machine's networking, so restoring them is the top priority.
"""

from __future__ import annotations

import atexit
import logging
import os
import signal
import sys
import threading

from .. import config, doh
from . import dns_control, tunnel
from .resolver import Resolver
from . import socks_proxy


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    log = logging.getLogger("dohproxy.macos")

    if not _is_root():
        log.error("Root privileges required. Re-run with: "
                  "sudo python -m dohproxy.macos.main")
        return 1

    # Decide whether the DPI tunnel can run.
    dpi_on = config.DPI_BYPASS
    tun_bin = tunnel.resolve_tun2socks() if dpi_on else None
    if dpi_on and tun_bin is None:
        log.warning("FREEGSM_DPI is on but tun2socks was not found "
                    "(set FREEGSM_TUN2SOCKS or put it on PATH/./bin). Running DoH-only.")
        dpi_on = False
    if dpi_on and not config.DOH_SERVER_IP:
        # The tunnel can only keep the DoH channel direct by excluding its literal
        # IP from the utun default-override. With a hostname upstream there is no
        # IP to exclude, so the DoH connection would itself be tunnelled and
        # fragmented -- taking down all DNS. Refuse DPI rather than break DoH.
        log.warning("FREEGSM_DPI is on but DOH_URL is not a literal IP (%s), so the "
                    "DoH channel can't be excluded from the tunnel. Running DoH-only.",
                    config.DOH_URL)
        dpi_on = False

    log.info("FreeGSM (macOS) starting. Upstream: %s  (fail-%s)  DPI: %s",
             config.DOH_URL, "open" if config.FAIL_OPEN else "closed",
             "ON" if dpi_on else "OFF")

    doh.start()
    log.info("Probing DoH upstream...")
    ok, detail = doh.probe()
    if not ok:
        log.error("DoH upstream %s is unreachable (%s). Not starting "
                  "(fail-closed would break all DNS).", config.DOH_URL, detail)
        doh.stop()
        return 1
    log.info("DoH upstream reachable.")

    resolver = Resolver()
    socks_srv = None
    tun = None
    try:
        resolver.start()
    except OSError as exc:
        log.error("Could not bind %s:%d (%s).",
                  config.LOCAL_DNS_HOST, config.LOCAL_DNS_PORT, exc)
        doh.stop()
        return 1

    stop = threading.Event()

    def _teardown() -> None:
        # Order matters: restore routing BEFORE DNS/servers so traffic falls
        # back to the real path immediately. Every step is idempotent AND
        # isolated: restoring the system DNS is the top-priority invariant, so an
        # exception in an earlier step must never skip it. atexit re-runs this in
        # the same order, so a step that reliably threw would otherwise strand DNS
        # at 127.0.0.1 with the resolver dead -- bricking the machine's DNS.
        try:
            if tun is not None:
                tun.stop()
        except Exception:  # noqa: BLE001
            log.exception("tunnel teardown failed; continuing to DNS restore")
        try:
            if socks_srv is not None:
                socks_srv.shutdown()
                socks_srv.server_close()
        except Exception:  # noqa: BLE001
            log.exception("SOCKS server teardown failed; continuing to DNS restore")
        dns_control.restore()

    atexit.register(_teardown)

    def _on_signal(signum, _frame):
        log.info("Received signal %s; shutting down...", signum)
        stop.set()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)
    # SIGHUP: when launched from a terminal, closing that terminal should stop
    # FreeGSM and restore DNS/routing rather than killing it uncleanly.
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, _on_signal)

    try:
        dns_control.install()
        if dpi_on:
            # Bring up the DPI tunnel. If any step fails, fall back to DoH-only
            # rather than killing DNS: tear down whatever partially started.
            try:
                socks_srv = socks_proxy.start_server()
                tun = tunnel.Tunnel(tun_bin)
                tun.start()
            except Exception as exc:  # noqa: BLE001 - degrade to DoH-only
                log.warning("DPI bypass setup failed (%s); continuing DoH-only.", exc)
                if tun is not None:
                    tun.stop()
                    tun = None
                if socks_srv is not None:
                    socks_srv.shutdown()
                    socks_srv.server_close()
                    socks_srv = None
                dpi_on = False
        log.info("Running. DNS upgraded to DoH%s. Press Ctrl+C to stop.",
                 " + SNI/443 fragmentation active" if dpi_on else "")
        stop.wait()
    finally:
        _teardown()  # stops tun + socks_srv + restores DNS (idempotent)
        resolver.stop()
        doh.stop()
        log.info("Stopped. Normal DNS and routing restored.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
