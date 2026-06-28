"""utun + tun2socks tunnel manager (macOS DPI bypass plumbing).

Brings the host's outbound TCP into userspace so the SOCKS5 splitting proxy can
fragment TLS ClientHellos:

  1. launch tun2socks on a utun device, forwarding flows to the local SOCKS5
     proxy (socks_proxy.py);
  2. give the utun a point-to-point address;
  3. exclude the DoH upstream IP (host route via the real gateway) so the DoH
     channel stays direct -- never tunnelled/fragmented (the invariant);
  4. override the default route with 0.0.0.0/1 + 128.0.0.0/1 pointing at the
     utun, so all other outbound TCP enters the tunnel.

The proxy's own upstream sockets bypass the tunnel via IP_BOUND_IF (see
socks_proxy.py), so they need no route exclusion -- only the DoH httpx client,
which can't easily set IP_BOUND_IF, gets the host-route exclusion above.

Teardown deletes every route it added and stops tun2socks (which makes the utun
vanish); it is best-effort and idempotent so it can run from a finally block, a
signal handler, and atexit. Interface routes are not persistent, so a reboot
also clears anything left behind.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

from .. import config

log = logging.getLogger("dohproxy.macos.tunnel")

# Persists the live tun2socks pid + the routes we added, so a crashed run (one
# killed before stop() could run) can be reconciled on the next start: the
# orphaned tun2socks is terminated and its leftover routes deleted, the same way
# dns_control recovers a leftover DNS backup. Without this, a SIGKILLed run
# leaves a utun + default-override routes blackholing all traffic with no record
# to clean them up.
STATE_FILE = Path("/Library/Application Support/FreeGSM/tunnel_state.json")


def _run(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=check)


def default_route() -> tuple[str | None, str | None]:
    """(gateway, interface) of the real default route, or (None, None)."""
    try:
        out = _run(["route", "-n", "get", "default"]).stdout
    except subprocess.CalledProcessError:
        return None, None
    gw = iface = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("gateway:"):
            gw = line.split()[1]
        elif line.startswith("interface:"):
            iface = line.split()[1]
    return gw, iface


def resolve_tun2socks() -> str | None:
    """Locate the tun2socks binary: configured path, PATH, or ./bin."""
    cand = config.TUN2SOCKS_PATH
    if cand and (Path(cand).is_file() or shutil.which(cand)):
        return shutil.which(cand) or cand
    for p in (Path.cwd() / "bin" / "tun2socks",
              Path(__file__).resolve().parent.parent.parent / "bin" / "tun2socks"):
        if p.is_file():
            return str(p)
    return None


def _iface_exists(dev: str) -> bool:
    return _run(["ifconfig", dev], check=False).returncode == 0


def _ipv6_default_exists() -> bool:
    """True if the host has an IPv6 default route we are NOT redirecting."""
    out = _run(["route", "-n", "get", "-inet6", "default"], check=False)
    return out.returncode == 0 and "gateway:" in out.stdout


# --------------------------------------------------------------------------- #
# Crash-recovery state (pid + routes), persisted across runs
# --------------------------------------------------------------------------- #
def _save_state(pid: int, routes: list[list[str]]) -> None:
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps({"pid": pid, "routes": routes}), encoding="utf-8")
    except OSError as exc:
        log.warning("could not persist tunnel state: %s", exc)


def _clear_state() -> None:
    try:
        STATE_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def _is_tun2socks(pid: int) -> bool:
    """True if pid is a live process whose command is tun2socks (guards against
    killing an unrelated process that reused the pid)."""
    out = _run(["ps", "-p", str(pid), "-o", "command="], check=False)
    return out.returncode == 0 and "tun2socks" in out.stdout


def _reconcile_leftover() -> bool:
    """Clean up after a crashed run: kill its orphaned tun2socks and delete the
    routes it left behind. Idempotent and best-effort.

    Returns True if it just SIGTERMed a live orphan (whose utun may not be
    reclaimed yet). If the orphan is still alive but can't be killed, the state
    file is kept so a later run can retry rather than abandoning a live tunnel
    with no recovery record."""
    try:
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False

    log.warning("Found leftover tunnel state from a previous run; cleaning up.")
    for dest_args in reversed(state.get("routes", [])):
        _run(["route", "-n", "delete", *dest_args], check=False)

    killed = False
    pid = state.get("pid")
    if isinstance(pid, int) and _is_tun2socks(pid):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as exc:
            # Orphan is alive but we couldn't signal it (e.g. EPERM). Keep the
            # state file so the next run can retry; clearing it now would strand
            # a live tun2socks holding the utun with no record to clean it up.
            log.error("could not terminate orphaned tun2socks pid %d (%s); "
                      "keeping state for retry.", pid, exc)
            return False
        log.info("terminated orphaned tun2socks pid %d", pid)
        killed = True
        # Escalate to SIGKILL if it ignores SIGTERM: this is the only reaper for
        # this orphan, and start() refuses to claim the fixed-name utun until the
        # device vanishes, so a SIGTERM-ignoring process would otherwise block the
        # tunnel until reboot.
        for _ in range(30):
            time.sleep(0.1)
            if not _is_tun2socks(pid):
                break
        else:
            try:
                os.kill(pid, signal.SIGKILL)
                log.warning("orphaned tun2socks pid %d ignored SIGTERM; sent SIGKILL", pid)
            except OSError:
                pass  # already gone (or unsignalable); _clear_state proceeds
    _clear_state()
    return killed


class Tunnel:
    def __init__(self, tun2socks_path: str) -> None:
        self._bin = tun2socks_path
        self._dev = config.TUN_DEVICE
        self._addr = config.TUN_ADDR
        self._proc: subprocess.Popen | None = None
        self._gw: str | None = None
        self._iface: str | None = None
        self._routes: list[list[str]] = []  # add-arg lists, deleted in reverse

    # -- routes -------------------------------------------------------------- #
    def _add_route(self, dest_args: list[str], required: bool = False) -> None:
        cp = _run(["route", "-n", "add", *dest_args], check=False)
        # Record the route BEFORE checking the result so stop()/reconcile always
        # deletes whatever the kernel may have created, even on a partial failure.
        self._routes.append(dest_args)
        if self._proc is not None:
            _save_state(self._proc.pid, self._routes)
        if required and cp.returncode != 0:
            raise RuntimeError(
                f"failed to add required route {dest_args}: {cp.stderr.strip()}"
            )

    # -- lifecycle ----------------------------------------------------------- #
    def start(self) -> None:
        # Recover from a crashed run before touching anything: kill any orphaned
        # tun2socks and delete its leftover routes, so we start from a clean slate
        # and never stack a second default-override on top of an old one.
        killed_orphan = _reconcile_leftover()

        self._gw, self._iface = default_route()
        if not self._gw or not self._iface:
            raise RuntimeError("no default route; refusing to set up tunnel")
        log.info("real default route: %s via %s", self._gw, self._iface)

        # The device name is fixed (config.TUN_DEVICE); if it still exists now
        # -- after reconciling our own leftovers -- something else owns it and our
        # ifconfig/route setup would target the wrong interface. Refuse rather
        # than blackhole traffic into a foreign device. But if we just killed an
        # orphan, its utun is torn down asynchronously, so give it a moment to
        # vanish before deciding the device is foreign.
        if _iface_exists(self._dev):
            if killed_orphan:
                for _ in range(30):
                    time.sleep(0.1)
                    if not _iface_exists(self._dev):
                        break
            if _iface_exists(self._dev):
                raise RuntimeError(
                    f"{self._dev} already exists and is not ours; refusing to set up tunnel"
                )

        if _ipv6_default_exists():
            log.warning("Host has an IPv6 default route; FreeGSM only redirects IPv4, "
                        "so IPv6 HTTPS bypasses the SNI splitter and its SNI stays "
                        "exposed. Disable IPv6 on this network for full coverage.")

        self._proc = subprocess.Popen(
            [self._bin, "-device", self._dev,
             "-proxy", f"socks5://{config.SOCKS_PROXY_HOST}:{config.SOCKS_PROXY_PORT}",
             "-loglevel", "warn"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        # Persist the pid IMMEDIATELY (before route setup). If we are SIGKILLed in
        # the window before the routes go in, the next run's _reconcile_leftover()
        # can still find and reap this tun2socks instead of it being an orphan
        # holding the fixed-name utun forever. _add_route re-saves as routes land.
        _save_state(self._proc.pid, self._routes)

        # Wait for the device tun2socks creates.
        for _ in range(50):
            if self._proc.poll() is not None:
                raise RuntimeError("tun2socks exited during startup")
            if _iface_exists(self._dev):
                break
            time.sleep(0.1)
        else:
            raise RuntimeError(f"{self._dev} did not appear")

        _run(["ifconfig", self._dev, self._addr, self._addr, "up"])
        log.info("tunnel device %s up (%s) via tun2socks", self._dev, self._addr)

        # Scoped default on the physical interface, so the SOCKS proxy's
        # upstream sockets (pinned with IP_BOUND_IF) have a route off the utun.
        # Without this, an ifscope lookup finds nothing and connects fail with
        # ENETUNREACH. App sockets (no IP_BOUND_IF) still use the global 0/1
        # route into the utun, so they remain fragmented.
        # Every route below is required: a missing scoped default makes the SOCKS
        # upstream sockets fail with ENETUNREACH; a missing DoH host-route would
        # tunnel (and fragment) our own resolver channel; missing /1 halves mean
        # traffic never enters the tunnel. Any failure raises so main.py degrades
        # cleanly to DoH-only (calling stop(), which deletes the partial routes)
        # rather than running a half-built tunnel that silently bypasses the DPI
        # splitter or breaks DNS.
        self._add_route(["-ifscope", self._iface, "default", self._gw], required=True)
        log.info("scoped default added: default via %s (ifscope %s)", self._gw, self._iface)

        # Keep the DoH channel direct (never tunnel our own resolver upstream).
        if config.DOH_SERVER_IP:
            self._add_route(["-host", config.DOH_SERVER_IP, self._gw], required=True)
            log.info("DoH upstream %s excluded via %s", config.DOH_SERVER_IP, self._gw)

        # Override the default route with two /1 halves pointing at the utun.
        self._add_route(["-net", "0.0.0.0/1", "-interface", self._dev], required=True)
        self._add_route(["-net", "128.0.0.0/1", "-interface", self._dev], required=True)
        log.info("default route now via %s (0/1 + 128/1)", self._dev)

    def stop(self) -> None:
        # Delete routes first (reverse order), so traffic falls back to the real
        # default the moment tun2socks goes away.
        for dest_args in reversed(self._routes):
            _run(["route", "-n", "delete", *dest_args], check=False)
        if self._routes:
            log.info("tunnel routes removed")
        self._routes.clear()

        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None
            log.info("tun2socks stopped; %s gone", self._dev)

        # Clean teardown done -- drop the crash-recovery state.
        _clear_state()
