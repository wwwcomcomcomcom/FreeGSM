"""System DNS reconfiguration for the macOS DoH-first port.

Points every enabled network service's DNS at the local resolver (127.0.0.1)
and restores the original servers on exit. This is the one system setting the
macOS port touches; restoring it is the single most important invariant -- if
the system DNS is left at 127.0.0.1 with our resolver dead, the machine has no
working DNS. So:

  * the original servers are persisted to disk BEFORE we change anything, so a
    crash can be recovered on the next start;
  * restore() is idempotent and is wired to signals + atexit + a finally block
    by the caller, so any exit path restores;
  * on start, a leftover backup file (from a crashed run) is restored FIRST,
    before reading the current servers -- otherwise we would back up 127.0.0.1
    as if it were the user's real DNS.

All calls go through `networksetup`, which requires root.
"""

from __future__ import annotations

import json
import logging
import subprocess
import threading
from pathlib import Path

from .. import config

log = logging.getLogger("dohproxy.macos.dns")

# Persistent so a crashed run can be recovered after reboot (networksetup
# changes survive reboots, but /tmp may not).
BACKUP_FILE = Path("/Library/Application Support/FreeGSM/dns_backup.json")

# Seconds before a networksetup call is abandoned. networksetup is known to hang
# on some macOS versions / VPN profiles; a hang during restore() would block
# Ctrl+C with DNS still pointed at the dying resolver, so every call is bounded.
_NETWORKSETUP_TIMEOUT = 10

# In-memory copy of the original servers, set by install().
_state: dict[str, list[str]] | None = None

# Serializes install()/restore() so the finally block, atexit, and any future
# concurrent caller can't interleave and corrupt the backup state.
_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# networksetup wrappers
# --------------------------------------------------------------------------- #
def _run(args: list[str]) -> str:
    return subprocess.run(
        ["networksetup", *args],
        capture_output=True, text=True, check=True,
        timeout=_NETWORKSETUP_TIMEOUT,
    ).stdout


def _list_services() -> list[str]:
    """Enabled network service names (skips the header line and disabled ones,
    which networksetup prefixes with '*')."""
    out = _run(["-listallnetworkservices"])
    services = []
    for line in out.splitlines()[1:]:  # first line is an informational notice
        name = line.strip()
        if name and not name.startswith("*"):
            services.append(name)
    return services


def _get_dns(service: str) -> list[str]:
    """Current DNS servers for a service; [] when none are set (DHCP)."""
    out = _run(["-getdnsservers", service]).strip()
    if not out or out.lower().startswith("there aren't"):
        return []
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def _set_dns(service: str, servers: list[str]) -> bool:
    """Set DNS servers for a service; [] resets it to DHCP-provided ('empty').
    Returns True on success, False if networksetup failed."""
    args = ["-setdnsservers", service] + (servers if servers else ["empty"])
    try:
        _run(args)
        return True
    except subprocess.CalledProcessError as exc:
        log.error("failed to set DNS for %r: %s", service, exc.stderr.strip())
        return False
    except subprocess.TimeoutExpired:
        # networksetup hung; treat as a failed call so _restore_from keeps the
        # backup for the next run's recovery rather than dropping it.
        log.error("networksetup timed out setting DNS for %r", service)
        return False


def _flush_cache() -> None:
    for cmd in (["dscacheutil", "-flushcache"], ["killall", "-HUP", "mDNSResponder"]):
        try:
            subprocess.run(cmd, capture_output=True, check=False)
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------- #
# Backup persistence
# --------------------------------------------------------------------------- #
def _save_backup(backup: dict[str, list[str]]) -> None:
    try:
        BACKUP_FILE.parent.mkdir(parents=True, exist_ok=True)
        BACKUP_FILE.write_text(json.dumps(backup), encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        log.warning("could not persist DNS backup: %s", exc)


def _load_backup() -> dict[str, list[str]] | None:
    try:
        return json.loads(BACKUP_FILE.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def _restore_from(backup: dict[str, list[str]]) -> bool:
    """Restore every service's DNS. Returns True only if all succeeded, so the
    caller can keep the on-disk backup when any restore failed."""
    all_ok = True
    for service, servers in backup.items():
        if _set_dns(service, servers):
            log.info("restored DNS for %r -> %s", service, servers or "DHCP")
        else:
            all_ok = False
    return all_ok


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def install() -> None:
    """Back up current DNS servers and point every service at 127.0.0.1."""
    with _lock:
        _install_locked()


def _install_locked() -> None:
    global _state

    # Crash recovery: a leftover backup means a previous run died before
    # restoring. Restore it FIRST so the values we are about to back up are the
    # user's real servers, not a stale 127.0.0.1.
    leftover: dict[str, list[str]] = {}
    if BACKUP_FILE.exists():
        old = _load_backup()
        if old:
            leftover = old  # authoritative record of the user's real servers
            log.warning("Found leftover DNS backup from a previous run; restoring it first.")
            if _restore_from(old):
                BACKUP_FILE.unlink(missing_ok=True)
            else:
                # Some services failed to restore and may still point at our
                # resolver. The corrected backup written below re-derives their
                # real servers from this leftover, so keep the file for now (it
                # is overwritten) rather than stranding DNS at 127.0.0.1.
                log.error("Leftover DNS restore incomplete; preserving its real "
                          "servers in the refreshed backup.")
        else:
            BACKUP_FILE.unlink(missing_ok=True)

    services = _list_services()
    backup: dict[str, list[str]] = {}
    for svc in services:
        current = _get_dns(svc)
        # We only ever set a service to EXACTLY [LOCAL_DNS_HOST]. During crash
        # recovery (a leftover backup existed), a service still showing exactly
        # that is our own leftover -- not the user's DNS -- so re-derive its real
        # servers from the leftover backup (captured on a clean start), falling
        # back to DHCP ([]). On a clean start there is nothing of ours to confuse
        # it with, so a lone 127.0.0.1 is the user's real config (e.g. a local
        # dnscrypt/dnsmasq resolver) and is preserved. A list that merely
        # *contains* 127.0.0.1 is never our setting, so it is always kept verbatim.
        #
        # Only re-derive when this service is actually IN the leftover backup --
        # i.e. we know we set it to 127.0.0.1 last run. A service NOT in leftover
        # (e.g. added since the crash) that reads exactly 127.0.0.1 is the user's
        # own config (a local resolver) and must be kept verbatim; falling back
        # to [] there would silently convert their DNS to DHCP.
        if leftover and current == [config.LOCAL_DNS_HOST] and svc in leftover:
            current = leftover[svc]
        backup[svc] = current
    _save_backup(backup)
    _state = backup

    for svc in services:
        _set_dns(svc, [config.LOCAL_DNS_HOST])
        log.info("DNS for %r -> %s", svc, config.LOCAL_DNS_HOST)
    _flush_cache()
    log.info("System DNS repointed to local resolver (%d service(s)).", len(services))


def restore() -> None:
    """Restore the original DNS servers. Idempotent and thread-safe: safe to call
    from a finally block, a signal handler, and atexit all at once."""
    with _lock:
        _restore_locked()


def _restore_locked() -> None:
    global _state

    backup = _state
    if backup is None:
        # install() never ran (or already restored) -- but recover a leftover
        # file just in case.
        backup = _load_backup()
        if backup is None:
            return

    all_ok = _restore_from(backup)
    _flush_cache()
    if not all_ok:
        # At least one service is still pointed at our (dying) resolver. Keep the
        # on-disk backup and in-memory state so the next start's crash-recovery
        # path can finish the job -- deleting it now would strand DNS at 127.0.0.1
        # with no record of the user's real servers.
        log.error("DNS restore incomplete; keeping backup %s for recovery.", BACKUP_FILE)
        return
    _state = None
    BACKUP_FILE.unlink(missing_ok=True)
    log.info("Original system DNS restored.")
