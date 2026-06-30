"""Runtime configuration for FreeGSM.

Defaults give an MVP that "just works" when launched: Cloudflare 1.1.1.1 over
DoH, fail-closed on errors, intercepting IPv4/IPv6 UDP/53 and TCP/53.

Priority (highest first): environment variables → config.yml → built-in defaults.
"""

from __future__ import annotations

import ipaddress
import os
import sys
from pathlib import Path
from urllib.parse import urlparse


def _load_yaml_config() -> dict:
    """Return key/value pairs from config.yml, or {} if absent/unreadable."""
    candidates = [
        Path(sys.executable).parent / "config.yml" if getattr(sys, "frozen", False) else None,
        Path.cwd() / "config.yml",
        Path(__file__).parent.parent / "config.yml",
    ]
    for p in candidates:
        if p is not None and p.is_file():
            try:
                import yaml
                with open(p, encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                return data if isinstance(data, dict) else {}
            except Exception:
                return {}
    return {}

_yaml = _load_yaml_config()


def _env_flag(name: str, yaml_key: str, default: bool) -> bool:
    val = os.environ.get(name)
    # An empty/whitespace-only env var is treated as "unset" (fall through to
    # yaml/default) rather than as an explicit "false" -- an accidentally-empty
    # FREEGSM_DPI= should not silently disable a feature.
    if val is not None and val.strip() != "":
        return val.strip().lower() not in ("0", "false", "no", "off")
    if yaml_key in _yaml:
        return bool(_yaml[yaml_key])
    return default


def _parse_int(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _env_int(name: str, yaml_key: str, default: int) -> int:
    val = os.environ.get(name)
    if val is not None:
        return _parse_int(val, default)
    if yaml_key in _yaml:
        return _parse_int(_yaml[yaml_key], default)
    return default


# --- DoH upstream -----------------------------------------------------------
# We connect to the literal IP so resolving the DoH host never needs DNS
# itself. Cloudflare's certificate includes a `1.1.1.1` IP SAN, so TLS
# verification still succeeds.
#
# NOTE: many networks (schools, captive portals, some ISPs) block the 1.1.1.1
# address *specifically*. This is still Cloudflare's DoH resolver -- 1.0.0.1 is
# its secondary anycast IP for the exact same service, and the certificate
# covers both IPs -- but 1.0.0.1 is usually not blocked, so it is the default.
# With fail-closed, an unreachable upstream would break all DNS, so the app
# probes the upstream at startup and refuses to run if it can't be reached.
# Override without rebuilding via the FREEGSM_DOH_URL env var or config.yml.
DOH_URL = os.environ.get("FREEGSM_DOH_URL") or _yaml.get("doh_url") or "https://1.0.0.1/dns-query"

# Host part of the DoH upstream, when it is a literal IP. The DPI-bypass layer
# uses this to leave our own DoH connection alone (never fragment the channel we
# depend on). None if DOH_URL points at a hostname instead of an IP.
def _doh_host() -> str | None:
    host = urlparse(DOH_URL).hostname
    if not host:
        return None
    # Only a *literal IPv4 address* can be excluded from capture/fragmentation.
    # Validate strictly (str.isdigit() accepts unicode digits, and a dotted
    # heuristic accepts 999.999.999.999) so a hostname upstream cleanly returns
    # None and the caller can degrade rather than silently fragmenting DoH.
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        return None
    return host


DOH_SERVER_IP = _doh_host()

# Seconds to wait for a DoH round-trip before giving up (and, fail-closed,
# dropping the query).
DOH_TIMEOUT = 5.0

# --- DNS cache --------------------------------------------------------------
# Cache DNS responses in memory for a configurable TTL ceiling.
# The effective cache lifetime is min(DNS_CACHE_TTL_SEC, the response's
# minimum record TTL). Set to 0 to disable caching.
DNS_CACHE_TTL_SEC = max(0, _env_int("FREEGSM_DNS_CACHE_TTL_SEC", "dns_cache_ttl_sec", 300))

# --- Behaviour --------------------------------------------------------------
# Fail-closed: when DoH fails, drop the original query rather than letting the
# plaintext query escape. Set True to fail-open (leak plaintext on errors).
FAIL_OPEN = False

# Number of worker threads handling captured packets / DoH round-trips.
WORKER_THREADS = 32

# --- TCP transparent proxy --------------------------------------------------
# Local listener that terminates redirected TCP/53 connections. Redirected
# packets are aimed at the machine's own interface IP (injecting toward
# 127.0.0.1 does not work with WinDivert), so the server binds to all
# interfaces. The handler rejects any peer that is not the local host itself,
# so this is not an open resolver.
TCP_BIND_HOST = "0.0.0.0"
TCP_BIND_HOST_V6 = "::"
TCP_PROXY_PORT = 53533

# --- macOS DoH-first resolver -----------------------------------------------
# macOS has no WinDivert. The macOS port (dohproxy/macos/) instead runs a local
# DoH-terminating resolver and points the system DNS at it (reverted on exit).
# Binding loopback:53 requires root; binding 127.0.0.1 (not 0.0.0.0) inherently
# rejects any non-local client, so it can never act as an open resolver.
LOCAL_DNS_HOST = "127.0.0.1"
LOCAL_DNS_PORT = 53

# --- macOS SNI/DPI bypass (utun + tun2socks + local SOCKS) -------------------
# pf cannot redirect local outbound traffic, so the macOS DPI bypass routes
# outbound TCP through a utun device handled by tun2socks, which terminates each
# flow and forwards it to this local SOCKS5 proxy. The proxy fragments the
# TLS ClientHello (dpi.split_hello) on :443 and otherwise pipes through.
# The proxy's upstream sockets are pinned to the physical interface via
# IP_BOUND_IF so they bypass utun (no routing loop) -- the macOS analogue of the
# WinDivert reserved-port-range exclusion.
SOCKS_PROXY_HOST = "127.0.0.1"
SOCKS_PROXY_PORT = 1080

# tun2socks device + its point-to-point address. The default route is split into
# 0.0.0.0/1 + 128.0.0.0/1 pointing at this device so it overrides 0.0.0.0/0
# without deleting the user's real default route (standard VPN trick; both
# halves vanish on teardown). 198.18.0.0/15 is the RFC2544 benchmarking range,
# safe to use for a local tunnel endpoint.
TUN_DEVICE = "utun123"
TUN_ADDR = "198.18.0.1"
# Path to the tun2socks binary. Override via FREEGSM_TUN2SOCKS; otherwise the
# launcher looks on PATH and in ./bin.
TUN2SOCKS_PATH = os.environ.get("FREEGSM_TUN2SOCKS") or _yaml.get("tun2socks_path") or "tun2socks"

# --- DPI / SNI-blocking bypass ----------------------------------------------
# DoH only protects DNS. Many networks (notably Korean school/ISP filters) ALSO
# do deep-packet inspection of the plaintext Server Name Indication (SNI) in the
# TLS ClientHello of every outbound HTTPS connection, and inject a TCP RST (or
# drop) the moment they see a blocked host name -- so a site stays unreachable
# even after its DNS resolves fine over DoH.
#
# These filters reassemble the TCP stream before reading the SNI, so merely
# re-segmenting the ClientHello at the TCP layer does not help. The technique
# that does (proven by Jigsaw's Intra) is TLS *record-layer* fragmentation:
# re-emit the ClientHello as TWO valid TLS records, so a one-record SNI matcher
# can't read the name while the server reassembles the handshake normally.
# Record fragmentation inserts 5 bytes (a second record header), which is
# impossible on the raw packet path without desyncing the client kernel's TCP
# sequence space -- so we instead TERMINATE each outbound :443 connection at a
# tiny local relay (the same WinDivert redirect trick used for TCP/53) and let
# the relay reframe the ClientHello. See https_proxy.py.
#
# Toggle with FREEGSM_DPI=0 to disable.
DPI_BYPASS = _env_flag("FREEGSM_DPI", "dpi_bypass", True)

# Local relay that terminates redirected outbound TCP/443 connections, fragments
# the ClientHello, and pipes the rest through to the real server.
HTTPS_PROXY_PORT = 53444

# Local relay that transparently forwards redirected outbound UDP/443 packets
# (QUIC / HTTP-3) to the real server.
QUIC_PROXY_PORT = 53445

# The relay's own upstream sockets (relay -> real server) are bound to source
# ports in [UPSTREAM_PORT_BASE, UPSTREAM_PORT_BASE + UPSTREAM_PORT_COUNT). The
# kernel filter excludes this range so those packets are never captured -- this
# both avoids an inject loop and keeps the relay's upstream off the capture path.
# The range sits BELOW Windows' ephemeral range (49152-65535) so it never
# collides with ports the OS hands out to other apps' own HTTPS connections.
UPSTREAM_PORT_BASE = 30000
UPSTREAM_PORT_COUNT = 2048

# TLS-record split bounds (bytes, including the 5-byte record header), matching
# Intra's defaults: the first record carries SPLIT_MIN-5 .. SPLIT_MAX-5 bytes of
# the ClientHello handshake -- early, before the SNI -- and the rest follows in a
# second record.
SPLIT_MIN = 6
SPLIT_MAX = 64

# Relay timeouts (seconds).
HTTPS_CONNECT_TIMEOUT = 8.0
HTTPS_FIRST_READ_TIMEOUT = 8.0
QUIC_IDLE_TIMEOUT = 30.0
# Idle timeout for a relayed connection's bidirectional pump: a half-open or
# stalled connection is reaped after this many seconds so it can't leak a thread
# + two sockets forever. Generous enough for slow/large downloads.
RELAY_IDLE_TIMEOUT = 300.0
# Idle timeout for a DNS-over-TCP connection to the local resolver. DNS/TCP
# clients reconnect freely (RFC 7766), so a stalled stream can be dropped.
DNS_TCP_IDLE_TIMEOUT = 30.0

# Upper bound on the connection-redirect map. Entries are normally removed on
# RST/FIN, but a connection that dies without a captured teardown would leak one
# forever; when the map exceeds this, the oldest entries are evicted.
CONN_MAP_MAX = 8192

# --- WinDivert --------------------------------------------------------------
# DNS interception covers both IPv4 and IPv6. The DNS clauses capture three
# things:
#   1. outbound UDP/53 queries  -> synthesized DoH responses
#   2. outbound TCP/53 queries  -> redirected to the local DoH proxy
#   3. packets that proxy emits (src port == TCP_PROXY_PORT) -> rewritten so they
#      appear to come from the real DNS server. No `outbound` qualifier on this
#      clause so it also matches same-host (loopback-flagged) replies.
# Our own injected packets never re-match: redirected queries carry dst port ==
# proxy port (not 53) and the rewritten replies carry src port == 53.
_DNS_CLAUSES = (
    "(outbound and udp.DstPort == 53)"
    " or (outbound and tcp.DstPort == 53)"
    f" or (tcp.SrcPort == {TCP_PROXY_PORT})"
)

# DPI clauses (added only when bypass is on):
#   * outbound TCP/443, EXCEPT our DoH upstream and EXCEPT the relay's reserved
#     upstream source-port range -> redirected to the HTTPS splitting relay.
#   * outbound UDP/443, EXCEPT the relay's reserved upstream source-port range
#     -> redirected to the QUIC/HTTP-3 relay.
#   * packets the relays emit (src port == HTTPS_PROXY_PORT / QUIC_PROXY_PORT)
#     -> rewritten back to look like they came from the real server:443.
_upstream_hi = UPSTREAM_PORT_BASE + UPSTREAM_PORT_COUNT - 1
_doh_excl = f" and ip.DstAddr != {DOH_SERVER_IP}" if DOH_SERVER_IP else ""
_DPI_CLAUSES = (
    f"(outbound and tcp.DstPort == 443{_doh_excl}"
    f" and (tcp.SrcPort < {UPSTREAM_PORT_BASE} or tcp.SrcPort > {_upstream_hi}))"
    f" or (tcp.SrcPort == {HTTPS_PROXY_PORT})"
    f" or (outbound and udp.DstPort == 443"
    f" and (udp.SrcPort < {UPSTREAM_PORT_BASE} or udp.SrcPort > {_upstream_hi}))"
    f" or (udp.SrcPort == {QUIC_PROXY_PORT})"
)

DIVERT_FILTER = (
    f"((ip or ipv6) and ({_DNS_CLAUSES}))"
    + (f" or (ip and ({_DPI_CLAUSES}))" if DPI_BYPASS else "")
)
