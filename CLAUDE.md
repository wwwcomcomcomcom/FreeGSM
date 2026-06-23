# FreeGSM-DoH

Windows app (Admin-only) that transparently upgrades the machine's plaintext DNS
to **DNS-over-HTTPS** and defeats **SNI-based DPI blocking**, without changing any
system setting. Stop the process and everything reverts. IPv4 only.

Two independent jobs, both driven by a single **WinDivert** capture loop:
1. **DoH** — outbound DNS (UDP/53 + TCP/53) is re-resolved over an encrypted
   HTTP/2 connection to a DoH server. Stateless: a DNS query and a DoH request
   body are the *same bytes* (RFC 8484), so no DNS parsing.
2. **SNI/DPI bypass** — outbound TCP/443 is relayed through a local process that
   re-emits the TLS ClientHello as **two TLS records** (record-layer
   fragmentation, ported from Jigsaw's Intra), so a one-record SNI matcher can't
   read the host while the server reassembles normally. Toggle: `FREEGSM_DPI`.

## Module map (`dohproxy/`)

| File | Responsibility |
|------|----------------|
| `main.py` | Entry: admin check → start DoH client → **probe upstream (refuse to start if unreachable)** → start TCP/HTTPS servers → run capture loop in a daemon thread, Ctrl+C to stop. |
| `config.py` | All tunables + builds the WinDivert `DIVERT_FILTER` string. Read this first to understand the capture filter. |
| `divert.py` | `Diverter`: the one WinDivert handle. `recv()` → `_dispatch()` classifies each packet and routes to a handler. Thread-safe injection via `_send` (a lock). |
| `doh.py` | DoH client (shared `httpx.Client`, HTTP/2, kept-alive). `resolve(query)->bytes`, `probe()`. Raises on failure so callers can fail-closed. |
| `udp_handler.py` | UDP/53: runs on a **thread pool** (blocking DoH round-trip). Mutates the captured packet in place into its reply and injects inbound. |
| `tcp_proxy.py` | TCP/53: WinDivert redirect to a local DoH-terminating server (`socketserver`). Packet rewriting is **inline on the capture thread**. |
| `https_proxy.py` | TCP/443 SNI relay: same redirect trick; terminates the connection, fragments the ClientHello via `dpi.split_hello`, then dumb bidirectional pipe. |
| `dpi.py` | Pure TLS primitives: `split_hello` (the Intra port) + `sni_name` (logging only). No I/O. |
| `dnsutil.py` | `describe_query` — human-readable query string for logs only. Never raises. |

Root: `run.py` (PyInstaller entry, wraps `main`), `verify_lolps.py` (SNI test), `build.ps1`.

## Packet dispatch (`divert.py:_dispatch`)

```
outbound UDP dst:53          -> udp_handler.handle   (thread pool)
TCP, if DPI on and
  (outbound dst:443 OR src==HTTPS_PROXY_PORT) -> https_proxy.handle_packet
TCP otherwise (dst:53 / src==TCP_PROXY_PORT)  -> tcp_proxy.handle_packet
anything else                -> passed through untouched
```

Both TCP relays use the same redirect recipe: rewrite an outbound client→server
packet's destination to `src_addr:<local-port>` and inject it **INBOUND** (aiming
at the host's own interface IP, *not* 127.0.0.1 — loopback injection doesn't work
with WinDivert); rewrite the relay→client reply's source back to the real
`server:port`. A per-relay `_conn_map` keyed by `(src_addr, src_port)` remembers
the original destination; it's touched only from the capture thread, so no lock.

## Invariants — break these and it silently fails

- **Never insert/remove bytes on the WinDivert path.** That desyncs the client
  kernel's TCP sequence numbers and triggers a RST. This is the entire reason the
  ClientHello split happens in a userspace relay (which owns both sockets) rather
  than by editing packets. Mutating addresses/ports/payload-as-whole is fine.
- **Fail-closed.** On any DoH error the query is *dropped*, not leaked in
  plaintext (`FAIL_OPEN=False`). Because of this, `main.py` probes the upstream at
  startup and refuses to run if unreachable — otherwise a bad upstream kills all
  DNS on the machine.
- **The relay's upstream sockets bind to a reserved source-port range**
  (`UPSTREAM_PORT_BASE..+COUNT`, default 30000–32047) that `DIVERT_FILTER`
  excludes, so they're never re-captured (no inject loop). The DoH upstream IP is
  excluded the same way. If you add a new outbound socket on a filtered port,
  exclude it in the filter or you'll capture your own traffic.
- **Injected packets must not re-match the filter.** Redirected queries carry
  dst==proxy-port (not 53); rewritten replies carry src==53. Keep that property
  when editing handlers.
- Handlers run in two regimes: **UDP = thread pool** (blocking DoH ok), **TCP
  packet-rewrite = inline on the capture thread** (must stay fast, non-blocking).

## Commands

```powershell
# Run from source — MUST be an ELEVATED terminal (WinDivert loads a kernel driver)
pip install -r requirements.txt
python -m dohproxy.main

# Build single self-elevating exe -> dist\FreeGSM-DoH.exe (bundles WinDivert)
powershell -ExecutionPolicy Bypass -File .\build.ps1

# Verify DoH (app running, elevated)
nslookup example.com        # UDP path
nslookup -vc example.com    # forces TCP path
# Verify SNI bypass: expect "OK  HTTP 200" and a "[HTTPS] ... -> 2 TLS records" log line
python verify_lolps.py [host]
```

No test suite or linter is configured.

## Config (`dohproxy/config.py`, env overrides need no rebuild)

- `FREEGSM_DOH_URL` — upstream. Default `https://1.0.0.1/dns-query` (Cloudflare's
  secondary IP; many networks block `1.1.1.1` *specifically*). Connect to a
  literal IP so resolving the DoH host never needs DNS — the cert's IP SAN covers
  it. Alternatives: `8.8.8.8` (Google), `9.9.9.9` (Quad9). `DOH_SERVER_IP` is
  derived from this to exclude our own channel from capture/fragmentation.
- `FREEGSM_DPI=0` — disable the SNI/443 relay (DoH only).
- `SPLIT_MIN`/`SPLIT_MAX` (6/64) — first-record size bounds, before the SNI.
- Ports: `TCP_PROXY_PORT=53533`, `HTTPS_PROXY_PORT=53444`. `FAIL_OPEN`,
  `WORKER_THREADS=32`, timeouts.

## Known gaps

QUIC/HTTP-3 (UDP/443) is untouched — disable browser HTTP/3 if the network
filters QUIC by SNI. No DNS cache. 443 relay pipes through userspace Python (fine
for browsing, slow for bulk). The split assumes the whole ClientHello arrives in
the first `recv` (true for a <16 KB hello).
