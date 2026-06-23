# FreeGSM-DoH

A small Windows app that does for the desktop what [Intra](https://github.com/Jigsaw-Code/Intra)
does for Android: it transparently upgrades the machine's plaintext DNS to
**DNS-over-HTTPS (DoH)**. Leave it running and every DNS query the machine makes
is re-resolved over an encrypted HTTPS connection to a DoH server (default:
Cloudflare `1.1.1.1`) instead of being sent in clear text on UDP/TCP port 53.

It works by intercepting DNS packets with **WinDivert** (`WinDivert64.dll` +
`WinDivert64.sys`, bundled inside `pydivert` — no separate download), resolving
each query over DoH, and feeding the answer back to the application. No system
DNS settings are changed; nothing to undo. Stop the app and normal DNS resumes.

It **also** defeats **SNI-based blocking**. Fixing DNS is only half the battle:
even after a name resolves, many networks (notably Korean school/ISP filters)
inspect the plaintext server name (**SNI**) in the TLS ClientHello of every
outbound HTTPS connection and inject a TCP `RST` (or drop) the instant they see a
blocked host. FreeGSM borrows [Intra](https://github.com/Jigsaw-Code/Intra)'s
proven trick — **TLS record-layer fragmentation** — to re-emit the ClientHello as
two TLS records the censor can't read, while the destination server reassembles
it normally. So blocked sites actually **load**, not just resolve.

## How it works

- **UDP/53** (the vast majority of DNS): the outbound query packet is captured,
  its payload (a DNS message) is POSTed to the DoH server — DoH uses the *exact
  same wire format* — and the returned bytes are injected straight back as the
  reply. Stateless, no DNS parsing.
- **TCP/53**: the connection is transparently redirected to a tiny local server
  that terminates it and answers each length-prefixed query over DoH (proven
  WinDivert redirect technique, as used by mitmproxy).
- **DoH transport**: one kept-alive HTTP/2 connection to the DoH server. We
  connect to the literal IP (`https://1.1.1.1/...`), whose TLS certificate
  carries an IP SAN, so resolving the DoH server never needs DNS itself (no
  bootstrap problem).
- **Fail-closed**: if the DoH server can't be reached, queries are **dropped**
  rather than leaking in plaintext. (Flip `FAIL_OPEN = True` in `config.py` to
  prefer connectivity over privacy.)
- **SNI/DPI bypass (TCP/443)**: a transparent local relay. Outbound `:443`
  connections are redirected to it with the same WinDivert trick used for TCP/53;
  the relay terminates the connection, reads the TLS ClientHello, and re-emits it
  as **two valid TLS records** (record-layer fragmentation, ported from Intra's
  `splitHello`) before piping the rest of the bytes straight through. The split
  point is early — within the first ~1–59 handshake bytes, *before* the SNI — so a
  DPI that reads the SNI from the first TLS record finds a short record with no
  name in it and doesn't reassemble across records; the server, following the
  spec, reassembles and the handshake completes.

  > Why a relay instead of raw packet surgery? Record fragmentation **inserts**
  > 5 bytes (a second record header). You can't insert bytes on the WinDivert
  > path without desyncing the client kernel's TCP sequence numbers (it would
  > `RST` when the server ACKs bytes it never sent). A process that owns both
  > sockets can reframe freely — which is exactly why Intra does it this way too.

  The relay's own upstream sockets are bound to a reserved source-port range
  (`30000–32047`) that the kernel filter excludes, so they're never re-captured
  (no inject loop) and add no capture cost. Our DoH connection (to the upstream
  IP on `:443`) is excluded too. Disable the whole thing with `FREEGSM_DPI=0`.

## Requirements

- Windows 10/11, 64-bit
- **Administrator** (WinDivert loads a kernel driver)
- Python 3.12+ (to run from source or build the exe)

## Run from source

```powershell
pip install -r requirements.txt
# Run from an ELEVATED terminal (Run as administrator):
python -m dohproxy.main
```

Leave the window open — DNS is now going over DoH. Press **Ctrl+C** to stop.

## Build a single .exe

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

Produces `dist\FreeGSM-DoH.exe`, a self-contained binary that **requests UAC
elevation on launch** and bundles the WinDivert driver. Just double-click it.

## Configuration

Everything lives in `dohproxy/config.py`. The most useful knob is the upstream,
which can also be set **without rebuilding** via an environment variable:

```powershell
set FREEGSM_DOH_URL=https://8.8.8.8/dns-query   # Google
set FREEGSM_DOH_URL=https://9.9.9.9/dns-query   # Quad9
```

> ⚠️ **Why the default is `1.0.0.1`, not `1.1.1.1`:** many networks (schools,
> captive portals, some ISPs) block the `1.1.1.1` address specifically. `1.0.0.1`
> is Cloudflare's secondary IP for the **same** DoH resolver (the cert covers
> both) and is normally not blocked, so it's the safe default. Because the app is
> fail-closed, an unreachable upstream would break all DNS — so on startup it
> **probes the upstream and refuses to start** if it's unreachable, telling you
> to switch.

## Verify it's working

From an elevated terminal with the app running:

```powershell
nslookup example.com          # UDP path
nslookup -vc example.com      # forces the TCP path
```

Both should resolve. To prove traffic is encrypted, run `pktmon` or Wireshark:
you should see **no** plaintext packets leaving on port 53 — only TLS to your
DoH server on port 443.

Fail-closed check: block your DoH server's IP on :443 in the firewall → lookups
stop resolving (no plaintext leak); unblock → resolution returns.

**SNI bypass check** — with the app running, hit a site your network blocks by
SNI:

```powershell
python verify_lolps.py            # GET https://lol.ps/ ; prints HTTP status
python verify_lolps.py <host>     # try any other blocked host
```

A printed `OK  HTTP 200` means the ClientHello got through. You'll also see a
`[HTTPS] <ip>:443  SNI=lol.ps  ClientHello ... -> 2 TLS records` line in the
app's log as the handshake is fragmented. (Compare with `FREEGSM_DPI=0`: the same
request should hang or reset.)

## Limitations (MVP scope)

- IPv4 only (IPv6 DNS is passed through untouched).
- No system tray / GUI toggle, no run-as-a-service autostart.
- No DNS cache (every query is a DoH round-trip; HTTP/2 keep-alive keeps this
  cheap).
- **SNI bypass relays all TCP/443 through a userspace Python pipe.** Fine for
  browsing; bulk downloads are bottlenecked by that pipe. Turn it off with
  `FREEGSM_DPI=0` if you only need DoH.
- **QUIC / HTTP-3 (UDP/443) is not handled.** Browsers carry SNI there too; if
  your network filters QUIC by SNI, disable HTTP/3 in the browser so it falls
  back to TCP (which this *does* fix), or the connection may still be blocked.
- The split assumes the ClientHello arrives in the first read from the client
  (true in practice for a <16 KB hello). A hello dribbled across reads would only
  have its first chunk fragmented.

These are deliberate cuts for a minimal "turn it on and it works" build.
