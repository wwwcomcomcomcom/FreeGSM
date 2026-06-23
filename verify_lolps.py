"""End-to-end check: can we actually reach a SNI-blocked site?

Run this with FreeGSM-DoH already running (elevated) in another window. It does a
plain HTTPS GET to https://lol.ps/ -- the same thing a browser does -- and
reports whether the TLS handshake survived (i.e. the SNI/DPI bypass worked) and
what the server answered.

    python verify_lolps.py            # tests lol.ps
    python verify_lolps.py example.org

Exit code 0 = got an HTTP response; 1 = failed (reset/timeout/etc).
"""

from __future__ import annotations

import sys

import httpx

HOST = sys.argv[1] if len(sys.argv) > 1 else "lol.ps"
URL = f"https://{HOST}/"


def main() -> int:
    print(f"GET {URL}")
    try:
        # http2 off keeps the request a single, ordinary TLS ClientHello so this
        # exercises exactly the path the bypass targets.
        with httpx.Client(timeout=10.0, follow_redirects=True, verify=True) as c:
            r = c.get(URL, headers={"User-Agent": "FreeGSM-verify/1.0"})
    except httpx.ConnectError as exc:
        print(f"FAIL  connection error: {exc}")
        print("      (a reset here usually means SNI DPI is still cutting the "
              "handshake -- is FreeGSM-DoH running, and DPI bypass on?)")
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL  {type(exc).__name__}: {exc}")
        return 1

    print(f"OK    HTTP {r.status_code} {r.reason_phrase}  ({len(r.content)} bytes)")
    server = r.headers.get("server")
    if server:
        print(f"      server: {server}")
    print(f"      final URL: {r.url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
