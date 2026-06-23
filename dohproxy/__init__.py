"""FreeGSM-DoH: a transparent DNS-over-HTTPS proxy for Windows.

Intercepts plaintext DNS (UDP/53 and TCP/53) with WinDivert and re-resolves
every query over DoH (default: Cloudflare 1.1.1.1), so the machine's DNS
traffic leaves the NIC only as TLS to the DoH server.
"""

__version__ = "0.1.0"
