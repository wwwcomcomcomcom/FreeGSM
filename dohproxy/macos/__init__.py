"""macOS port of FreeGSM (DoH + optional SNI/443 DPI bypass).

macOS has no WinDivert and pf's `rdr` cannot redirect a host's own outbound
connections (see docs/MACOS_PORT.md, spike A), so the Windows packet-capture
model does not apply. This package implements both FreeGSM jobs differently:

  * DoH  -- a local DoH-terminating resolver (resolver.py) is bound to loopback
    and the system DNS is repointed at it, restoring the original servers on
    exit (dns_control.py).
  * DPI  -- outbound TCP is routed through a utun + tun2socks into a local
    SOCKS5 proxy (tunnel.py + socks_proxy.py) that fragments the TLS
    ClientHello. Toggle with FREEGSM_DPI=0; if tun2socks is missing or the DoH
    upstream isn't a literal IP, the port runs DoH-only.
"""
