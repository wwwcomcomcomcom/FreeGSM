"""DoH client.

A DNS query and a DoH request body are the *same* bytes (RFC 8484
``application/dns-message`` == the UDP DNS wire format), so resolving is just:
POST the query bytes, return the response bytes. No DNS parsing required.
"""

from __future__ import annotations

import logging

import httpx

from . import config
from .dnscache import DnsCache

log = logging.getLogger("dohproxy.doh")

_HEADERS = {
    "Content-Type": "application/dns-message",
    "Accept": "application/dns-message",
}

# One shared client: HTTP/2 + a kept-alive TLS connection to the DoH server, so
# the per-query cost is just a multiplexed request. httpx.Client is safe to use
# from multiple threads concurrently.
_client: httpx.Client | None = None
_cache = DnsCache()


def start() -> None:
    global _client
    if _client is None:
        _client = httpx.Client(
            http2=True,
            timeout=config.DOH_TIMEOUT,
            headers=_HEADERS,
            # Keep the connection pool small but warm.
            limits=httpx.Limits(max_keepalive_connections=8, max_connections=16),
        )
    _cache.start()


def stop() -> None:
    global _client
    if _client is not None:
        _client.close()
        _client = None
    _cache.stop()


# A minimal DNS query for "example.com" A, used to probe upstream reachability.
_PROBE_QUERY = (
    b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x07example\x03com\x00\x00\x01\x00\x01"
)


def probe() -> tuple[bool, str]:
    """Check the DoH upstream is reachable. Returns (ok, detail)."""
    try:
        resolve(_PROBE_QUERY, use_cache=False)
        return True, "ok"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def resolve(query: bytes, *, use_cache: bool = True) -> bytes:
    """Resolve a raw DNS query (wire format) via DoH and return the raw
    response (wire format).

    Raises on any failure so callers can fail closed (drop the query).
    """
    if use_cache:
        cached = _cache.get(query)
        if cached is not None:
            log.debug("DNS cache hit (%d bytes)", len(query))
            return cached
    # Snapshot the shared client so a concurrent stop() (which sets _client to
    # None) during shutdown can't turn this into an AttributeError mid-call.
    client = _client
    if client is None:
        raise RuntimeError("DoH client not started")
    resp = client.post(config.DOH_URL, content=query)
    resp.raise_for_status()
    body = resp.content
    if not body:
        raise ValueError("empty DoH response")
    if use_cache:
        _cache.put(query, body)
    return body
