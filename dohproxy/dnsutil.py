"""Tiny helpers to make DNS queries human-readable for logging."""

from __future__ import annotations

import struct

# Common QTYPE numbers -> names (anything else is shown as TYPE<n>).
_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 48: "DNSKEY", 64: "SVCB",
    65: "HTTPS", 255: "ANY",
}


def describe_query(query: bytes) -> str:
    """Return e.g. ``"example.com A"`` from a raw DNS query, or a best-effort
    fallback string if the message can't be parsed."""
    try:
        # Skip the 12-byte header, then read the QNAME labels.
        i = 12
        labels = []
        while True:
            length = query[i]
            i += 1
            if length == 0:
                break
            # On-wire labels are ASCII (IDNs arrive as xn-- punycode already).
            labels.append(query[i:i + length].decode("ascii", "replace"))
            i += length
        name = ".".join(labels) if labels else "."
        (qtype,) = struct.unpack_from("!H", query, i)
        return f"{name} {_QTYPES.get(qtype, f'TYPE{qtype}')}"
    except Exception:  # noqa: BLE001 - logging must never fail
        return f"<unpar? {len(query)}B>"
