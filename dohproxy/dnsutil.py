"""Tiny helpers to make DNS queries human-readable for logging."""

from __future__ import annotations

import struct

# Common QTYPE numbers -> names (anything else is shown as TYPE<n>).
_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 48: "DNSKEY", 64: "SVCB",
    65: "HTTPS", 255: "ANY",
}


# Pre-EDNS clients are limited to 512-byte UDP responses (RFC 1035).
_DEFAULT_UDP_SIZE = 512


def _question_end(query: bytes) -> int | None:
    """Offset of the byte just past the question section, or None if it can't be
    parsed. Used to trim a truncated response down to header + question."""
    qd = struct.unpack_from("!H", query, 4)[0]
    pos = 12
    for _ in range(qd):
        # QNAME: a sequence of length-prefixed labels ending in a zero length.
        # Compression pointers are illegal in a question, so reject them.
        while True:
            if pos >= len(query):
                return None
            length = query[pos]
            if length & 0xC0:
                return None
            pos += 1
            if length == 0:
                break
            pos += length
        pos += 4  # QTYPE + QCLASS
        if pos > len(query):
            return None
    return pos


def udp_payload_limit(query: bytes) -> int:
    """Largest UDP response the client will accept: its advertised EDNS0 payload
    size, or 512 when there is no OPT record. Best-effort; returns 512 on any
    trouble so we never over-promise."""
    try:
        ar = struct.unpack_from("!H", query, 10)[0]
        if ar == 0:
            return _DEFAULT_UDP_SIZE
        pos = _question_end(query)
        if pos is None:
            return _DEFAULT_UDP_SIZE
        # Walk the additional section looking for the OPT record (TYPE 41); its
        # CLASS field carries the requestor's UDP payload size.
        for _ in range(ar):
            if pos >= len(query):
                return _DEFAULT_UDP_SIZE
            if query[pos] & 0xC0 == 0xC0:        # compressed name
                pos += 2
            else:
                while pos < len(query) and query[pos] != 0:
                    pos += query[pos] + 1
                pos += 1                          # the zero length octet
            rtype, rclass = struct.unpack_from("!HH", query, pos)
            if rtype == 41:                       # OPT
                return max(_DEFAULT_UDP_SIZE, rclass)
            rdlen = struct.unpack_from("!H", query, pos + 8)[0]
            pos += 10 + rdlen                     # type+class+ttl+rdlen+rdata
        return _DEFAULT_UDP_SIZE
    except Exception:  # noqa: BLE001 - never raise on the resolve path
        return _DEFAULT_UDP_SIZE


def truncated_response(query: bytes) -> bytes | None:
    """Build a minimal TC=1 (truncated) response echoing the query's question, so
    an over-large answer makes the client retry over TCP instead of relying on IP
    fragmentation (which the DPI middleboxes we target routinely drop). Returns
    None if the query can't be parsed, so the caller can fall back."""
    end = None
    try:
        if len(query) >= 12:
            end = _question_end(query)
    except Exception:  # noqa: BLE001
        end = None
    if end is None:
        return None
    msg = bytearray(query[:end])
    msg[2] |= 0x80   # QR  = 1 (response)
    msg[2] |= 0x02   # TC  = 1 (truncated)
    msg[3] &= 0xF0   # clear RCODE (low nibble) -> NOERROR
    struct.pack_into("!HHH", msg, 6, 0, 0, 0)  # ANCOUNT = NSCOUNT = ARCOUNT = 0
    return bytes(msg)


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
