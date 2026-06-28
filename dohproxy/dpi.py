"""TLS ClientHello fragmentation primitives for the SNI/DPI bypass.

This is a faithful Python port of the splitting logic from Jigsaw's Intra
(`Android/app/src/go/intra/split/retrier.go: splitHello`). The relay in
`https_proxy.py` feeds each captured ClientHello through `split_hello` and writes
the returned segments to the upstream socket as separate TCP writes.

The key idea is **TLS record-layer fragmentation**, not TCP segmentation: the
single ClientHello record is re-emitted as TWO valid TLS records (the handshake
message is allowed to span records). The split point is early -- within the first
~1..59 bytes of the handshake, well before the SNI -- so a DPI box that reads the
SNI out of the first TLS record finds a short record with no name in it, and
typically doesn't reassemble the handshake across records. The destination
server, which follows the spec, reassembles and completes the handshake normally.
"""

from __future__ import annotations

import random
import struct

# Record-layer content type 0x16 == handshake; these are the legal record
# versions for a ClientHello.
_TLS_HANDSHAKE = 0x16
_TLS_VERSIONS = {0x0301, 0x0302, 0x0303, 0x0304}


def is_tls_handshake(payload: bytes) -> bool:
    """True if ``payload`` begins with a TLS handshake record (content type
    0x16) -- i.e. it could be a ClientHello worth splitting. Lets callers avoid
    reaching into this module's private ``_TLS_HANDSHAKE`` constant."""
    return payload[:1] == bytes([_TLS_HANDSHAKE])


def tls_record_len(h: bytes) -> tuple[int, bool]:
    """Return ``(record_body_len, ok)`` for a buffer that begins with a TLS
    record header, mirroring Intra's ``getTLSClientHelloRecordLen``."""
    if len(h) < 5 or h[0] != _TLS_HANDSHAKE:
        return 0, False
    if int.from_bytes(h[1:3], "big") not in _TLS_VERSIONS:
        return 0, False
    return int.from_bytes(h[3:5], "big"), True


def split_hello(hello: bytes, min_split: int = 6, max_split: int = 64) -> list[bytes]:
    """Split a ClientHello into a list of byte-segments to write in order.

    Port of Intra's ``splitHello``. ``min_split``/``max_split`` bound the size of
    the first segment (the 5-byte TLS header included). When ``hello`` is a valid
    TLS record this produces two records (record-layer fragmentation); otherwise
    it falls back to a plain two-way byte split.
    """
    if len(hello) <= 1:
        return [hello]

    # Random first-segment size in [min_split, max_split], capped at half so the
    # second segment is never empty. splitLen counts the 5-byte TLS header.
    split_len = random.randint(min_split, max_split)
    limit = len(hello) // 2
    if split_len > limit:
        split_len = limit

    record_len, ok = tls_record_len(hello)
    # If the whole record isn't buffered yet (a large ClientHello -- e.g. ECH or
    # many extensions -- spread across multiple TCP segments), fragmenting would
    # emit a second record header whose length field lies about the bytes present,
    # corrupting the stream while the leftover bytes get forwarded raw. Forward
    # the ClientHello untouched instead: no DPI bypass for this connection, but a
    # byte-identical stream that completes the handshake normally.
    if ok and len(hello) < record_len + 5:
        return [hello]

    record_split_len = split_len - 5
    if not ok or record_split_len <= 0 or record_split_len >= record_len:
        # Not a fragmentable TLS record: just split the bytes in two.
        return [hello[:split_len], hello[split_len:]]

    # First record: the original 5-byte header with its length field rewritten
    # to record_split_len, followed by that many handshake bytes.
    first = bytearray(hello[:split_len])
    struct.pack_into("!H", first, 3, record_split_len)

    # Second record: a fresh copy of the original 5-byte header (length rewritten
    # to the remainder) placed right before the leftover handshake bytes. The 5
    # bytes it overwrites were already sent inside the first record.
    second = bytearray(hello[split_len - 5:])
    second[0:5] = hello[0:5]
    struct.pack_into("!H", second, 3, record_len - record_split_len)

    return [bytes(first), bytes(second)]


# --------------------------------------------------------------------------- #
# SNI extraction (for logging only; the split does not depend on the SNI).
# --------------------------------------------------------------------------- #
def sni_name(payload: bytes) -> str:
    """Best-effort SNI host name from a ClientHello, or ``"<no-sni>"``."""
    try:
        if len(payload) < 6 or payload[0] != _TLS_HANDSHAKE or payload[5] != 0x01:
            return "<no-sni>"
        pos = 5
        hs_len = int.from_bytes(payload[pos + 1:pos + 4], "big")
        end = min(pos + 4 + hs_len, len(payload))
        pos += 4 + 2 + 32                                        # hdr + version + random
        pos += 1 + payload[pos]                                  # session_id
        pos += 2 + int.from_bytes(payload[pos:pos + 2], "big")   # cipher_suites
        pos += 1 + payload[pos]                                  # compression
        if pos + 2 > end:
            return "<no-sni>"
        ext_end = min(pos + 2 + int.from_bytes(payload[pos:pos + 2], "big"), end)
        pos += 2
        while pos + 4 <= ext_end:
            etype = int.from_bytes(payload[pos:pos + 2], "big")
            elen = int.from_bytes(payload[pos + 2:pos + 4], "big")
            body = pos + 4
            if etype == 0x0000:  # server_name
                p = body + 2
                if p < ext_end and payload[p] == 0x00:
                    nlen = int.from_bytes(payload[p + 1:p + 3], "big")
                    name = payload[p + 3:p + 3 + nlen]
                    return name.decode("ascii", "replace") or "<empty>"
                return "<no-sni>"
            pos = body + elen
        return "<no-sni>"
    except Exception:  # noqa: BLE001
        return "<unparseable>"
