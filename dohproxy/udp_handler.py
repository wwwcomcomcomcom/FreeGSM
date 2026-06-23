"""UDP/53 handling: stateless DoH response synthesis.

An outbound UDP DNS query is captured, its payload (the DNS query) is resolved
over DoH, and the *same* packet object is turned into the reply by swapping
addresses/ports and replacing the payload, then injected back inbound. pydivert
updates the IP/UDP length fields when the payload is reassigned and recomputes
checksums on send().
"""

from __future__ import annotations

import logging

from pydivert.consts import Direction

from . import config, doh
from .dnsutil import describe_query

log = logging.getLogger("dohproxy.udp")


def handle(packet, send) -> None:
    """Resolve one captured outbound UDP/53 query and inject the reply.

    ``send`` is a thread-safe callable that injects a pydivert Packet.
    On any DoH failure the query is dropped (fail-closed) unless
    ``config.FAIL_OPEN`` is set, in which case the original query is forwarded.
    """
    query = packet.payload
    if not query:
        return

    desc = describe_query(query)
    log.info("[INTERCEPT] UDP  %s  (from %s)", desc, packet.src_addr)

    try:
        answer = doh.resolve(query)
    except Exception as exc:  # noqa: BLE001 - fail-closed on anything
        if config.FAIL_OPEN:
            log.warning("[FAILED]    UDP  %s  -> DoH error: %s; forwarding plaintext", desc, exc)
            send(packet)
        else:
            log.warning("[FAILED]    UDP  %s  -> DoH error: %s; dropped", desc, exc)
        return

    log.info("[RESOLVED]  UDP  %s  -> %d bytes", desc, len(answer))

    # Turn the captured query into its reply, in place.
    packet.src_addr, packet.dst_addr = packet.dst_addr, packet.src_addr
    packet.src_port, packet.dst_port = packet.dst_port, packet.src_port
    packet.payload = answer
    packet.direction = Direction.INBOUND
    send(packet)
