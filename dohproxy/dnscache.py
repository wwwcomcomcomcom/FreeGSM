"""In-memory DNS cache with TTL expiration."""

from __future__ import annotations

import logging
import struct
import threading
import time

from . import config

log = logging.getLogger("dohproxy.dnscache")


class DnsCache:
    def __init__(self, ttl_sec: int | None = None) -> None:
        self._ttl_sec = config.DNS_CACHE_TTL_SEC if ttl_sec is None else max(0, int(ttl_sec))
        self._lock = threading.Lock()
        # {cache_key: (response_bytes, expires_at)}
        self._store: dict[bytes, tuple[bytes, float]] = {}

    def start(self) -> None:
        if self._ttl_sec > 0:
            log.info("DNS cache enabled (in-memory, ttl=%ds)", self._ttl_sec)

    def stop(self) -> None:
        with self._lock:
            self._store.clear()

    def get(self, query: bytes) -> bytes | None:
        if self._ttl_sec <= 0:
            return None
        if len(query) < 2:
            return None
        key = self._cache_key(query)
        now = time.monotonic()
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            response, expires_at = entry
            if now >= expires_at:
                del self._store[key]
                return None
            return self._apply_query_id(query, response)

    def put(self, query: bytes, response: bytes) -> None:
        if self._ttl_sec <= 0:
            return
        if len(query) < 2 or len(response) < 2:
            return
        ttl_sec = self._effective_ttl_sec(response)
        if ttl_sec <= 0:
            return
        key = self._cache_key(query)
        now = time.monotonic()
        expires_at = now + ttl_sec
        with self._lock:
            self._store[key] = (response, expires_at)
            expired = [k for k, (_, expiry) in self._store.items() if expiry <= now]
            for k in expired:
                del self._store[k]

    @staticmethod
    def _cache_key(query: bytes) -> bytes:
        # Strip the 2-byte DNS transaction ID so different IDs for the same
        # question still hit the same cache entry.
        return query[2:]

    @staticmethod
    def _apply_query_id(query: bytes, response: bytes) -> bytes:
        return query[:2] + response[2:]

    def _effective_ttl_sec(self, response: bytes) -> int:
        response_ttl = self._min_response_ttl(response)
        if response_ttl is None:
            return self._ttl_sec
        return min(self._ttl_sec, response_ttl)

    @staticmethod
    def _min_response_ttl(response: bytes) -> int | None:
        """Return the minimum TTL across all DNS records in the response.

        The DNS wire format is compact and can use name compression pointers, so
        we only need to skip names and parse the fixed RR header fields.
        """
        try:
            if len(response) < 12:
                return None
            qdcount, ancount, nscount, arcount = struct.unpack_from("!4H", response, 4)
            offset = 12

            for _ in range(qdcount):
                offset = DnsCache._skip_name(response, offset)
                if offset + 4 > len(response):
                    return None
                offset += 4  # QTYPE + QCLASS

            min_ttl: int | None = None
            for _ in range(ancount + nscount + arcount):
                offset = DnsCache._skip_name(response, offset)
                if offset + 10 > len(response):
                    return None
                ttl = struct.unpack_from("!I", response, offset + 4)[0]
                rdlength = struct.unpack_from("!H", response, offset + 8)[0]
                offset += 10
                if offset + rdlength > len(response):
                    return None
                min_ttl = ttl if min_ttl is None else min(min_ttl, ttl)
                offset += rdlength

            return min_ttl
        except Exception:  # noqa: BLE001 - cache must fail closed to "no cache"
            return None

    @staticmethod
    def _skip_name(message: bytes, offset: int) -> int:
        while True:
            if offset >= len(message):
                raise ValueError("truncated DNS name")
            length = message[offset]
            if length == 0:
                return offset + 1
            if length & 0xC0 == 0xC0:
                if offset + 1 >= len(message):
                    raise ValueError("truncated DNS compression pointer")
                return offset + 2
            if length & 0xC0:
                raise ValueError("invalid DNS label length")
            if offset + 1 + length > len(message):
                raise ValueError("truncated DNS label")
            offset += 1 + length
