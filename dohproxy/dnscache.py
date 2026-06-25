"""In-memory DNS cache with TTL expiration."""

from __future__ import annotations

import logging
import threading
import time

from . import config

log = logging.getLogger("dohproxy.dnscache")


class DnsCache:
    def __init__(self, ttl_sec: int | None = None) -> None:
        self._ttl_sec = config.DNS_CACHE_TTL_SEC if ttl_sec is None else max(0, int(ttl_sec))
        self._lock = threading.Lock()
        # {cache_key: (response_bytes, stored_at)}
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
            response, stored_at = entry
            if now - stored_at > self._ttl_sec:
                del self._store[key]
                return None
            return self._apply_query_id(query, response)

    def put(self, query: bytes, response: bytes) -> None:
        if self._ttl_sec <= 0:
            return
        if len(query) < 2 or len(response) < 2:
            return
        key = self._cache_key(query)
        now = time.monotonic()
        cutoff = now - self._ttl_sec
        with self._lock:
            self._store[key] = (response, now)
            expired = [k for k, (_, t) in self._store.items() if t < cutoff]
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
