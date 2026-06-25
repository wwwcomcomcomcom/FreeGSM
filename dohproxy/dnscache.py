"""Persistent DNS cache backed by SQLite."""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from pathlib import Path

from . import config

log = logging.getLogger("dohproxy.dnscache")


class DnsCache:
    def __init__(self, db_path: Path | None = None, ttl_sec: int | None = None) -> None:
        self._db_path = Path(db_path or config.DNS_CACHE_DB)
        self._ttl_sec = config.DNS_CACHE_TTL_SEC if ttl_sec is None else max(0, int(ttl_sec))
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    def start(self) -> None:
        with self._lock:
            if self._ttl_sec <= 0 or self._conn is not None:
                return
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self._db_path, timeout=5.0, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dns_cache (
                    query BLOB PRIMARY KEY,
                    response BLOB NOT NULL,
                    stored_at INTEGER NOT NULL
                ) WITHOUT ROWID
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_cache_stored_at ON dns_cache(stored_at)")
            self._conn = conn
            self._prune_locked(int(time.time()))
            log.info("DNS cache enabled: %s (ttl=%ds)", self._db_path, self._ttl_sec)

    def stop(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def get(self, query: bytes) -> bytes | None:
        if self._ttl_sec <= 0:
            return None
        if len(query) < 2:
            return None
        self._ensure_started()
        assert self._conn is not None
        now = int(time.time())
        cutoff = now - self._ttl_sec
        key = self._cache_key(query)
        with self._lock:
            row = self._conn.execute(
                "SELECT response, stored_at FROM dns_cache WHERE query = ?",
                (key,),
            ).fetchone()
            if row is None:
                return None
            response, stored_at = row
            if stored_at < cutoff:
                self._conn.execute("DELETE FROM dns_cache WHERE query = ?", (key,))
                self._conn.commit()
                return None
            return self._apply_query_id(query, bytes(response))

    def put(self, query: bytes, response: bytes) -> None:
        if self._ttl_sec <= 0:
            return
        if len(query) < 2 or len(response) < 2:
            return
        self._ensure_started()
        assert self._conn is not None
        now = int(time.time())
        cutoff = now - self._ttl_sec
        key = self._cache_key(query)
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO dns_cache(query, response, stored_at) VALUES (?, ?, ?)",
                (key, response, now),
            )
            self._conn.execute("DELETE FROM dns_cache WHERE stored_at < ?", (cutoff,))
            self._conn.commit()

    def _ensure_started(self) -> None:
        if self._conn is None:
            self.start()

    def _prune_locked(self, cutoff: int) -> None:
        if self._conn is None:
            return
        self._conn.execute("DELETE FROM dns_cache WHERE stored_at < ?", (cutoff,))
        self._conn.commit()

    @staticmethod
    def _cache_key(query: bytes) -> bytes:
        # DNS query IDs are typically randomized per request. Cache on the
        # message body so different IDs for the same question still hit.
        return query[2:]

    @staticmethod
    def _apply_query_id(query: bytes, response: bytes) -> bytes:
        return query[:2] + response[2:]
