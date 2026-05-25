"""Simple in-process TTL cache for Temporal activity results.

Thread-safe for asyncio (single-threaded cooperative scheduling). Contents
are lost on worker restart — that's fine. The goal is to avoid redundant
network calls when multiple repos bump the same package to the same version
within the same worker process lifetime.

Usage:
    _cache = ActivityCache()                    # immutable results — cache forever
    _cache = ActivityCache(ttl_seconds=3600)    # stale-ish results — 1 hour TTL

    key = (ecosystem, package, old_version, new_version)
    if (hit := _cache.get(key)) is not None:
        activity.logger.debug("cache hit for %s %s", package, new_version)
        return hit
    result = await _fetch(...)
    _cache.set(key, result)
    return result
"""

import time
from typing import Any

INDEFINITE = float("inf")

_all_caches: list["ActivityCache"] = []


def clear_all_caches() -> None:
    """Clear every ActivityCache instance. Call from test fixtures."""
    for cache in _all_caches:
        cache.clear()


class ActivityCache:
    __slots__ = ("_ttl", "_store")

    def __init__(self, ttl_seconds: float = INDEFINITE) -> None:
        self._ttl = ttl_seconds
        self._store: dict[tuple, tuple[float, Any]] = {}
        _all_caches.append(self)

    def get(self, key: tuple) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        ts, value = entry
        if self._ttl != INDEFINITE and time.monotonic() - ts > self._ttl:
            del self._store[key]
            return None
        return value

    def set(self, key: tuple, value: Any) -> None:
        self._store[key] = (time.monotonic(), value)

    def clear(self) -> None:
        self._store.clear()

    def __len__(self) -> int:
        return len(self._store)
