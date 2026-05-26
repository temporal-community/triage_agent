"""Shared httpx.AsyncClient for all signal activities.

A single client with connection pooling replaces per-call instantiation,
reusing TCP connections and TLS sessions across activity invocations.
Timeouts are specified per-request, not per-client.
"""

import httpx

_client: httpx.AsyncClient | None = None


def get_client() -> httpx.AsyncClient:
    """Return the shared AsyncClient, creating it on first call."""
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            limits=httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20,
                keepalive_expiry=30.0,
            ),
        )
    return _client
