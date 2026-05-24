"""
GitHub App authentication helpers.

Generates short-lived App JWTs and exchanges them for installation access
tokens (scoped to one installation, valid 1 hour). Tokens are cached and
refreshed automatically when within 5 minutes of expiry.
"""

import os
import time
from datetime import datetime

import httpx
import jwt
from temporalio.exceptions import ApplicationError

_token_cache: dict[int, tuple[str, float]] = {}  # installation_id → (token, unix_expires_at)


def _load_private_key() -> str:
    """Load the App private key from a file path or inline env var."""
    if path := os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH"):
        with open(path) as f:
            return f.read()
    if key := os.environ.get("GITHUB_APP_PRIVATE_KEY"):
        # Deployment platforms often encode newlines as literal \n
        return key.replace("\\n", "\n")
    raise ValueError(
        "GitHub App private key not configured. "
        "Set GITHUB_APP_PRIVATE_KEY_PATH or GITHUB_APP_PRIVATE_KEY."
    )


def _generate_app_jwt() -> str:
    app_id = os.environ["GITHUB_APP_ID"]
    private_key = _load_private_key()
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 600, "iss": app_id}
    return jwt.encode(payload, private_key, algorithm="RS256")


async def get_installation_token(installation_id: int) -> str:
    """Return a valid installation access token, fetching a new one if needed."""
    token, expires_at = _token_cache.get(installation_id, ("", 0.0))
    if token and time.time() < expires_at - 300:  # refresh 5 min before expiry
        return token

    app_jwt = _generate_app_jwt()
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )

    if resp.status_code == 401:
        _token_cache.pop(installation_id, None)  # evict stale entry so next call retries
        raise ApplicationError(
            "GitHub App JWT rejected — check GITHUB_APP_ID and private key",
            non_retryable=True,
        )
    if resp.status_code == 404:
        raise ApplicationError(
            f"Installation {installation_id} not found — App may not be installed on this repo",
            non_retryable=True,
        )
    resp.raise_for_status()

    data = resp.json()
    new_token: str = data["token"]
    exp = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")).timestamp()
    _token_cache[installation_id] = (new_token, exp)
    return new_token
