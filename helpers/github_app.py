import os
import time
import httpx
import jwt


_token_cache: dict[int, tuple[str, float]] = {}  # installation_id -> (token, expires_at)


def _generate_app_jwt() -> str:
    app_id = os.environ["GITHUB_APP_ID"]
    key_path = os.environ["GITHUB_APP_PRIVATE_KEY_PATH"]
    with open(key_path) as f:
        private_key = f.read()
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 600, "iss": app_id}
    return jwt.encode(payload, private_key, algorithm="RS256")


async def get_installation_token(installation_id: int) -> str:
    """Returns a cached installation access token, refreshing if within 5 minutes of expiry."""
    token, expires_at = _token_cache.get(installation_id, ("", 0.0))
    if token and time.time() < expires_at - 300:
        return token

    app_jwt = _generate_app_jwt()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
            },
        )
        resp.raise_for_status()
        data = resp.json()

    new_token: str = data["token"]
    # GitHub tokens are valid for 1 hour; expires_at is ISO 8601
    from datetime import datetime, timezone
    expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")).timestamp()
    _token_cache[installation_id] = (new_token, expires_at)
    return new_token
