"""
Tests for helpers/github_app.py — JWT generation and installation token caching.
Uses a real RSA key generated for tests (no GitHub connection needed for JWT tests).
"""

import time
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import httpx
import pytest
import respx

import helpers.github_app as app_module
from helpers.github_app import get_installation_token
from temporalio.exceptions import ApplicationError

INSTALL_URL = "https://api.github.com/app/installations/12345/access_tokens"

# Test RSA private key (generated once, safe to commit — test-only)
TEST_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAxi+GRyOF6FAMGULiKlgOJnlkN3kc1vW2QrJS4Jt4qDMzbZCb
SuGTemSZ5EJwuJ+3cPIJTxXjlsyrVHHMBRny/Oqw/4iuSxyLW2sllI7OVvLzedzJ
zrqWhAFdFaXdR2nF28QFTOVOLpcfyPwpKCVhoHHeJZXK5qt2B/a8GF+ox4+cmKD4
EUJwCnDSbfgh48uZO9/pmNo/Vd5UphmDCOOLnBs7iQxLf21tDZBvgNtTCTF2MXeS
bN+OlkBn0RxWnVqIBpQA6D5Efpa8v7H8sp9WXj2s6Dzgk8M5ZRcg/mHtjhEeIr5F
oVigMh+JhlEpxs33HRT3ldUAl1nKzCplRNQ/GQIDAQABAoIBAF0c4QK1XumqCjUo
JmhsnKFY8Uva3EDmiq5FaAjdItAr1iLJCR0iZI7hiygiSyGC8MXhAZyllRs5p9lx
6cAP1AkeHvC//9uMWrEl4y8r9SgG13vOzwYQxjzZAynzlsZBnNNHApKBPb1IBYgB
aTjSb07ZkNypxv2fW0Icm3z8HKk9LOM5VtA7eyf3QT+yIMzKdbFwL1CQdgwapM/o
CRDQA6Y90wP23U2vpfzGbLm5HlR4SoNx72n/EBVGFuaDKohhzA0wbBhq3cOCKV3E
ZONEiJaZL4SGHwau5w8QvksBeepfuFhIF7sAmCDWqnqrHp1dfcRgiQPzdtXR1ilo
G/7YPG0CgYEA8HSgv/FlVP2uZanMOawhLCvNCpJhEa0RkFQOSPuVQ3W8nzWKAcCj
CKu9gU+IyU2tEf6QfJVgQYKjTUn5ug/1fM3CLfe5qXCtloazltInAP4dmM1z7g2p
n5QdtqzKv2zVDz5jTjR1PUYPSZuf+Q3lZ0C/NJI8SjxLCyH8ApSRxX8CgYEA0v9b
0MiWg/ymz9iWfW58otshY8MjoRrBd/vnDWGpAGv/EiwZ3EssxHkiIGaANP+Ypy33
+xRHHzaQluTNLwA+QT9IuMjeR75nSKkJasKRqNTdn3F+8neeDiGObR9mb2e7qEM1
HLrhWS7E9FJwZWNhVw0pS2tz10s68lqawbYAt2cCgYAo+qderuQnHOi42Lw+Y/Bv
V7OlBpdWbNlecITSuVWR3qHbvEMd01e1pZcxT32vWPaS54B2SvrRj1MHXAEcTZX3
xBVAwkQ49UQQMDqxDHWrPKOMpA8K1fc/g/2gYUhYYVLaOzavYE9Otv7p+4TC7DRZ
aXZsnjN6L1ZWul75jZpePwKBgFgGWnqexFRp+fmqJRZNGsgiXSquhVW3wNDakYj+
ni/j3jTpmxxRbGrHElqsCH6Tx06vmc3wpr8511ZsO8GI+2/jA+a7Pih2IcapZplY
dMYXkCHtioWDK7g/fZi+ydBeWWaYKzdCK7M2FMrM/cD+leRoRDsHp/tAkmX7MKbx
1BivAoGAKXmCoqXBw7BO2WHi7qXnHsbQ49aVQzGqgnAk9dut9bvGhUSMX+dIQc4A
HdUkplILAneqOG13wNFc2j0aQEXJOcFiFv5M01WTcxAGV2IXos5deoUfoYyK0Kci
8ZQuUINM9eEA2kn68lQqOqL4sP5OwymaAvHf6f5yHVKARsEVqL4=
-----END RSA PRIVATE KEY-----"""


def _token_response(token: str = "ghs_test_token", hours_valid: int = 1) -> dict:
    exp = (datetime.now(timezone.utc) + timedelta(hours=hours_valid)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"token": token, "expires_at": exp}


@pytest.fixture(autouse=True)
def clear_cache():
    """Each test starts with a cold token cache."""
    app_module._token_cache.clear()
    yield
    app_module._token_cache.clear()


@pytest.fixture(autouse=True)
def set_app_env(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_ID", "99999")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", TEST_PRIVATE_KEY)


# ---------------------------------------------------------------------------
# Token fetching
# ---------------------------------------------------------------------------


@respx.mock
async def test_fetches_token_on_cache_miss():
    respx.post(INSTALL_URL).mock(
        return_value=httpx.Response(200, json=_token_response("ghs_fresh"))
    )
    token = await get_installation_token(12345)
    assert token == "ghs_fresh"


@respx.mock
async def test_returns_cached_token_on_hit():
    route = respx.post(INSTALL_URL).mock(
        return_value=httpx.Response(200, json=_token_response("ghs_cached"))
    )
    await get_installation_token(12345)
    await get_installation_token(12345)  # second call — should hit cache
    assert route.call_count == 1


@respx.mock
async def test_refreshes_token_near_expiry():
    # Seed cache with a token expiring in 2 minutes (within the 5-min refresh window)
    expires_soon = time.time() + 120
    app_module._token_cache[12345] = ("ghs_old", expires_soon)

    respx.post(INSTALL_URL).mock(return_value=httpx.Response(200, json=_token_response("ghs_new")))
    token = await get_installation_token(12345)
    assert token == "ghs_new"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


@respx.mock
async def test_401_raises_non_retryable():
    respx.post(INSTALL_URL).mock(return_value=httpx.Response(401))
    with pytest.raises(ApplicationError) as exc_info:
        await get_installation_token(12345)
    assert exc_info.value.non_retryable is True


@respx.mock
async def test_404_raises_non_retryable():
    respx.post(INSTALL_URL).mock(return_value=httpx.Response(404))
    with pytest.raises(ApplicationError) as exc_info:
        await get_installation_token(12345)
    assert exc_info.value.non_retryable is True


# ---------------------------------------------------------------------------
# Private key loading
# ---------------------------------------------------------------------------


def test_private_key_from_env_var(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", TEST_PRIVATE_KEY)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY_PATH", raising=False)
    from helpers.github_app import _load_private_key

    key = _load_private_key()
    assert "BEGIN RSA PRIVATE KEY" in key


def test_private_key_from_file(monkeypatch, tmp_path):
    key_file = tmp_path / "key.pem"
    key_file.write_text(TEST_PRIVATE_KEY)
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PATH", str(key_file))
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY", raising=False)
    from helpers.github_app import _load_private_key

    key = _load_private_key()
    assert "BEGIN RSA PRIVATE KEY" in key


def test_private_key_literal_newlines(monkeypatch):
    """Deployment platforms often encode newlines as \\n literals."""
    encoded = TEST_PRIVATE_KEY.replace("\n", "\\n")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", encoded)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY_PATH", raising=False)
    from helpers.github_app import _load_private_key

    key = _load_private_key()
    assert "\n" in key  # literal \n were expanded


def test_missing_key_raises():
    from helpers.github_app import _load_private_key

    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(ValueError, match="not configured"):
            _load_private_key()
