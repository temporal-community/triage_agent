"""Unit tests for the Go Modules ecosystem provider."""
from __future__ import annotations

import io
import zipfile
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx
from temporalio.exceptions import ApplicationError
from temporalio.testing import ActivityEnvironment

from activities.ecosystems.gomod import GoModulesProvider, _escape

_PROXY = "https://proxy.golang.org"
_NOW = datetime.now(timezone.utc)
_OLD_TS = (_NOW - timedelta(days=180)).strftime("%Y-%m-%dT%H:%M:%SZ")
_NEW_TS = (_NOW - timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%SZ")

MODULE = "github.com/gorilla/mux"
OLD_VER = "v1.8.0"
NEW_VER = "v1.8.1"
_ESCAPED = _escape(MODULE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _info(version: str, ts: str = _NEW_TS, repo: str = "https://github.com/gorilla/mux") -> dict:
    return {
        "Version": version,
        "Time": ts,
        "Origin": {"VCS": "git", "URL": repo, "Ref": f"refs/tags/{version}"},
    }


def _make_zip(module: str, version: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"{module}@{version}/README.md", "# Hello")
        zf.writestr(f"{module}@{version}/go.mod", f"module {module}\n\ngo 1.21\n")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# _escape
# ---------------------------------------------------------------------------

def test_escape_lowercase_unchanged():
    assert _escape("github.com/gorilla/mux") == "github.com/gorilla/mux"


def test_escape_uppercase_encoded():
    assert _escape("github.com/BurntSushi/toml") == "github.com/!burnt!sushi/toml"


# ---------------------------------------------------------------------------
# fetch_metadata
# ---------------------------------------------------------------------------

@respx.mock
async def test_metadata_success():
    respx.get(f"{_PROXY}/{_ESCAPED}/@v/{NEW_VER}.info").mock(
        return_value=httpx.Response(200, json=_info(NEW_VER))
    )
    env = ActivityEnvironment()
    result = await env.run(GoModulesProvider().fetch_metadata, MODULE, OLD_VER, NEW_VER)
    assert result.is_major_bump is False
    assert result.weekly_downloads is None
    assert result.package_description is None


@respx.mock
async def test_metadata_major_bump():
    respx.get(f"{_PROXY}/{_ESCAPED}/@v/v2.0.0.info").mock(
        return_value=httpx.Response(200, json=_info("v2.0.0"))
    )
    env = ActivityEnvironment()
    result = await env.run(GoModulesProvider().fetch_metadata, MODULE, OLD_VER, "v2.0.0")
    assert result.is_major_bump is True


@respx.mock
async def test_metadata_404_raises_non_retryable():
    respx.get(f"{_PROXY}/{_ESCAPED}/@v/{NEW_VER}.info").mock(
        return_value=httpx.Response(404)
    )
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(GoModulesProvider().fetch_metadata, MODULE, OLD_VER, NEW_VER)
    assert exc_info.value.non_retryable is True


@respx.mock
async def test_metadata_410_raises_non_retryable():
    respx.get(f"{_PROXY}/{_ESCAPED}/@v/{NEW_VER}.info").mock(
        return_value=httpx.Response(410)
    )
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(GoModulesProvider().fetch_metadata, MODULE, OLD_VER, NEW_VER)
    assert exc_info.value.non_retryable is True


# ---------------------------------------------------------------------------
# fetch_release_age
# ---------------------------------------------------------------------------

@respx.mock
async def test_release_age_recent():
    respx.get(f"{_PROXY}/{_ESCAPED}/@v/{NEW_VER}.info").mock(
        return_value=httpx.Response(200, json=_info(NEW_VER, ts=_NEW_TS))
    )
    env = ActivityEnvironment()
    result = await env.run(GoModulesProvider().fetch_release_age, MODULE, NEW_VER)
    assert result.release_age_hours is not None
    assert 40 < result.release_age_hours < 56


@respx.mock
async def test_release_age_missing_time():
    respx.get(f"{_PROXY}/{_ESCAPED}/@v/{NEW_VER}.info").mock(
        return_value=httpx.Response(200, json={"Version": NEW_VER})
    )
    env = ActivityEnvironment()
    result = await env.run(GoModulesProvider().fetch_release_age, MODULE, NEW_VER)
    assert result.release_age_hours is None


# ---------------------------------------------------------------------------
# fetch_maintainer
# ---------------------------------------------------------------------------

async def test_maintainer_always_false():
    env = ActivityEnvironment()
    result = await env.run(GoModulesProvider().fetch_maintainer, MODULE, OLD_VER, NEW_VER)
    assert result.maintainer_changed is False


# ---------------------------------------------------------------------------
# get_archive_url
# ---------------------------------------------------------------------------

async def test_get_archive_url():
    provider = GoModulesProvider()
    async with httpx.AsyncClient() as client:
        result = await provider.get_archive_url(client, MODULE, NEW_VER)
    assert result is not None
    url, filename, checksum = result
    assert url == f"{_PROXY}/{_ESCAPED}/@v/{NEW_VER}.zip"
    assert filename.endswith(".zip")
    assert checksum == ""


# ---------------------------------------------------------------------------
# extract_archive
# ---------------------------------------------------------------------------

def test_extract_archive(tmp_path):
    provider = GoModulesProvider()
    zip_bytes = _make_zip(MODULE, NEW_VER)
    provider.extract_archive(zip_bytes, f"mux@{NEW_VER}.zip", str(tmp_path))
    assert (tmp_path / f"{MODULE}@{NEW_VER}" / "go.mod").exists()


# ---------------------------------------------------------------------------
# fetch_attestations
# ---------------------------------------------------------------------------

async def test_attestations_always_false():
    env = ActivityEnvironment()
    result = await env.run(GoModulesProvider().fetch_attestations, MODULE, OLD_VER, NEW_VER)
    assert result.has_attestation is False


# ---------------------------------------------------------------------------
# fetch_release
# ---------------------------------------------------------------------------

@respx.mock
async def test_fetch_release_no_origin_url():
    respx.get(f"{_PROXY}/{_ESCAPED}/@v/{NEW_VER}.info").mock(
        return_value=httpx.Response(200, json={"Version": NEW_VER, "Time": _NEW_TS})
    )
    respx.get(f"{_PROXY}/{_ESCAPED}/@v/{OLD_VER}.info").mock(
        return_value=httpx.Response(200, json={"Version": OLD_VER, "Time": _OLD_TS})
    )
    env = ActivityEnvironment()
    result = await env.run(GoModulesProvider().fetch_release, MODULE, OLD_VER, NEW_VER)
    assert result.github_release_exists is False


@respx.mock
async def test_fetch_release_non_200_returns_empty():
    respx.get(f"{_PROXY}/{_ESCAPED}/@v/{NEW_VER}.info").mock(
        return_value=httpx.Response(500)
    )
    respx.get(f"{_PROXY}/{_ESCAPED}/@v/{OLD_VER}.info").mock(
        return_value=httpx.Response(200, json=_info(OLD_VER, ts=_OLD_TS))
    )
    env = ActivityEnvironment()
    result = await env.run(GoModulesProvider().fetch_release, MODULE, OLD_VER, NEW_VER)
    assert result.github_release_exists is False


# ---------------------------------------------------------------------------
# name_re
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "github.com/gorilla/mux",
    "golang.org/x/net",
    "k8s.io/client-go",
    "github.com/foo/bar/v2",
])
def test_name_re_valid(name):
    assert GoModulesProvider.name_re.match(name)


@pytest.mark.parametrize("name", [
    "../../etc/passwd",
    "github.com/../evil",
    "",
])
def test_name_re_rejects_invalid(name):
    assert not GoModulesProvider.name_re.match(name)


# ---------------------------------------------------------------------------
# Ecosystem registration
# ---------------------------------------------------------------------------

def test_go_provider_auto_discovered():
    from activities.ecosystems import get_provider
    assert isinstance(get_provider("go"), GoModulesProvider)


def test_dependabot_slug_map_includes_go():
    from activities.ecosystems import get_dependabot_slug_map
    assert get_dependabot_slug_map().get("go_modules") == "go"
