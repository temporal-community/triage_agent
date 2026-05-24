"""Unit tests for the Cargo (crates.io) ecosystem provider."""

from __future__ import annotations

import gzip
import io
import tarfile
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx
from temporalio.exceptions import ApplicationError
from temporalio.testing import ActivityEnvironment

from activities.ecosystems.cargo import CargoProvider

_API = "https://crates.io/api/v1/crates"
_NOW = datetime.now(timezone.utc)
_OLD_TS = (_NOW - timedelta(days=180)).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
_NEW_TS = (_NOW - timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")

PACKAGE = "serde"
OLD_VER = "1.0.100"
NEW_VER = "1.0.200"


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _crate_response(
    description: str = "A generic serialization/deserialization framework",
    recent_downloads: int = 5_000_000,
    old_publisher: str = "dtolnay",
    new_publisher: str = "dtolnay",
    repository: str = "https://github.com/serde-rs/serde",
) -> dict:
    return {
        "crate": {
            "id": PACKAGE,
            "name": PACKAGE,
            "description": description,
            "recent_downloads": recent_downloads,
            "repository": repository,
        },
        "versions": [
            {
                "num": NEW_VER,
                "created_at": _NEW_TS,
                "checksum": "abc123",
                "published_by": {"login": new_publisher},
            },
            {
                "num": OLD_VER,
                "created_at": _OLD_TS,
                "checksum": "def456",
                "published_by": {"login": old_publisher},
            },
        ],
    }


def _make_crate_bytes() -> bytes:
    """Build a minimal valid .crate (gzipped tarball) in memory."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        inner = io.BytesIO()
        with tarfile.open(fileobj=inner, mode="w") as tf:
            content = b"fn main() {}"
            info = tarfile.TarInfo(name=f"{PACKAGE}-{NEW_VER}/src/lib.rs")
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
        gz.write(inner.getvalue())
    return buf.getvalue()


# ---------------------------------------------------------------------------
# fetch_metadata
# ---------------------------------------------------------------------------


@respx.mock
async def test_metadata_success():
    respx.get(f"{_API}/{PACKAGE}").mock(return_value=httpx.Response(200, json=_crate_response()))
    env = ActivityEnvironment()
    provider = CargoProvider()
    result = await env.run(provider.fetch_metadata, PACKAGE, OLD_VER, NEW_VER)
    assert result.weekly_downloads == 5_000_000
    assert result.is_major_bump is False
    assert "serialization" in (result.package_description or "")


@respx.mock
async def test_metadata_404_raises_non_retryable():
    respx.get(f"{_API}/{PACKAGE}").mock(return_value=httpx.Response(404))
    env = ActivityEnvironment()
    provider = CargoProvider()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(provider.fetch_metadata, PACKAGE, OLD_VER, NEW_VER)
    assert exc_info.value.non_retryable is True


@respx.mock
async def test_metadata_major_bump_detected():
    respx.get(f"{_API}/{PACKAGE}").mock(return_value=httpx.Response(200, json=_crate_response()))
    env = ActivityEnvironment()
    provider = CargoProvider()
    result = await env.run(provider.fetch_metadata, PACKAGE, "1.0.0", "2.0.0")
    assert result.is_major_bump is True


# ---------------------------------------------------------------------------
# fetch_release_age
# ---------------------------------------------------------------------------


@respx.mock
async def test_release_age_recent():
    respx.get(f"{_API}/{PACKAGE}").mock(return_value=httpx.Response(200, json=_crate_response()))
    env = ActivityEnvironment()
    provider = CargoProvider()
    result = await env.run(provider.fetch_release_age, PACKAGE, NEW_VER)
    assert result.release_age_hours is not None
    assert 40 < result.release_age_hours < 56  # ~48h


@respx.mock
async def test_release_age_version_not_found():
    respx.get(f"{_API}/{PACKAGE}").mock(return_value=httpx.Response(200, json=_crate_response()))
    env = ActivityEnvironment()
    provider = CargoProvider()
    result = await env.run(provider.fetch_release_age, PACKAGE, "9.9.9")
    assert result.release_age_hours is None


@respx.mock
async def test_release_age_404_raises_non_retryable():
    respx.get(f"{_API}/{PACKAGE}").mock(return_value=httpx.Response(404))
    env = ActivityEnvironment()
    provider = CargoProvider()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(provider.fetch_release_age, PACKAGE, NEW_VER)
    assert exc_info.value.non_retryable is True


# ---------------------------------------------------------------------------
# fetch_maintainer
# ---------------------------------------------------------------------------


@respx.mock
async def test_maintainer_unchanged():
    respx.get(f"{_API}/{PACKAGE}").mock(return_value=httpx.Response(200, json=_crate_response()))
    env = ActivityEnvironment()
    provider = CargoProvider()
    result = await env.run(provider.fetch_maintainer, PACKAGE, OLD_VER, NEW_VER)
    assert result.maintainer_changed is False


@respx.mock
async def test_maintainer_changed():
    respx.get(f"{_API}/{PACKAGE}").mock(
        return_value=httpx.Response(
            200,
            json=_crate_response(old_publisher="original-author", new_publisher="new-publisher"),
        )
    )
    env = ActivityEnvironment()
    provider = CargoProvider()
    result = await env.run(provider.fetch_maintainer, PACKAGE, OLD_VER, NEW_VER)
    assert result.maintainer_changed is True


@respx.mock
async def test_maintainer_missing_published_by_returns_false():
    data = _crate_response()
    for v in data["versions"]:
        v["published_by"] = None
    respx.get(f"{_API}/{PACKAGE}").mock(return_value=httpx.Response(200, json=data))
    env = ActivityEnvironment()
    provider = CargoProvider()
    result = await env.run(provider.fetch_maintainer, PACKAGE, OLD_VER, NEW_VER)
    assert result.maintainer_changed is False


# ---------------------------------------------------------------------------
# get_archive_url
# ---------------------------------------------------------------------------


@respx.mock
async def test_get_archive_url():
    respx.get(f"{_API}/{PACKAGE}").mock(return_value=httpx.Response(200, json=_crate_response()))
    provider = CargoProvider()
    async with httpx.AsyncClient() as client:
        result = await provider.get_archive_url(client, PACKAGE, NEW_VER)
    assert result is not None
    url, filename, checksum = result
    assert url == f"https://static.crates.io/crates/{PACKAGE}/{PACKAGE}-{NEW_VER}.crate"
    assert filename == f"{PACKAGE}-{NEW_VER}.crate"
    assert checksum == "abc123"


@respx.mock
async def test_get_archive_url_version_not_found_returns_none():
    respx.get(f"{_API}/{PACKAGE}").mock(return_value=httpx.Response(200, json=_crate_response()))
    provider = CargoProvider()
    async with httpx.AsyncClient() as client:
        result = await provider.get_archive_url(client, PACKAGE, "9.9.9")
    assert result is None


# ---------------------------------------------------------------------------
# extract_archive
# ---------------------------------------------------------------------------


def test_extract_archive(tmp_path):
    provider = CargoProvider()
    crate_bytes = _make_crate_bytes()
    provider.extract_archive(crate_bytes, f"{PACKAGE}-{NEW_VER}.crate", str(tmp_path))
    assert (tmp_path / f"{PACKAGE}-{NEW_VER}" / "src" / "lib.rs").exists()


# ---------------------------------------------------------------------------
# fetch_attestations
# ---------------------------------------------------------------------------


async def test_attestations_always_false():
    env = ActivityEnvironment()
    provider = CargoProvider()
    result = await env.run(provider.fetch_attestations, PACKAGE, OLD_VER, NEW_VER)
    assert result.has_attestation is False


# ---------------------------------------------------------------------------
# fetch_release
# ---------------------------------------------------------------------------


@respx.mock
async def test_fetch_release_no_github_repo():
    data = _crate_response(repository="")
    respx.get(f"{_API}/{PACKAGE}").mock(return_value=httpx.Response(200, json=data))
    env = ActivityEnvironment()
    provider = CargoProvider()
    result = await env.run(provider.fetch_release, PACKAGE, OLD_VER, NEW_VER)
    assert result.github_release_exists is False


@respx.mock
async def test_fetch_release_non_200_returns_empty():
    respx.get(f"{_API}/{PACKAGE}").mock(return_value=httpx.Response(500))
    env = ActivityEnvironment()
    provider = CargoProvider()
    result = await env.run(provider.fetch_release, PACKAGE, OLD_VER, NEW_VER)
    assert result.github_release_exists is False


# ---------------------------------------------------------------------------
# Ecosystem registration
# ---------------------------------------------------------------------------


def test_cargo_provider_auto_discovered():
    from activities.ecosystems import get_provider

    provider = get_provider("cargo")
    assert isinstance(provider, CargoProvider)
