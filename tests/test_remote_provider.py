"""Tests for RemoteEcosystemProvider — the HTTP bridge base class."""

from __future__ import annotations

import io
import re
import tarfile
import zipfile

import httpx
import pytest
import respx
from temporalio.exceptions import ApplicationError
from temporalio.testing import ActivityEnvironment

from activities.ecosystems.remote import RemoteEcosystemProvider

_BASE = "https://bridge.example.com/triage/v1"


class _FakeProvider(RemoteEcosystemProvider):
    ecosystem_name = "fake"
    osv_name = "Fake"
    dependabot_slug = "fake"
    name_re = re.compile(r"^[a-z]+$")
    remote_base_url = _BASE


_PROVIDER = _FakeProvider()
PKG = "mypackage"
OLD = "1.0.0"
NEW = "1.1.0"


# ---------------------------------------------------------------------------
# fetch_metadata
# ---------------------------------------------------------------------------


@respx.mock
async def test_fetch_metadata_success():
    respx.post(f"{_BASE}/fetch_metadata").mock(
        return_value=httpx.Response(200, json={"is_major_bump": False})
    )
    env = ActivityEnvironment()
    result = await env.run(_PROVIDER.fetch_metadata, PKG, OLD, NEW)
    assert result.is_major_bump is False
    assert result.weekly_downloads is None


@respx.mock
async def test_fetch_metadata_404_non_retryable():
    respx.post(f"{_BASE}/fetch_metadata").mock(return_value=httpx.Response(404))
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(_PROVIDER.fetch_metadata, PKG, OLD, NEW)
    assert exc_info.value.non_retryable is True


@respx.mock
async def test_fetch_metadata_410_non_retryable():
    respx.post(f"{_BASE}/fetch_metadata").mock(return_value=httpx.Response(410))
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(_PROVIDER.fetch_metadata, PKG, OLD, NEW)
    assert exc_info.value.non_retryable is True


# ---------------------------------------------------------------------------
# fetch_release_age
# ---------------------------------------------------------------------------


@respx.mock
async def test_fetch_release_age_success():
    respx.post(f"{_BASE}/fetch_release_age").mock(
        return_value=httpx.Response(200, json={"release_age_hours": 72.5})
    )
    env = ActivityEnvironment()
    result = await env.run(_PROVIDER.fetch_release_age, PKG, NEW)
    assert result.release_age_hours == pytest.approx(72.5)


@respx.mock
async def test_fetch_release_age_null_body():
    respx.post(f"{_BASE}/fetch_release_age").mock(return_value=httpx.Response(200, json=None))
    env = ActivityEnvironment()
    result = await env.run(_PROVIDER.fetch_release_age, PKG, NEW)
    assert result.release_age_hours is None


# ---------------------------------------------------------------------------
# fetch_maintainer
# ---------------------------------------------------------------------------


@respx.mock
async def test_fetch_maintainer_changed():
    respx.post(f"{_BASE}/fetch_maintainer").mock(
        return_value=httpx.Response(200, json={"maintainer_changed": True})
    )
    env = ActivityEnvironment()
    result = await env.run(_PROVIDER.fetch_maintainer, PKG, OLD, NEW)
    assert result.maintainer_changed is True


# ---------------------------------------------------------------------------
# get_archive_url
# ---------------------------------------------------------------------------


@respx.mock
async def test_get_archive_url_success():
    respx.post(f"{_BASE}/get_archive_url").mock(
        return_value=httpx.Response(
            200,
            json={
                "url": "https://files.pythonhosted.org/packages/mypackage-1.1.0.zip",
                "filename": "mypackage-1.1.0.zip",
                "checksum": "sha256:abc",
            },
        )
    )
    async with httpx.AsyncClient() as client:
        result = await _PROVIDER.get_archive_url(client, PKG, NEW)
    assert result is not None
    url, filename, checksum = result
    assert "files.pythonhosted.org" in url
    assert filename == "mypackage-1.1.0.zip"
    assert checksum == "sha256:abc"


@respx.mock
async def test_get_archive_url_null_means_none():
    respx.post(f"{_BASE}/get_archive_url").mock(return_value=httpx.Response(200, json=None))
    async with httpx.AsyncClient() as client:
        result = await _PROVIDER.get_archive_url(client, PKG, NEW)
    assert result is None


@respx.mock
async def test_get_archive_url_untrusted_host_raises():
    respx.post(f"{_BASE}/get_archive_url").mock(
        return_value=httpx.Response(
            200,
            json={
                "url": "https://evil.example.com/malware.zip",
                "filename": "malware.zip",
                "checksum": "",
            },
        )
    )
    async with httpx.AsyncClient() as client:
        with pytest.raises(ApplicationError) as exc_info:
            await _PROVIDER.get_archive_url(client, PKG, NEW)
    assert exc_info.value.non_retryable is True


# ---------------------------------------------------------------------------
# extract_archive — zip
# ---------------------------------------------------------------------------


def test_extract_zip(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("mypackage-1.1.0/setup.py", "# setup")
    _PROVIDER.extract_archive(buf.getvalue(), "mypackage-1.1.0.zip", str(tmp_path))
    assert (tmp_path / "mypackage-1.1.0" / "setup.py").exists()


def _make_tar(name: str = "mypackage-1.1.0") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        content = b"# setup"
        info = tarfile.TarInfo(name=f"{name}/setup.py")
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def test_extract_tar(tmp_path):
    _PROVIDER.extract_archive(_make_tar(), "mypackage-1.1.0.tar.gz", str(tmp_path))
    assert (tmp_path / "mypackage-1.1.0" / "setup.py").exists()


def test_extract_zip_path_traversal_rejected(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.py", "malicious")
    with pytest.raises(ApplicationError) as exc_info:
        _PROVIDER.extract_archive(buf.getvalue(), "bad.zip", str(tmp_path))
    assert exc_info.value.non_retryable is True


# ---------------------------------------------------------------------------
# fetch_attestations
# ---------------------------------------------------------------------------


@respx.mock
async def test_fetch_attestations_has_attestation():
    respx.post(f"{_BASE}/fetch_attestations").mock(
        return_value=httpx.Response(200, json={"has_attestation": True, "publisher_kind": "GitHub"})
    )
    env = ActivityEnvironment()
    result = await env.run(_PROVIDER.fetch_attestations, PKG, OLD, NEW)
    assert result.has_attestation is True
    assert result.publisher_kind == "GitHub"


# ---------------------------------------------------------------------------
# fetch_release
# ---------------------------------------------------------------------------


@respx.mock
async def test_fetch_release_exists():
    respx.post(f"{_BASE}/fetch_release").mock(
        return_value=httpx.Response(
            200, json={"github_release_exists": True, "release_author": "bot"}
        )
    )
    env = ActivityEnvironment()
    result = await env.run(_PROVIDER.fetch_release, PKG, OLD, NEW)
    assert result.github_release_exists is True
    assert result.release_author == "bot"


# ---------------------------------------------------------------------------
# not auto-discovered as a standalone provider
# ---------------------------------------------------------------------------


def test_remote_base_class_not_in_registry():
    from activities.ecosystems import _build_provider_registry

    registry = _build_provider_registry()
    # The base class has no ecosystem_name value, so it must not be registered
    for name, provider in registry.items():
        assert type(provider).__name__ != "RemoteEcosystemProvider", (
            "RemoteEcosystemProvider itself was auto-discovered — it should only be a base class"
        )
