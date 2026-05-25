"""
Unit tests for the Composer (Packagist) ecosystem provider.
HTTP calls mocked with respx; Temporal context via ActivityEnvironment.
"""

from __future__ import annotations

import io
import time
import zipfile

import httpx
import pytest
import respx
from temporalio.exceptions import ApplicationError
from temporalio.testing import ActivityEnvironment

from ecosystems.composer import ComposerProvider

_PACKAGIST = "https://packagist.org"
_CODELOAD = "https://codeload.github.com"

# ---------------------------------------------------------------------------
# Packagist response helpers
# ---------------------------------------------------------------------------


def _pkg_response(
    vendor: str = "example",
    name: str = "mypackage",
    description: str = "A PHP library",
    monthly_downloads: int = 400_000,
    versions: dict | None = None,
) -> dict:
    now_iso = "2024-01-15T10:00:00+00:00"
    default_version = {
        "name": f"{vendor}/{name}",
        "version": "v1.0.0",
        "version_normalized": "1.0.0.0",
        "time": now_iso,
        "source": {
            "type": "git",
            "url": f"https://github.com/{vendor}/{name}.git",
            "reference": "abc123",
        },
        "dist": {
            "type": "zip",
            "url": f"https://api.github.com/repos/{vendor}/{name}/zipball/abc123",
            "shasum": "deadbeef",
        },
        "authors": [{"name": "Alice Smith", "email": "alice@example.com"}],
        "require": {"php": ">=8.0"},
    }
    return {
        "package": {
            "name": f"{vendor}/{name}",
            "description": description,
            "downloads": {
                "total": 10_000_000,
                "monthly": monthly_downloads,
                "daily": 13_333,
            },
            "versions": versions if versions is not None else {"v1.0.0": default_version},
        }
    }


def _two_version_pkg(
    vendor: str = "example",
    name: str = "mypackage",
    old_authors: list[dict] | None = None,
    new_authors: list[dict] | None = None,
    old_time: str = "2023-01-01T00:00:00+00:00",
    new_time: str = "2024-01-15T10:00:00+00:00",
) -> dict:
    old_authors = old_authors or [{"name": "Alice Smith"}]
    new_authors = new_authors or [{"name": "Alice Smith"}]
    source = {
        "type": "git",
        "url": f"https://github.com/{vendor}/{name}.git",
        "reference": "abc123",
    }
    return {
        "package": {
            "name": f"{vendor}/{name}",
            "description": "A PHP library",
            "downloads": {"monthly": 400_000},
            "versions": {
                "v1.0.0": {
                    "name": f"{vendor}/{name}",
                    "version": "v1.0.0",
                    "time": old_time,
                    "source": source,
                    "authors": old_authors,
                    "require": {},
                },
                "v2.0.0": {
                    "name": f"{vendor}/{name}",
                    "version": "v2.0.0",
                    "time": new_time,
                    "source": source,
                    "authors": new_authors,
                    "require": {},
                },
            },
        }
    }


# ---------------------------------------------------------------------------
# ComposerProvider._parse
# ---------------------------------------------------------------------------


def test_parse_valid():
    p = ComposerProvider()
    assert p._parse("laravel/framework") == ("laravel", "framework")


def test_parse_invalid():
    p = ComposerProvider()
    with pytest.raises(ApplicationError):
        p._parse("no-slash-here")


def test_find_version_bare():
    p = ComposerProvider()
    versions = {"v1.2.3": {"data": True}, "2.0.0": {"other": True}}
    assert p._find_version(versions, "1.2.3") == {"data": True}
    assert p._find_version(versions, "2.0.0") == {"other": True}
    assert p._find_version(versions, "9.9.9") is None


# ---------------------------------------------------------------------------
# fetch_metadata
# ---------------------------------------------------------------------------


@respx.mock
async def test_fetch_metadata_success():
    respx.get(f"{_PACKAGIST}/packages/laravel/framework.json").mock(
        return_value=httpx.Response(
            200, json=_pkg_response(vendor="laravel", name="framework", monthly_downloads=4_000_000)
        )
    )
    env = ActivityEnvironment()
    result = await env.run(
        ComposerProvider().fetch_metadata, "laravel/framework", "10.0.0", "10.1.0"
    )
    assert result.is_major_bump is False
    assert result.package_description == "A PHP library"
    assert result.weekly_downloads == 1_000_000  # 4_000_000 / 4


@respx.mock
async def test_fetch_metadata_major_bump():
    respx.get(f"{_PACKAGIST}/packages/example/mypackage.json").mock(
        return_value=httpx.Response(200, json=_pkg_response())
    )
    env = ActivityEnvironment()
    result = await env.run(ComposerProvider().fetch_metadata, "example/mypackage", "1.9.0", "2.0.0")
    assert result.is_major_bump is True


@respx.mock
async def test_fetch_metadata_no_downloads():
    pkg = _pkg_response()
    pkg["package"]["downloads"] = {}
    respx.get(f"{_PACKAGIST}/packages/example/mypackage.json").mock(
        return_value=httpx.Response(200, json=pkg)
    )
    env = ActivityEnvironment()
    result = await env.run(ComposerProvider().fetch_metadata, "example/mypackage", "1.0.0", "1.1.0")
    assert result.weekly_downloads is None


@respx.mock
async def test_fetch_metadata_404():
    respx.get(f"{_PACKAGIST}/packages/ghost/package.json").mock(return_value=httpx.Response(404))
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(ComposerProvider().fetch_metadata, "ghost/package", "1.0.0", "1.1.0")
    assert exc_info.value.non_retryable is True


# ---------------------------------------------------------------------------
# fetch_release_age
# ---------------------------------------------------------------------------


@respx.mock
async def test_fetch_release_age_success():
    hours_ago = 48
    ts = time.time() - hours_ago * 3600
    from datetime import datetime, timezone

    dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")

    pkg = _pkg_response(
        versions={
            "v1.2.3": {
                "name": "example/mypackage",
                "version": "v1.2.3",
                "time": dt,
                "source": {
                    "type": "git",
                    "url": "https://github.com/example/mypackage.git",
                    "reference": "abc",
                },
                "authors": [{"name": "Alice"}],
                "require": {},
            }
        }
    )
    respx.get(f"{_PACKAGIST}/packages/example/mypackage.json").mock(
        return_value=httpx.Response(200, json=pkg)
    )
    env = ActivityEnvironment()
    result = await env.run(ComposerProvider().fetch_release_age, "example/mypackage", "1.2.3")
    assert result.release_age_hours is not None
    assert 47 < result.release_age_hours < 49


@respx.mock
async def test_fetch_release_age_version_not_found():
    respx.get(f"{_PACKAGIST}/packages/example/mypackage.json").mock(
        return_value=httpx.Response(200, json=_pkg_response())
    )
    env = ActivityEnvironment()
    result = await env.run(ComposerProvider().fetch_release_age, "example/mypackage", "9.9.9")
    assert result.release_age_hours is None


@respx.mock
async def test_fetch_release_age_api_error():
    respx.get(f"{_PACKAGIST}/packages/example/mypackage.json").mock(
        return_value=httpx.Response(503)
    )
    env = ActivityEnvironment()
    result = await env.run(ComposerProvider().fetch_release_age, "example/mypackage", "1.0.0")
    assert result.release_age_hours is None


# ---------------------------------------------------------------------------
# fetch_maintainer
# ---------------------------------------------------------------------------


@respx.mock
async def test_fetch_maintainer_unchanged():
    respx.get(f"{_PACKAGIST}/packages/example/mypackage.json").mock(
        return_value=httpx.Response(200, json=_two_version_pkg())
    )
    env = ActivityEnvironment()
    result = await env.run(
        ComposerProvider().fetch_maintainer, "example/mypackage", "1.0.0", "2.0.0"
    )
    assert result.maintainer_changed is False


@respx.mock
async def test_fetch_maintainer_new_author():
    pkg = _two_version_pkg(
        old_authors=[{"name": "Alice Smith"}],
        new_authors=[{"name": "Alice Smith"}, {"name": "Bob Jones"}],
    )
    respx.get(f"{_PACKAGIST}/packages/example/mypackage.json").mock(
        return_value=httpx.Response(200, json=pkg)
    )
    env = ActivityEnvironment()
    result = await env.run(
        ComposerProvider().fetch_maintainer, "example/mypackage", "1.0.0", "2.0.0"
    )
    assert result.maintainer_changed is True


@respx.mock
async def test_fetch_maintainer_empty_authors():
    pkg = _two_version_pkg(old_authors=[], new_authors=[])
    respx.get(f"{_PACKAGIST}/packages/example/mypackage.json").mock(
        return_value=httpx.Response(200, json=pkg)
    )
    env = ActivityEnvironment()
    result = await env.run(
        ComposerProvider().fetch_maintainer, "example/mypackage", "1.0.0", "2.0.0"
    )
    assert result.maintainer_changed is False


# ---------------------------------------------------------------------------
# fetch_attestations
# ---------------------------------------------------------------------------


async def test_fetch_attestations_returns_empty():
    env = ActivityEnvironment()
    result = await env.run(
        ComposerProvider().fetch_attestations, "example/mypackage", "1.0.0", "1.1.0"
    )
    assert result.has_attestation is False


# ---------------------------------------------------------------------------
# extract_archive
# ---------------------------------------------------------------------------


def test_extract_archive():
    import tempfile
    from pathlib import Path

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("src/MyClass.php", "<?php class MyClass {}")
        zf.writestr("composer.json", '{"name": "example/mypackage"}')
    zip_bytes = buf.getvalue()

    with tempfile.TemporaryDirectory() as dest:
        ComposerProvider().extract_archive(zip_bytes, "mypackage-1.0.0.zip", dest)
        assert (Path(dest) / "composer.json").exists()
        assert (Path(dest) / "src/MyClass.php").exists()


# ---------------------------------------------------------------------------
# get_archive_url
# ---------------------------------------------------------------------------


@respx.mock
async def test_get_archive_url_vtag():
    pkg = _pkg_response(vendor="example", name="mypackage")
    respx.get(f"{_PACKAGIST}/packages/example/mypackage.json").mock(
        return_value=httpx.Response(200, json=pkg)
    )
    respx.head(f"{_CODELOAD}/example/mypackage/zip/refs/tags/v1.0.0").mock(
        return_value=httpx.Response(200)
    )

    async with httpx.AsyncClient(timeout=15.0) as client:
        result = await ComposerProvider().get_archive_url(client, "example/mypackage", "1.0.0")

    assert result is not None
    url, fname, integrity = result
    assert "v1.0.0" in url
    assert fname == "mypackage-1.0.0.zip"
    assert integrity == ""


@respx.mock
async def test_get_archive_url_bare_tag_fallback():
    pkg = _pkg_response()
    respx.get(f"{_PACKAGIST}/packages/example/mypackage.json").mock(
        return_value=httpx.Response(200, json=pkg)
    )
    # v-prefix 404, bare tag 200
    respx.head(f"{_CODELOAD}/example/mypackage/zip/refs/tags/v1.0.0").mock(
        return_value=httpx.Response(404)
    )
    respx.head(f"{_CODELOAD}/example/mypackage/zip/refs/tags/1.0.0").mock(
        return_value=httpx.Response(200)
    )

    async with httpx.AsyncClient(timeout=15.0) as client:
        result = await ComposerProvider().get_archive_url(client, "example/mypackage", "1.0.0")

    assert result is not None
    url, _, _ = result
    assert "/1.0.0" in url
    assert "/v1.0.0" not in url


@respx.mock
async def test_get_archive_url_no_github_source():
    pkg = _pkg_response()
    # Replace source URL with a non-GitHub one
    pkg["package"]["versions"]["v1.0.0"]["source"]["url"] = (
        "https://bitbucket.org/example/mypackage.git"
    )
    respx.get(f"{_PACKAGIST}/packages/example/mypackage.json").mock(
        return_value=httpx.Response(200, json=pkg)
    )

    async with httpx.AsyncClient(timeout=15.0) as client:
        result = await ComposerProvider().get_archive_url(client, "example/mypackage", "1.0.0")

    assert result is None


@respx.mock
async def test_get_archive_url_both_tags_404():
    pkg = _pkg_response()
    respx.get(f"{_PACKAGIST}/packages/example/mypackage.json").mock(
        return_value=httpx.Response(200, json=pkg)
    )
    respx.head(f"{_CODELOAD}/example/mypackage/zip/refs/tags/v1.0.0").mock(
        return_value=httpx.Response(404)
    )
    respx.head(f"{_CODELOAD}/example/mypackage/zip/refs/tags/1.0.0").mock(
        return_value=httpx.Response(404)
    )

    async with httpx.AsyncClient(timeout=15.0) as client:
        result = await ComposerProvider().get_archive_url(client, "example/mypackage", "1.0.0")

    assert result is None


# ---------------------------------------------------------------------------
# pr_parser — composer ecosystem detection
# ---------------------------------------------------------------------------


def test_pr_parser_composer_from_branch():
    from helpers.pr_parser import parse_pr

    result = parse_pr(
        "Bump laravel/framework from 10.0.0 to 10.1.0",
        branch="dependabot/composer/laravel/framework-10.1.0",
    )
    assert result is not None
    assert result.package == "laravel/framework"
    assert result.old_version == "10.0.0"
    assert result.new_version == "10.1.0"
    assert result.ecosystem == "composer"


def test_pr_parser_composer_symfony():
    from helpers.pr_parser import parse_pr

    result = parse_pr(
        "Bump symfony/console from 6.3.0 to 6.4.0",
        branch="dependabot/composer/symfony/console-6.4.0",
    )
    assert result is not None
    assert result.ecosystem == "composer"
    assert result.package == "symfony/console"


# ---------------------------------------------------------------------------
# webhook validation — composer name regex
# ---------------------------------------------------------------------------


def test_webhook_validates_composer_name():
    from api.webhook import _validate_parsed_package

    assert _validate_parsed_package("composer", "laravel/framework", "10.0.0", "10.1.0") is None
    assert _validate_parsed_package("composer", "symfony/console", "6.3.0", "6.4.0") is None


def test_webhook_rejects_composer_no_slash():
    from api.webhook import _validate_parsed_package

    err = _validate_parsed_package("composer", "novendor", "1.0", "2.0")
    assert err is not None


def test_webhook_rejects_composer_path_traversal():
    from api.webhook import _validate_parsed_package

    err = _validate_parsed_package("composer", "evil/../etc/passwd", "1.0", "2.0")
    assert err is not None


# ---------------------------------------------------------------------------
# version_lineage — composer
# ---------------------------------------------------------------------------


@respx.mock
async def test_version_lineage_composer_stale():
    from activities.version_lineage import check as lineage_check

    now = time.time()
    one_year = 365 * 24 * 3600

    def _t(ago_secs: float) -> str:
        from datetime import datetime, timezone

        dt = datetime.fromtimestamp(now - ago_secs, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    pkg = {
        "package": {
            "versions": {
                "v0.9.0": {"time": _t(3 * one_year), "authors": [], "require": {}},
                "v1.0.0": {"time": _t(one_year // 2), "authors": [], "require": {}},
            }
        }
    }
    respx.get("https://packagist.org/packages/example/mypackage.json").mock(
        return_value=httpx.Response(200, json=pkg)
    )
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "composer", "example/mypackage", "v0.8.0", "v0.9.0")
    assert result.stale_version_line is True
    assert result.latest_major == 1
    assert result.bump_major == 0


@respx.mock
async def test_version_lineage_composer_current():
    from activities.version_lineage import check as lineage_check

    now = time.time()

    def _t(ago_secs: float) -> str:
        from datetime import datetime, timezone

        dt = datetime.fromtimestamp(now - ago_secs, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    pkg = {
        "package": {
            "versions": {
                "v1.2.3": {"time": _t(3600), "authors": [], "require": {}},
                "v1.2.2": {"time": _t(86400), "authors": [], "require": {}},
            }
        }
    }
    respx.get("https://packagist.org/packages/example/mypackage.json").mock(
        return_value=httpx.Response(200, json=pkg)
    )
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "composer", "example/mypackage", "1.2.2", "1.2.3")
    assert result.stale_version_line is False


@respx.mock
async def test_version_lineage_composer_filters_dev_branches():
    from activities.version_lineage import check as lineage_check

    now = time.time()

    def _t(ago_secs: float) -> str:
        from datetime import datetime, timezone

        dt = datetime.fromtimestamp(now - ago_secs, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    pkg = {
        "package": {
            "versions": {
                "dev-main": {"time": _t(100), "authors": [], "require": {}},
                "dev-develop": {"time": _t(200), "authors": [], "require": {}},
                "v1.0.0": {"time": _t(3600), "authors": [], "require": {}},
            }
        }
    }
    respx.get("https://packagist.org/packages/example/mypackage.json").mock(
        return_value=httpx.Response(200, json=pkg)
    )
    env = ActivityEnvironment()
    # dev-main should not make 1.0.0 look stale (dev branches aren't stable releases)
    result = await env.run(lineage_check, "composer", "example/mypackage", "0.9.0", "1.0.0")
    assert result.stale_version_line is False
