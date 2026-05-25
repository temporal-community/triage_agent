"""Tests for version lineage signal: detect patches to abandoned major version lines."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx
from temporalio.exceptions import ApplicationError
from temporalio.testing import ActivityEnvironment

from ecosystems import detect_stale_version_line
from activities.version_lineage import check as lineage_check
from models import (
    VersionLineageChecks,
    PackageChecks,
    ReleaseAgeChecks,
)

PYPI_BASE = "https://pypi.org/pypi"
NPM_BASE = "https://registry.npmjs.org"
RUBYGEMS_VER = "https://rubygems.org/api/v1/versions"

_NOW = datetime.now(timezone.utc)
_RECENT = (_NOW - timedelta(days=30)).isoformat()
_OLD = (_NOW - timedelta(days=1000)).isoformat()


# ---------------------------------------------------------------------------
# detect_stale_version_line — pure unit tests
# ---------------------------------------------------------------------------


def test_stale_when_older_major_bumped_and_newer_active():
    result = detect_stale_version_line(
        ["0.9.0", "0.9.1", "1.0.0", "1.0.1", "1.1.0"],
        new_version="0.9.2",
        release_dates={
            "0.9.0": _NOW - timedelta(days=800),
            "0.9.1": _NOW - timedelta(days=700),
            "1.0.0": _NOW - timedelta(days=500),
            "1.0.1": _NOW - timedelta(days=400),
            "1.1.0": _NOW - timedelta(days=30),  # latest major recently active
        },
    )
    assert result.stale_version_line is True
    assert result.bump_major == 0
    assert result.latest_major == 1


def test_not_stale_when_patching_latest_major():
    result = detect_stale_version_line(
        ["0.9.0", "1.0.0", "1.0.1"],
        new_version="1.0.2",
        release_dates={
            "0.9.0": _NOW - timedelta(days=800),
            "1.0.0": _NOW - timedelta(days=100),
            "1.0.1": _NOW - timedelta(days=50),
        },
    )
    assert result.stale_version_line is False
    assert result.bump_major == 1
    assert result.latest_major == 1


def test_not_stale_when_latest_major_itself_is_old():
    """If the highest major line is also inactive, don't flag — maybe the project maintains both."""
    result = detect_stale_version_line(
        ["0.9.0", "0.9.1", "1.0.0"],
        new_version="0.9.2",
        release_dates={
            "0.9.0": _NOW - timedelta(days=900),
            "0.9.1": _NOW - timedelta(days=800),
            "1.0.0": _NOW - timedelta(days=800),  # latest major also old
        },
    )
    assert result.stale_version_line is False


def test_not_stale_without_release_dates_same_major():
    """No release_dates provided — still catches clear cases by version numbers alone."""
    result = detect_stale_version_line(
        ["0.1.0", "0.2.0", "1.0.0"],
        new_version="0.2.1",
    )
    # Without dates, we still flag (conservative)
    assert result.stale_version_line is True
    assert result.bump_major == 0
    assert result.latest_major == 1


def test_prerelease_versions_excluded():
    """Pre-release versions (alpha, beta, rc) do not count as stable major versions."""
    result = detect_stale_version_line(
        ["1.0.0", "1.1.0", "2.0.0a1", "2.0.0rc1"],
        new_version="1.1.1",
        release_dates={
            "1.0.0": _NOW - timedelta(days=200),
            "1.1.0": _NOW - timedelta(days=100),
            "2.0.0a1": _NOW - timedelta(days=10),
            "2.0.0rc1": _NOW - timedelta(days=5),
        },
    )
    # 2.x is only pre-releases, so 1.x is the latest stable major
    assert result.stale_version_line is False
    assert result.latest_major == 1


def test_empty_version_list():
    result = detect_stale_version_line([], new_version="1.0.0")
    assert result.stale_version_line is False


def test_v_prefix_versions_parsed():
    """Versions with a 'v' prefix are handled."""
    result = detect_stale_version_line(
        ["v0.9.0", "v1.0.0"],
        new_version="v0.9.1",
    )
    assert result.bump_major == 0
    assert result.latest_major == 1


# ---------------------------------------------------------------------------
# Activity tests — PyPI
# ---------------------------------------------------------------------------


def _pypi_releases_json(versions_with_dates: dict[str, str]) -> dict:
    releases = {}
    for version, ts in versions_with_dates.items():
        releases[version] = [{"upload_time_iso_8601": ts, "filename": f"pkg-{version}.tar.gz"}]
    return {"releases": releases, "info": {"name": "pkg"}}


@respx.mock
async def test_pypi_stale_version_line_detected():
    respx.get(f"{PYPI_BASE}/pkg/json").mock(
        return_value=httpx.Response(
            200,
            json=_pypi_releases_json(
                {
                    "0.9.0": _OLD,
                    "0.9.1": _OLD,
                    "1.0.0": _RECENT,
                    "1.1.0": _RECENT,
                }
            ),
        )
    )
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "pip", "pkg", "0.9.0", "0.9.2")
    assert result.stale_version_line is True
    assert result.bump_major == 0
    assert result.latest_major == 1


@respx.mock
async def test_pypi_no_stale_line_when_patching_latest():
    respx.get(f"{PYPI_BASE}/requests/json").mock(
        return_value=httpx.Response(
            200,
            json=_pypi_releases_json(
                {
                    "2.31.0": _OLD,
                    "2.32.0": _RECENT,
                }
            ),
        )
    )
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "pip", "requests", "2.31.0", "2.32.0")
    assert result.stale_version_line is False


@respx.mock
async def test_pypi_404_raises_non_retryable():
    from temporalio.exceptions import ApplicationError

    respx.get(f"{PYPI_BASE}/nosuchpkg/json").mock(return_value=httpx.Response(404))
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(lineage_check, "pip", "nosuchpkg", "1.0.0", "1.0.1")
    assert exc_info.value.non_retryable is True


# ---------------------------------------------------------------------------
# Activity tests — npm
# ---------------------------------------------------------------------------


def _npm_pkg_json(versions_with_dates: dict[str, str]) -> dict:
    time_map = {"created": _OLD, "modified": _RECENT}
    time_map.update(versions_with_dates)
    return {"time": time_map}


@respx.mock
async def test_npm_stale_version_line_detected():
    respx.get(f"{NPM_BASE}/mypkg").mock(
        return_value=httpx.Response(
            200,
            json=_npm_pkg_json(
                {
                    "0.1.0": _OLD,
                    "1.0.0": _RECENT,
                    "1.1.0": _RECENT,
                }
            ),
        )
    )
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "npm", "mypkg", "0.1.0", "0.1.1")
    assert result.stale_version_line is True
    assert result.bump_major == 0
    assert result.latest_major == 1


# ---------------------------------------------------------------------------
# Activity tests — RubyGems
# ---------------------------------------------------------------------------


def _rubygems_versions_json(versions_with_dates: dict[str, str]) -> list[dict]:
    return [{"number": v, "created_at": ts} for v, ts in versions_with_dates.items()]


@respx.mock
async def test_rubygems_stale_version_line_detected():
    respx.get(f"{RUBYGEMS_VER}/mygem.json").mock(
        return_value=httpx.Response(
            200,
            json=_rubygems_versions_json(
                {
                    "0.5.0": _OLD,
                    "1.0.0": _RECENT,
                }
            ),
        )
    )
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "rubygems", "mygem", "0.5.0", "0.5.1")
    assert result.stale_version_line is True


# ---------------------------------------------------------------------------
# Activity tests — npm 404
# ---------------------------------------------------------------------------


@respx.mock
async def test_npm_404_raises_non_retryable():
    respx.get(f"{NPM_BASE}/nosuchpkg").mock(return_value=httpx.Response(404))
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(lineage_check, "npm", "nosuchpkg", "1.0.0", "1.0.1")
    assert exc_info.value.non_retryable is True


# ---------------------------------------------------------------------------
# Activity tests — RubyGems 404
# ---------------------------------------------------------------------------


@respx.mock
async def test_rubygems_404_raises_non_retryable():
    respx.get(f"{RUBYGEMS_VER}/nosuchgem.json").mock(return_value=httpx.Response(404))
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(lineage_check, "rubygems", "nosuchgem", "1.0.0", "1.0.1")
    assert exc_info.value.non_retryable is True


# ---------------------------------------------------------------------------
# Activity tests — Composer edge cases
# ---------------------------------------------------------------------------

PACKAGIST_BASE = "https://packagist.org/packages"


@respx.mock
async def test_composer_no_slash_returns_empty():
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "composer", "noslash", "1.0.0", "1.0.1")
    assert result == VersionLineageChecks()


@respx.mock
async def test_composer_404_raises_non_retryable():
    respx.get(f"{PACKAGIST_BASE}/vendor/pkg.json").mock(return_value=httpx.Response(404))
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(lineage_check, "composer", "vendor/pkg", "1.0.0", "1.0.1")
    assert exc_info.value.non_retryable is True


@respx.mock
async def test_composer_non_200_returns_empty():
    respx.get(f"{PACKAGIST_BASE}/vendor/pkg.json").mock(return_value=httpx.Response(503))
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "composer", "vendor/pkg", "1.0.0", "1.0.1")
    assert result == VersionLineageChecks()


@respx.mock
async def test_composer_no_versions_returns_empty():
    respx.get(f"{PACKAGIST_BASE}/vendor/pkg.json").mock(
        return_value=httpx.Response(200, json={"package": {"versions": {}}})
    )
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "composer", "vendor/pkg", "1.0.0", "1.0.1")
    assert result == VersionLineageChecks()


# ---------------------------------------------------------------------------
# Activity tests — Maven edge cases
# ---------------------------------------------------------------------------

MAVEN_SEARCH = "https://search.maven.org/solrsearch/select"


@respx.mock
async def test_maven_no_colon_returns_empty():
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "maven", "nocolon", "1.0.0", "1.0.1")
    assert result == VersionLineageChecks()


@respx.mock
async def test_maven_non_200_returns_empty():
    respx.get(MAVEN_SEARCH).mock(return_value=httpx.Response(503))
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "maven", "com.example:lib", "1.0.0", "1.0.1")
    assert result == VersionLineageChecks()


@respx.mock
async def test_maven_no_docs_returns_empty():
    respx.get(MAVEN_SEARCH).mock(return_value=httpx.Response(200, json={"response": {"docs": []}}))
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "maven", "com.example:lib", "1.0.0", "1.0.1")
    assert result == VersionLineageChecks()


# ---------------------------------------------------------------------------
# Activity tests — NuGet edge cases
# ---------------------------------------------------------------------------

NUGET_BASE = "https://api.nuget.org/v3-flatcontainer"


@respx.mock
async def test_nuget_non_200_returns_empty():
    respx.get(f"{NUGET_BASE}/mypkg/index.json").mock(return_value=httpx.Response(503))
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "nuget", "mypkg", "1.0.0", "1.0.1")
    assert result == VersionLineageChecks()


# ---------------------------------------------------------------------------
# Activity tests — unknown ecosystem falls through
# ---------------------------------------------------------------------------


@respx.mock
async def test_unknown_ecosystem_returns_empty():
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "gomod", "github.com/foo/bar", "1.0.0", "1.0.1")
    assert result == VersionLineageChecks()


# ---------------------------------------------------------------------------
# Activity tests — Cargo (crates.io)
# ---------------------------------------------------------------------------

CARGO_API = "https://crates.io/api/v1/crates"


def _cargo_crate_response(versions: dict[str, str], yanked: set[str] | None = None) -> dict:
    """Build a minimal crates.io API response with the given {version: created_at} map."""
    yanked = yanked or set()
    return {
        "crate": {"id": "mycrate", "name": "mycrate"},
        "versions": [
            {"num": v, "created_at": ts, "yanked": v in yanked} for v, ts in versions.items()
        ],
    }


@respx.mock
async def test_cargo_stale_version_line_detected():
    respx.get(f"{CARGO_API}/mycrate").mock(
        return_value=httpx.Response(
            200,
            json=_cargo_crate_response({"0.5.0": _OLD, "1.0.0": _RECENT, "1.1.0": _RECENT}),
        )
    )
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "cargo", "mycrate", "0.5.0", "0.5.1")
    assert result.stale_version_line is True
    assert result.bump_major == 0
    assert result.latest_major == 1


@respx.mock
async def test_cargo_not_stale_when_patching_latest():
    respx.get(f"{CARGO_API}/mycrate").mock(
        return_value=httpx.Response(
            200,
            json=_cargo_crate_response({"0.5.0": _OLD, "1.0.0": _RECENT, "1.1.0": _RECENT}),
        )
    )
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "cargo", "mycrate", "1.0.0", "1.1.0")
    assert result.stale_version_line is False


@respx.mock
async def test_cargo_yanked_versions_excluded():
    """Yanked versions should not participate in version lineage detection."""
    respx.get(f"{CARGO_API}/mycrate").mock(
        return_value=httpx.Response(
            200,
            json=_cargo_crate_response(
                {"0.5.0": _OLD, "1.0.0": _RECENT},
                yanked={"1.0.0"},
            ),
        )
    )
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "cargo", "mycrate", "0.5.0", "0.5.1")
    # 1.0.0 is yanked so only 0.x is visible — not stale
    assert result.stale_version_line is False


@respx.mock
async def test_cargo_404_raises_non_retryable():
    respx.get(f"{CARGO_API}/nosuchcrate").mock(return_value=httpx.Response(404))
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(lineage_check, "cargo", "nosuchcrate", "1.0.0", "1.0.1")
    assert exc_info.value.non_retryable is True


@respx.mock
async def test_cargo_non_200_returns_empty():
    respx.get(f"{CARGO_API}/mycrate").mock(return_value=httpx.Response(503))
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "cargo", "mycrate", "1.0.0", "1.0.1")
    assert result == VersionLineageChecks()


# ---------------------------------------------------------------------------
# Classifier rule
# ---------------------------------------------------------------------------


def test_rule_based_stale_version_line_is_yellow():
    from classifiers import _rule_based

    signals = PackageChecks(
        ecosystem="pip",
        package_name="oldpkg",
        old_version="0.9.0",
        new_version="0.9.1",
        age=ReleaseAgeChecks(release_age_hours=500.0),
        version_lineage=VersionLineageChecks(stale_version_line=True, latest_major=1, bump_major=0),
    )
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    assert any("0.x" in f and "1.x" in f for f in verdict.flags)
