"""
Unit tests for signal activities. HTTP calls are mocked with respx.
Each test uses ActivityEnvironment to provide the Temporal activity context.
"""
import json
import pytest
import respx
import httpx
from temporalio.testing import ActivityEnvironment

from activities.pypi_metadata import fetch as pypi_fetch
from activities.osv import check as osv_check
from activities.release_age import check as release_age_check
from activities.maintainer import history as maintainer_history


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

PYPI_BASE = "https://pypi.org/pypi"
PYPISTATS_BASE = "https://pypistats.org/api/packages"
OSV_URL = "https://api.osv.dev/v1/query"


def _pypi_response(package: str, version: str, upload_time: str = "2025-01-01T00:00:00Z") -> dict:
    return {
        "info": {
            "name": package,
            "version": version,
            "author": "Test Author",
            "author_email": "test@example.com",
            "maintainer": "",
            "maintainer_email": "",
        },
        "urls": [{"upload_time_iso_8601": upload_time, "upload_time": upload_time.rstrip("Z")}],
    }


# ---------------------------------------------------------------------------
# pypi_metadata
# ---------------------------------------------------------------------------

@respx.mock
async def test_pypi_metadata_fetch_success():
    respx.get(f"{PYPI_BASE}/requests/2.32.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_response("requests", "2.32.0"))
    )
    respx.get(f"{PYPISTATS_BASE}/requests/recent").mock(
        return_value=httpx.Response(200, json={"data": {"last_week": 50_000_000}})
    )

    env = ActivityEnvironment()
    result = await env.run(pypi_fetch, "pip", "requests", "2.31.0", "2.32.0")

    assert result.weekly_downloads == 50_000_000
    assert result.is_major_bump is False


@respx.mock
async def test_pypi_metadata_major_bump():
    respx.get(f"{PYPI_BASE}/django/5.0.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_response("django", "5.0.0"))
    )
    respx.get(f"{PYPISTATS_BASE}/django/recent").mock(
        return_value=httpx.Response(200, json={"data": {"last_week": 1_000_000}})
    )

    env = ActivityEnvironment()
    result = await env.run(pypi_fetch, "pip", "django", "4.2.0", "5.0.0")
    assert result.is_major_bump is True


@respx.mock
async def test_pypi_metadata_404_raises_non_retryable():
    from temporalio.exceptions import ApplicationError
    respx.get(f"{PYPI_BASE}/nonexistent/1.0.0/json").mock(
        return_value=httpx.Response(404)
    )

    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(pypi_fetch, "pip", "nonexistent", "0.9.0", "1.0.0")
    assert exc_info.value.non_retryable is True


@respx.mock
async def test_pypi_metadata_pypistats_failure_returns_none():
    respx.get(f"{PYPI_BASE}/requests/2.32.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_response("requests", "2.32.0"))
    )
    respx.get(f"{PYPISTATS_BASE}/requests/recent").mock(
        return_value=httpx.Response(500)
    )

    env = ActivityEnvironment()
    result = await env.run(pypi_fetch, "pip", "requests", "2.31.0", "2.32.0")
    assert result.weekly_downloads is None


# ---------------------------------------------------------------------------
# osv
# ---------------------------------------------------------------------------

@respx.mock
async def test_osv_no_vulns():
    respx.post(OSV_URL).mock(
        return_value=httpx.Response(200, json={"vulns": []})
    )

    env = ActivityEnvironment()
    result = await env.run(osv_check, "pip", "requests", "2.31.0", "2.32.0")
    assert result.osv_vulnerabilities == []


@respx.mock
async def test_osv_with_cves():
    respx.post(OSV_URL).mock(
        return_value=httpx.Response(200, json={
            "vulns": [
                {"id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["CVE-2024-12345"]},
                {"id": "GHSA-aaaa-bbbb-cccc", "aliases": []},
            ]
        })
    )

    env = ActivityEnvironment()
    result = await env.run(osv_check, "pip", "badpkg", "1.0.0", "1.0.1")
    assert "CVE-2024-12345" in result.osv_vulnerabilities
    assert "GHSA-aaaa-bbbb-cccc" in result.osv_vulnerabilities


@respx.mock
async def test_osv_passes_correct_ecosystem():
    route = respx.post(OSV_URL).mock(
        return_value=httpx.Response(200, json={})
    )

    env = ActivityEnvironment()
    await env.run(osv_check, "pip", "requests", "2.31.0", "2.32.0")

    body = json.loads(route.calls[0].request.content)
    assert body["package"]["ecosystem"] == "PyPI"


# ---------------------------------------------------------------------------
# release_age
# ---------------------------------------------------------------------------

@respx.mock
async def test_release_age_recent():
    from datetime import datetime, timezone, timedelta
    recent = (datetime.now(timezone.utc) - timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
    respx.get(f"{PYPI_BASE}/requests/2.32.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_response("requests", "2.32.0", recent))
    )

    env = ActivityEnvironment()
    result = await env.run(release_age_check, "pip", "requests", "2.31.0", "2.32.0")
    assert 11.0 < result.release_age_hours < 13.0


@respx.mock
async def test_release_age_old():
    respx.get(f"{PYPI_BASE}/requests/2.32.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_response("requests", "2.32.0", "2024-01-01T00:00:00Z"))
    )

    env = ActivityEnvironment()
    result = await env.run(release_age_check, "pip", "requests", "2.31.0", "2.32.0")
    assert result.release_age_hours > 24 * 30  # at least a month old


# ---------------------------------------------------------------------------
# maintainer
# ---------------------------------------------------------------------------

@respx.mock
async def test_maintainer_no_change():
    for version in ("2.31.0", "2.32.0"):
        respx.get(f"{PYPI_BASE}/requests/{version}/json").mock(
            return_value=httpx.Response(200, json=_pypi_response("requests", version))
        )

    env = ActivityEnvironment()
    result = await env.run(maintainer_history, "pip", "requests", "2.31.0", "2.32.0")
    assert result.maintainer_changed is False


@respx.mock
async def test_maintainer_changed():
    old = _pypi_response("pkg", "1.0.0")
    old["info"]["author"] = "original@example.com"
    new = _pypi_response("pkg", "2.0.0")
    new["info"]["author"] = "newcomer@example.com"
    new["info"]["maintainer"] = "newcomer@example.com"

    respx.get(f"{PYPI_BASE}/pkg/1.0.0/json").mock(return_value=httpx.Response(200, json=old))
    respx.get(f"{PYPI_BASE}/pkg/2.0.0/json").mock(return_value=httpx.Response(200, json=new))

    env = ActivityEnvironment()
    result = await env.run(maintainer_history, "pip", "pkg", "1.0.0", "2.0.0")
    assert result.maintainer_changed is True


@respx.mock
async def test_maintainer_fetch_error_returns_no_change():
    # Network error on one version → _fetch_info returns None → default False
    respx.get(f"{PYPI_BASE}/errpkg/1.0.0/json").mock(side_effect=httpx.ConnectError("timeout"))
    respx.get(f"{PYPI_BASE}/errpkg/2.0.0/json").mock(return_value=httpx.Response(200, json=_pypi_response("errpkg", "2.0.0")))
    env = ActivityEnvironment()
    result = await env.run(maintainer_history, "pip", "errpkg", "1.0.0", "2.0.0")
    assert result.maintainer_changed is False


# ---------------------------------------------------------------------------
# pypi_metadata — exception and non-semver edge cases
# ---------------------------------------------------------------------------

@respx.mock
async def test_pypi_metadata_pypistats_network_error_returns_none():
    respx.get(f"{PYPI_BASE}/requests/2.32.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_response("requests", "2.32.0"))
    )
    respx.get(f"{PYPISTATS_BASE}/requests/recent").mock(
        side_effect=httpx.ConnectError("network down")
    )
    env = ActivityEnvironment()
    result = await env.run(pypi_fetch, "pip", "requests", "2.31.0", "2.32.0")
    assert result.weekly_downloads is None


def test_pypi_is_major_non_semver_returns_false():
    from activities.ecosystems import is_major
    assert is_major("not-a-version", "also-not") is False
    assert is_major("", "") is False


# ---------------------------------------------------------------------------
# release_age — 404, empty urls, missing timestamp, naive datetime
# ---------------------------------------------------------------------------

@respx.mock
async def test_release_age_404_raises_non_retryable():
    from activities.release_age import check as release_age_check
    from temporalio.exceptions import ApplicationError
    respx.get(f"{PYPI_BASE}/missing/1.0.0/json").mock(return_value=httpx.Response(404))
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(release_age_check, "pip", "missing", "0.9.0", "1.0.0")
    assert exc_info.value.non_retryable is True


@respx.mock
async def test_release_age_empty_urls_returns_none():
    from activities.release_age import check as release_age_check
    respx.get(f"{PYPI_BASE}/requests/2.32.0/json").mock(
        return_value=httpx.Response(200, json={"info": {}, "urls": []})
    )
    env = ActivityEnvironment()
    result = await env.run(release_age_check, "pip", "requests", "2.31.0", "2.32.0")
    assert result.release_age_hours is None


@respx.mock
async def test_release_age_missing_timestamp_returns_none():
    from activities.release_age import check as release_age_check
    respx.get(f"{PYPI_BASE}/requests/2.32.0/json").mock(
        return_value=httpx.Response(200, json={"info": {}, "urls": [{}]})
    )
    env = ActivityEnvironment()
    result = await env.run(release_age_check, "pip", "requests", "2.31.0", "2.32.0")
    assert result.release_age_hours is None


def test_release_age_naive_datetime_gets_utc():
    from activities.ecosystems import parse_upload_time
    # No Z and no +00:00 → naive datetime → should be treated as UTC
    dt = parse_upload_time("2024-06-01T12:00:00")
    from datetime import timezone
    assert dt.tzinfo is not None
    assert dt.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# npm paths — pypi_metadata
# ---------------------------------------------------------------------------

NPM_BASE = "https://registry.npmjs.org"
NPM_DOWNLOADS_BASE = "https://api.npmjs.org/downloads/point/last-week"


@respx.mock
async def test_npm_metadata_fetch_success():
    respx.get(f"{NPM_BASE}/lodash/4.17.21").mock(
        return_value=httpx.Response(200, json={
            "name": "lodash",
            "version": "4.17.21",
            "description": "Lodash modular utilities.",
        })
    )
    respx.get(f"{NPM_DOWNLOADS_BASE}/lodash").mock(
        return_value=httpx.Response(200, json={"downloads": 30_000_000})
    )

    env = ActivityEnvironment()
    result = await env.run(pypi_fetch, "npm", "lodash", "4.17.20", "4.17.21")

    assert result.weekly_downloads == 30_000_000
    assert result.is_major_bump is False
    assert result.package_description == "Lodash modular utilities."


@respx.mock
async def test_npm_metadata_major_bump():
    respx.get(f"{NPM_BASE}/react/18.0.0").mock(
        return_value=httpx.Response(200, json={"name": "react", "description": "React"})
    )
    respx.get(f"{NPM_DOWNLOADS_BASE}/react").mock(
        return_value=httpx.Response(200, json={"downloads": 50_000_000})
    )

    env = ActivityEnvironment()
    result = await env.run(pypi_fetch, "npm", "react", "17.0.0", "18.0.0")
    assert result.is_major_bump is True


@respx.mock
async def test_npm_metadata_404_raises_non_retryable():
    from temporalio.exceptions import ApplicationError
    respx.get(f"{NPM_BASE}/nonexistent/1.0.0").mock(return_value=httpx.Response(404))

    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(pypi_fetch, "npm", "nonexistent", "0.9.0", "1.0.0")
    assert exc_info.value.non_retryable is True


@respx.mock
async def test_npm_metadata_downloads_failure_returns_none():
    respx.get(f"{NPM_BASE}/lodash/4.17.21").mock(
        return_value=httpx.Response(200, json={"name": "lodash", "description": "Lodash"})
    )
    respx.get(f"{NPM_DOWNLOADS_BASE}/lodash").mock(return_value=httpx.Response(500))

    env = ActivityEnvironment()
    result = await env.run(pypi_fetch, "npm", "lodash", "4.17.20", "4.17.21")
    assert result.weekly_downloads is None


@respx.mock
async def test_npm_metadata_downloads_network_error_returns_none():
    respx.get(f"{NPM_BASE}/lodash/4.17.21").mock(
        return_value=httpx.Response(200, json={"name": "lodash", "description": "Lodash"})
    )
    respx.get(f"{NPM_DOWNLOADS_BASE}/lodash").mock(side_effect=httpx.ConnectError("down"))

    env = ActivityEnvironment()
    result = await env.run(pypi_fetch, "npm", "lodash", "4.17.20", "4.17.21")
    assert result.weekly_downloads is None


@respx.mock
async def test_pypi_metadata_long_summary_truncated():
    long_summary = "x" * 600
    resp_data = _pypi_response("pkg", "1.0.0")
    resp_data["info"]["summary"] = long_summary
    respx.get(f"{PYPI_BASE}/pkg/1.0.0/json").mock(return_value=httpx.Response(200, json=resp_data))
    respx.get(f"{PYPISTATS_BASE}/pkg/recent").mock(
        return_value=httpx.Response(200, json={"data": {"last_week": 1000}})
    )

    env = ActivityEnvironment()
    result = await env.run(pypi_fetch, "pip", "pkg", "0.9.0", "1.0.0")
    assert result.package_description is not None
    assert len(result.package_description) == 500


# ---------------------------------------------------------------------------
# npm paths — release_age
# ---------------------------------------------------------------------------

@respx.mock
async def test_npm_release_age_success():
    from datetime import datetime, timezone, timedelta
    recent = (datetime.now(timezone.utc) - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    respx.get(f"{NPM_BASE}/lodash").mock(
        return_value=httpx.Response(200, json={"time": {"4.17.21": recent}})
    )

    env = ActivityEnvironment()
    result = await env.run(release_age_check, "npm", "lodash", "4.17.20", "4.17.21")
    assert result.release_age_hours is not None
    assert 5.0 < result.release_age_hours < 7.0


@respx.mock
async def test_npm_release_age_404_raises_non_retryable():
    from temporalio.exceptions import ApplicationError
    respx.get(f"{NPM_BASE}/missing").mock(return_value=httpx.Response(404))

    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(release_age_check, "npm", "missing", "1.0.0", "1.1.0")
    assert exc_info.value.non_retryable is True


@respx.mock
async def test_npm_release_age_missing_version_returns_none():
    respx.get(f"{NPM_BASE}/lodash").mock(
        return_value=httpx.Response(200, json={"time": {}})
    )

    env = ActivityEnvironment()
    result = await env.run(release_age_check, "npm", "lodash", "4.17.20", "4.17.21")
    assert result.release_age_hours is None


# ---------------------------------------------------------------------------
# npm paths — maintainer
# ---------------------------------------------------------------------------

def _npm_version_response(maintainers: list[dict]) -> dict:
    return {"name": "pkg", "maintainers": maintainers}


@respx.mock
async def test_npm_maintainer_no_change():
    maintainers = [{"name": "alice", "email": "alice@example.com"}]
    respx.get(f"{NPM_BASE}/pkg/1.0.0").mock(
        return_value=httpx.Response(200, json=_npm_version_response(maintainers))
    )
    respx.get(f"{NPM_BASE}/pkg/1.1.0").mock(
        return_value=httpx.Response(200, json=_npm_version_response(maintainers))
    )

    env = ActivityEnvironment()
    result = await env.run(maintainer_history, "npm", "pkg", "1.0.0", "1.1.0")
    assert result.maintainer_changed is False


@respx.mock
async def test_npm_maintainer_changed():
    old_maintainers = [{"name": "alice", "email": "alice@example.com"}]
    new_maintainers = [
        {"name": "alice", "email": "alice@example.com"},
        {"name": "bob", "email": "bob@example.com"},
    ]
    respx.get(f"{NPM_BASE}/pkg/1.0.0").mock(
        return_value=httpx.Response(200, json=_npm_version_response(old_maintainers))
    )
    respx.get(f"{NPM_BASE}/pkg/1.1.0").mock(
        return_value=httpx.Response(200, json=_npm_version_response(new_maintainers))
    )

    env = ActivityEnvironment()
    result = await env.run(maintainer_history, "npm", "pkg", "1.0.0", "1.1.0")
    assert result.maintainer_changed is True


@respx.mock
async def test_npm_maintainer_fetch_error_returns_no_change():
    respx.get(f"{NPM_BASE}/pkg/1.0.0").mock(side_effect=httpx.ConnectError("timeout"))
    respx.get(f"{NPM_BASE}/pkg/1.1.0").mock(
        return_value=httpx.Response(200, json=_npm_version_response([{"name": "alice"}]))
    )

    env = ActivityEnvironment()
    result = await env.run(maintainer_history, "npm", "pkg", "1.0.0", "1.1.0")
    assert result.maintainer_changed is False


# ---------------------------------------------------------------------------
# RubyGems paths — pypi_metadata
# ---------------------------------------------------------------------------

RUBYGEMS_API = "https://rubygems.org/api/v1/gems"
RUBYGEMS_DL_SEARCH = "https://rubygems.org/api/v1/downloads/search.json"


@respx.mock
async def test_rubygems_metadata_fetch_success():
    respx.get(f"{RUBYGEMS_API}/rails.json").mock(
        return_value=httpx.Response(200, json={
            "info": "Full-stack web framework.",
            "downloads": 500_000_000,
        })
    )
    respx.get(RUBYGEMS_DL_SEARCH).mock(
        return_value=httpx.Response(200, json={"rubygems": {
            "2024-01-01": 10_000, "2024-01-02": 12_000, "2024-01-03": 11_000,
            "2024-01-04": 13_000, "2024-01-05": 9_000, "2024-01-06": 8_000,
            "2024-01-07": 11_000,
        }})
    )

    env = ActivityEnvironment()
    result = await env.run(pypi_fetch, "rubygems", "rails", "7.0.0", "7.1.0")
    assert result.weekly_downloads == 74_000   # sum of 7 days, not total lifetime
    assert result.package_description == "Full-stack web framework."
    assert result.is_major_bump is False


@respx.mock
async def test_rubygems_metadata_weekly_downloads_fallback_on_error():
    """weekly_downloads is None when the search endpoint fails — metadata fetch still succeeds."""
    respx.get(f"{RUBYGEMS_API}/rails.json").mock(
        return_value=httpx.Response(200, json={"info": "Framework", "downloads": 100})
    )
    respx.get(RUBYGEMS_DL_SEARCH).mock(return_value=httpx.Response(500))

    env = ActivityEnvironment()
    result = await env.run(pypi_fetch, "rubygems", "rails", "7.0.0", "7.1.0")
    assert result.weekly_downloads is None
    assert result.is_major_bump is False


@respx.mock
async def test_rubygems_metadata_major_bump():
    respx.get(f"{RUBYGEMS_API}/rails.json").mock(
        return_value=httpx.Response(200, json={"info": "Framework", "downloads": 100})
    )
    respx.get(RUBYGEMS_DL_SEARCH).mock(return_value=httpx.Response(500))

    env = ActivityEnvironment()
    result = await env.run(pypi_fetch, "rubygems", "rails", "7.1.0", "8.0.0")
    assert result.is_major_bump is True


@respx.mock
async def test_rubygems_metadata_404_raises_non_retryable():
    from temporalio.exceptions import ApplicationError
    respx.get(f"{RUBYGEMS_API}/nosuchthing.json").mock(return_value=httpx.Response(404))
    respx.get(RUBYGEMS_DL_SEARCH).mock(return_value=httpx.Response(404))

    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(pypi_fetch, "rubygems", "nosuchthing", "0.9.0", "1.0.0")
    assert exc_info.value.non_retryable is True


@respx.mock
async def test_rubygems_metadata_empty_description():
    respx.get(f"{RUBYGEMS_API}/mygem.json").mock(
        return_value=httpx.Response(200, json={"info": "", "downloads": 0})
    )
    respx.get(RUBYGEMS_DL_SEARCH).mock(return_value=httpx.Response(500))

    env = ActivityEnvironment()
    result = await env.run(pypi_fetch, "rubygems", "mygem", "1.0.0", "1.0.1")
    assert result.package_description is None


# ---------------------------------------------------------------------------
# RubyGems paths — release_age
# ---------------------------------------------------------------------------

RUBYGEMS_VERSIONS_API = "https://rubygems.org/api/v1/versions"


@respx.mock
async def test_rubygems_release_age_success():
    import datetime
    recent = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=6)
    ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    respx.get(f"{RUBYGEMS_VERSIONS_API}/rails.json").mock(
        return_value=httpx.Response(200, json=[
            {"number": "7.1.0", "created_at": recent},
            {"number": "7.0.0", "created_at": "2023-01-01T00:00:00.000Z"},
        ])
    )

    env = ActivityEnvironment()
    result = await env.run(release_age_check, "rubygems", "rails", "7.0.0", "7.1.0")
    assert result.release_age_hours is not None
    assert 5.0 < result.release_age_hours < 7.0


@respx.mock
async def test_rubygems_release_age_404_raises_non_retryable():
    from temporalio.exceptions import ApplicationError
    respx.get(f"{RUBYGEMS_VERSIONS_API}/nosuchthing.json").mock(return_value=httpx.Response(404))

    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(release_age_check, "rubygems", "nosuchthing", "0.9.0", "1.0.0")
    assert exc_info.value.non_retryable is True


@respx.mock
async def test_rubygems_release_age_version_not_in_list_returns_none():
    respx.get(f"{RUBYGEMS_VERSIONS_API}/rails.json").mock(
        return_value=httpx.Response(200, json=[
            {"number": "7.0.0", "created_at": "2023-01-01T00:00:00.000Z"},
        ])
    )

    env = ActivityEnvironment()
    result = await env.run(release_age_check, "rubygems", "rails", "6.9.0", "7.1.0")
    assert result.release_age_hours is None


@respx.mock
async def test_rubygems_release_age_missing_created_at_returns_none():
    respx.get(f"{RUBYGEMS_VERSIONS_API}/rails.json").mock(
        return_value=httpx.Response(200, json=[
            {"number": "7.1.0"},  # no created_at
        ])
    )

    env = ActivityEnvironment()
    result = await env.run(release_age_check, "rubygems", "rails", "7.0.0", "7.1.0")
    assert result.release_age_hours is None


# ---------------------------------------------------------------------------
# RubyGems paths — maintainer
# ---------------------------------------------------------------------------


@respx.mock
async def test_rubygems_maintainer_no_change():
    respx.get(f"{RUBYGEMS_VERSIONS_API}/rails.json").mock(
        return_value=httpx.Response(200, json=[
            {"number": "7.0.0", "authors": "DHH, Eileen"},
            {"number": "7.1.0", "authors": "DHH, Eileen"},
        ])
    )

    env = ActivityEnvironment()
    result = await env.run(maintainer_history, "rubygems", "rails", "7.0.0", "7.1.0")
    assert result.maintainer_changed is False


@respx.mock
async def test_rubygems_maintainer_new_author_detected():
    respx.get(f"{RUBYGEMS_VERSIONS_API}/rails.json").mock(
        return_value=httpx.Response(200, json=[
            {"number": "7.0.0", "authors": "DHH"},
            {"number": "7.1.0", "authors": "DHH, NewContributor"},
        ])
    )

    env = ActivityEnvironment()
    result = await env.run(maintainer_history, "rubygems", "rails", "7.0.0", "7.1.0")
    assert result.maintainer_changed is True


@respx.mock
async def test_rubygems_maintainer_version_not_found_returns_no_change():
    respx.get(f"{RUBYGEMS_VERSIONS_API}/rails.json").mock(
        return_value=httpx.Response(200, json=[
            {"number": "7.0.0", "authors": "DHH"},
            # 7.1.0 missing from list
        ])
    )

    env = ActivityEnvironment()
    result = await env.run(maintainer_history, "rubygems", "rails", "7.0.0", "7.1.0")
    assert result.maintainer_changed is False


@respx.mock
async def test_rubygems_maintainer_http_error_returns_no_change():
    respx.get(f"{RUBYGEMS_VERSIONS_API}/rails.json").mock(
        return_value=httpx.Response(503)
    )

    env = ActivityEnvironment()
    result = await env.run(maintainer_history, "rubygems", "rails", "7.0.0", "7.1.0")
    assert result.maintainer_changed is False


@respx.mock
async def test_rubygems_maintainer_network_exception_returns_no_change():
    respx.get(f"{RUBYGEMS_VERSIONS_API}/rails.json").mock(
        side_effect=httpx.ConnectError("timeout")
    )

    env = ActivityEnvironment()
    result = await env.run(maintainer_history, "rubygems", "rails", "7.0.0", "7.1.0")
    assert result.maintainer_changed is False
