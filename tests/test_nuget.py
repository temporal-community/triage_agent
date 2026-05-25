"""
Unit tests for the NuGet ecosystem provider.
HTTP calls mocked with respx; Temporal context via ActivityEnvironment.
"""

from __future__ import annotations

import io
import zipfile

import httpx
import pytest
import respx
from temporalio.exceptions import ApplicationError
from temporalio.testing import ActivityEnvironment

from ecosystems.nuget import NuGetProvider, _fetch_catalog_entry, _parse_owners

_REG = "https://api.nuget.org/v3/registration5"
_FLAT = "https://api.nuget.org/v3-flatcontainer"
_SEARCH = "https://azuresearch-usnc.nuget.org/query"

PACKAGE = "Newtonsoft.Json"
OLD_VER = "12.0.3"
NEW_VER = "13.0.1"
ID_LOWER = "newtonsoft.json"


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _reg_index(versions: list[dict] | None = None) -> dict:
    """Build a small inline registration index."""
    items = versions or [
        _catalog_entry(
            OLD_VER, owners="jamesNK", project_url="https://github.com/JamesNK/Newtonsoft.Json"
        ),
        _catalog_entry(
            NEW_VER, owners="jamesNK", project_url="https://github.com/JamesNK/Newtonsoft.Json"
        ),
    ]
    return {
        "@type": ["catalog:CatalogRoot", "PackageRegistration"],
        "count": len(items),
        "items": [
            {
                "@type": "catalog:CatalogPage",
                "count": len(items),
                "items": [{"catalogEntry": e} for e in items],
            }
        ],
    }


def _catalog_entry(
    version: str,
    owners: str = "jamesNK",
    project_url: str = "https://github.com/JamesNK/Newtonsoft.Json",
    published: str = "2023-06-01T12:00:00Z",
) -> dict:
    return {
        "@type": "PackageDetails",
        "id": PACKAGE,
        "version": version,
        "authors": "James Newton-King",
        "owners": owners,
        "description": "Popular high-performance JSON framework",
        "projectUrl": project_url,
        "published": published,
    }


def _search_response(description: str = "Popular high-performance JSON framework") -> dict:
    return {
        "totalHits": 1,
        "data": [
            {
                "id": PACKAGE,
                "version": NEW_VER,
                "description": description,
                "totalDownloads": 3_000_000_000,
                "owners": ["jamesNK"],
            }
        ],
    }


def _make_nupkg() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lib/net6.0/Newtonsoft.Json.dll", b"PE\x00\x00" * 100)
        zf.writestr(f"{ID_LOWER}.nuspec", "<package/>")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# fetch_metadata
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_fetch_metadata_returns_signals():
    respx.get(f"{_REG}/{ID_LOWER}/index.json").mock(
        return_value=httpx.Response(200, json=_reg_index())
    )
    respx.get(_SEARCH).mock(return_value=httpx.Response(200, json=_search_response()))

    env = ActivityEnvironment()
    result = await env.run(NuGetProvider().fetch_metadata, PACKAGE, OLD_VER, NEW_VER)

    assert result.package_description == "Popular high-performance JSON framework"
    assert result.is_major_bump is True  # 12 → 13
    assert result.weekly_downloads is None  # NuGet has no weekly stat


@pytest.mark.asyncio
@respx.mock
async def test_fetch_metadata_minor_bump_not_flagged():
    respx.get(f"{_REG}/{ID_LOWER}/index.json").mock(
        return_value=httpx.Response(200, json=_reg_index())
    )
    respx.get(_SEARCH).mock(return_value=httpx.Response(200, json=_search_response()))

    env = ActivityEnvironment()
    result = await env.run(NuGetProvider().fetch_metadata, PACKAGE, "13.0.0", "13.0.1")
    assert result.is_major_bump is False


@pytest.mark.asyncio
@respx.mock
async def test_fetch_metadata_404_raises():
    respx.get(f"{_REG}/{ID_LOWER}/index.json").mock(return_value=httpx.Response(404))
    respx.get(_SEARCH).mock(return_value=httpx.Response(200, json=_search_response()))

    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(NuGetProvider().fetch_metadata, PACKAGE, OLD_VER, NEW_VER)
    assert exc_info.value.type == "PackageNotFound"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_metadata_search_failure_still_works():
    respx.get(f"{_REG}/{ID_LOWER}/index.json").mock(
        return_value=httpx.Response(200, json=_reg_index())
    )
    respx.get(_SEARCH).mock(return_value=httpx.Response(500))

    env = ActivityEnvironment()
    result = await env.run(NuGetProvider().fetch_metadata, PACKAGE, OLD_VER, NEW_VER)
    assert result.package_description is None
    assert result.is_major_bump is True


# ---------------------------------------------------------------------------
# fetch_release_age
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_fetch_release_age_returns_hours():
    published = "2024-01-10T00:00:00Z"
    entry = _catalog_entry(NEW_VER, published=published)
    respx.get(f"{_REG}/{ID_LOWER}/index.json").mock(
        return_value=httpx.Response(
            200,
            json=_reg_index(
                [
                    _catalog_entry(OLD_VER),
                    entry,
                ]
            ),
        )
    )

    env = ActivityEnvironment()
    result = await env.run(NuGetProvider().fetch_release_age, PACKAGE, NEW_VER)
    assert result.release_age_hours is not None
    assert result.release_age_hours > 0


@pytest.mark.asyncio
@respx.mock
async def test_fetch_release_age_unlisted_version_returns_none():
    """NuGet uses 1900-01-01 as published date for unlisted versions."""
    entry = _catalog_entry(NEW_VER, published="1900-01-01T00:00:00Z")
    respx.get(f"{_REG}/{ID_LOWER}/index.json").mock(
        return_value=httpx.Response(200, json=_reg_index([entry]))
    )

    env = ActivityEnvironment()
    result = await env.run(NuGetProvider().fetch_release_age, PACKAGE, NEW_VER)
    assert result.release_age_hours is None


@pytest.mark.asyncio
@respx.mock
async def test_fetch_release_age_version_not_found_returns_none():
    respx.get(f"{_REG}/{ID_LOWER}/index.json").mock(
        return_value=httpx.Response(200, json=_reg_index([_catalog_entry(OLD_VER)]))
    )

    env = ActivityEnvironment()
    result = await env.run(NuGetProvider().fetch_release_age, PACKAGE, "99.0.0")
    assert result.release_age_hours is None


# ---------------------------------------------------------------------------
# fetch_maintainer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_fetch_maintainer_no_change():
    respx.get(f"{_REG}/{ID_LOWER}/index.json").mock(
        return_value=httpx.Response(200, json=_reg_index())
    )

    env = ActivityEnvironment()
    result = await env.run(NuGetProvider().fetch_maintainer, PACKAGE, OLD_VER, NEW_VER)
    assert result.maintainer_changed is False


@pytest.mark.asyncio
@respx.mock
async def test_fetch_maintainer_new_owner_detected():
    index = _reg_index(
        [
            _catalog_entry(OLD_VER, owners="alice"),
            _catalog_entry(NEW_VER, owners="alice, bob"),  # bob is new
        ]
    )
    respx.get(f"{_REG}/{ID_LOWER}/index.json").mock(return_value=httpx.Response(200, json=index))

    env = ActivityEnvironment()
    result = await env.run(NuGetProvider().fetch_maintainer, PACKAGE, OLD_VER, NEW_VER)
    assert result.maintainer_changed is True


@pytest.mark.asyncio
@respx.mock
async def test_fetch_maintainer_list_owners():
    """owners can be a JSON list instead of a comma-separated string."""
    index = {
        "@type": ["catalog:CatalogRoot", "PackageRegistration"],
        "count": 2,
        "items": [
            {
                "@type": "catalog:CatalogPage",
                "count": 2,
                "items": [
                    {"catalogEntry": {**_catalog_entry(OLD_VER), "owners": ["alice"]}},
                    {"catalogEntry": {**_catalog_entry(NEW_VER), "owners": ["alice", "mallory"]}},
                ],
            }
        ],
    }
    respx.get(f"{_REG}/{ID_LOWER}/index.json").mock(return_value=httpx.Response(200, json=index))

    env = ActivityEnvironment()
    result = await env.run(NuGetProvider().fetch_maintainer, PACKAGE, OLD_VER, NEW_VER)
    assert result.maintainer_changed is True


@pytest.mark.asyncio
@respx.mock
async def test_fetch_maintainer_version_not_found_returns_no_change():
    respx.get(f"{_REG}/{ID_LOWER}/index.json").mock(
        return_value=httpx.Response(200, json=_reg_index([_catalog_entry(OLD_VER)]))
    )

    env = ActivityEnvironment()
    result = await env.run(NuGetProvider().fetch_maintainer, PACKAGE, OLD_VER, "99.0.0")
    assert result.maintainer_changed is False


# ---------------------------------------------------------------------------
# get_archive_url
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_get_archive_url_constructs_correct_url():
    async with __import__("httpx").AsyncClient() as client:
        result = await NuGetProvider().get_archive_url(client, PACKAGE, NEW_VER)

    assert result is not None
    url, filename, sha = result
    assert url == f"{_FLAT}/{ID_LOWER}/{NEW_VER.lower()}/{ID_LOWER}.{NEW_VER.lower()}.nupkg"
    assert filename == f"{PACKAGE}.{NEW_VER}.nupkg"
    assert sha == ""


def test_get_archive_url_lowercases_id():
    """NuGet flatcontainer paths must use the lowercase package ID."""
    import asyncio

    async def run():
        async with __import__("httpx").AsyncClient() as client:
            result = await NuGetProvider().get_archive_url(
                client, "Microsoft.Extensions.Logging", "8.0.0"
            )
        return result

    result = asyncio.run(run())
    assert result is not None
    url = result[0]
    assert "microsoft.extensions.logging" in url
    assert "Microsoft.Extensions.Logging" not in url


# ---------------------------------------------------------------------------
# extract_archive
# ---------------------------------------------------------------------------


def test_extract_archive_extracts_nupkg(tmp_path):
    nupkg = _make_nupkg()
    NuGetProvider().extract_archive(nupkg, f"{PACKAGE}.{NEW_VER}.nupkg", str(tmp_path))
    assert (tmp_path / f"{ID_LOWER}.nuspec").exists()


def test_extract_archive_rejects_path_traversal(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
    with pytest.raises(ApplicationError):
        NuGetProvider().extract_archive(buf.getvalue(), "evil.nupkg", str(tmp_path))


# ---------------------------------------------------------------------------
# fetch_attestations
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_attestations_returns_false():
    env = ActivityEnvironment()
    result = await env.run(NuGetProvider().fetch_attestations, PACKAGE, OLD_VER, NEW_VER)
    assert result.has_attestation is False


# ---------------------------------------------------------------------------
# fetch_release
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_fetch_release_returns_signals_when_github_release_exists(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    respx.get(f"{_REG}/{ID_LOWER}/index.json").mock(
        return_value=httpx.Response(200, json=_reg_index())
    )
    respx.get("https://api.github.com/repos/JamesNK/Newtonsoft.Json/releases/tags/v13.0.1").mock(
        return_value=httpx.Response(
            200,
            json={
                "tag_name": "v13.0.1",
                "author": {"login": "github-actions[bot]"},
                "created_at": "2023-06-01T12:05:00Z",
                "published_at": "2023-06-01T12:05:00Z",
                "body": "Bug fix release",
            },
        )
    )
    respx.get("https://api.github.com/repos/JamesNK/Newtonsoft.Json/git/refs/tags/v13.0.1").mock(
        return_value=httpx.Response(404)
    )
    respx.get("https://api.github.com/repos/JamesNK/Newtonsoft.Json/git/refs/tags/v12.0.3").mock(
        return_value=httpx.Response(404)
    )

    env = ActivityEnvironment()
    result = await env.run(NuGetProvider().fetch_release, PACKAGE, OLD_VER, NEW_VER)
    assert result.github_release_exists is True
    assert result.release_is_automated is True
    assert result.release_body == "Bug fix release"
    assert result.metadata_repo == "JamesNK/Newtonsoft.Json"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_release_no_github_url_returns_empty():
    index = _reg_index(
        [
            _catalog_entry(OLD_VER, project_url=""),
            _catalog_entry(NEW_VER, project_url=""),
        ]
    )
    respx.get(f"{_REG}/{ID_LOWER}/index.json").mock(return_value=httpx.Response(200, json=index))

    env = ActivityEnvironment()
    result = await env.run(NuGetProvider().fetch_release, PACKAGE, OLD_VER, NEW_VER)
    assert result.github_release_exists is False
    assert result.metadata_repo is None


# ---------------------------------------------------------------------------
# _fetch_catalog_entry — pagination
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_fetch_catalog_entry_handles_paginated_index():
    """When page items are null, the provider fetches the page URL."""
    page_url = f"{_REG}/{ID_LOWER}/page/1.0.0/13.0.1.json"
    index = {
        "@type": ["catalog:CatalogRoot", "PackageRegistration"],
        "count": 1,
        "items": [
            {
                "@type": "catalog:CatalogPage",
                "@id": page_url,
                "count": 2,
                # items absent — must be fetched from @id
            }
        ],
    }
    page_body = {
        "items": [
            {"catalogEntry": _catalog_entry(OLD_VER)},
            {"catalogEntry": _catalog_entry(NEW_VER)},
        ]
    }
    respx.get(f"{_REG}/{ID_LOWER}/index.json").mock(return_value=httpx.Response(200, json=index))
    respx.get(page_url).mock(return_value=httpx.Response(200, json=page_body))

    entry = await _fetch_catalog_entry(PACKAGE, NEW_VER)
    assert entry is not None
    assert entry["version"] == NEW_VER


@pytest.mark.asyncio
@respx.mock
async def test_fetch_catalog_entry_returns_none_for_missing_version():
    respx.get(f"{_REG}/{ID_LOWER}/index.json").mock(
        return_value=httpx.Response(200, json=_reg_index([_catalog_entry(OLD_VER)]))
    )
    entry = await _fetch_catalog_entry(PACKAGE, "99.0.0")
    assert entry is None


@pytest.mark.asyncio
@respx.mock
async def test_fetch_catalog_entry_returns_none_on_404():
    respx.get(f"{_REG}/{ID_LOWER}/index.json").mock(return_value=httpx.Response(404))
    entry = await _fetch_catalog_entry(PACKAGE, NEW_VER)
    assert entry is None


@pytest.mark.asyncio
@respx.mock
async def test_fetch_catalog_entry_case_insensitive_version_match():
    """Version comparison should be case-insensitive."""
    respx.get(f"{_REG}/{ID_LOWER}/index.json").mock(
        return_value=httpx.Response(200, json=_reg_index())
    )
    entry = await _fetch_catalog_entry(PACKAGE, NEW_VER.upper())
    assert entry is not None


# ---------------------------------------------------------------------------
# _parse_owners
# ---------------------------------------------------------------------------


def test_parse_owners_from_string():
    assert _parse_owners("alice, Bob, CHARLIE") == {"alice", "bob", "charlie"}


def test_parse_owners_from_list():
    assert _parse_owners(["Alice", "bob"]) == {"alice", "bob"}


def test_parse_owners_empty_string():
    assert _parse_owners("") == set()


def test_parse_owners_empty_list():
    assert _parse_owners([]) == set()


# ---------------------------------------------------------------------------
# version_lineage integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_nuget_stale_version_line_detected():
    from activities.version_lineage import check

    respx.get(f"{_FLAT}/{ID_LOWER}/index.json").mock(
        return_value=httpx.Response(
            200, json={"versions": ["12.0.1", "12.0.2", "12.0.3", "13.0.1"]}
        )
    )

    env = ActivityEnvironment()
    result = await env.run(check, "nuget", PACKAGE, OLD_VER, "12.0.4")
    assert result.stale_version_line is True
    assert result.latest_major == 13
    assert result.bump_major == 12


@pytest.mark.asyncio
@respx.mock
async def test_nuget_not_stale_when_patching_latest():
    from activities.version_lineage import check

    respx.get(f"{_FLAT}/{ID_LOWER}/index.json").mock(
        return_value=httpx.Response(200, json={"versions": ["12.0.3", "13.0.1"]})
    )

    env = ActivityEnvironment()
    result = await env.run(check, "nuget", PACKAGE, OLD_VER, NEW_VER)
    assert result.stale_version_line is False


@pytest.mark.asyncio
@respx.mock
async def test_nuget_version_lineage_404_raises():
    from activities.version_lineage import check

    respx.get(f"{_FLAT}/{ID_LOWER}/index.json").mock(return_value=httpx.Response(404))

    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(check, "nuget", PACKAGE, OLD_VER, NEW_VER)
    assert exc_info.value.type == "PackageNotFound"


# ---------------------------------------------------------------------------
# Webhook name validation
# ---------------------------------------------------------------------------


def test_nuget_name_accepted_by_webhook_validator():
    from ecosystems.nuget import NuGetProvider

    name_re = NuGetProvider.name_re
    assert name_re.match("Newtonsoft.Json")
    assert name_re.match("Microsoft.Extensions.Logging")
    assert name_re.match("MyPackage123")
    assert not name_re.match("../evil")
    assert not name_re.match("bad/slash")
