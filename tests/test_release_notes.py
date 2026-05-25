"""Tests for activities/release_notes.py — GitHub release signal checks."""

from __future__ import annotations


import httpx
import pytest
import respx
from temporalio.testing import ActivityEnvironment

from ecosystems import parse_github_repo
from activities.release_notes import check as release_check
from models import (
    ReleaseSignals,
    PackageSignals,
    ReleaseAgeSignals,
)

PYPI_BASE = "https://pypi.org/pypi"
NPM_BASE = "https://registry.npmjs.org"
RUBYGEMS_GEM = "https://rubygems.org/api/v1/gems"
RUBYGEMS_VER = "https://rubygems.org/api/v1/versions"
GH_API = "https://api.github.com/repos"


# ---------------------------------------------------------------------------
# parse_github_repo — pure unit tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://github.com/psf/requests", "psf/requests"),
        ("https://github.com/psf/requests.git", "psf/requests"),
        ("git+https://github.com/lodash/lodash.git", "lodash/lodash"),
        ("git://github.com/owner/repo.git", "owner/repo"),
        ("git@github.com:owner/repo.git", "owner/repo"),
        ("https://github.com/owner/repo/issues", "owner/repo"),
        ("https://github.com/nicowillis/better.js", "nicowillis/better.js"),
        # npm shorthands
        ("github:owner/repo", "owner/repo"),
        ("github:owner/repo.git", "owner/repo"),
        # non-GitHub
        ("https://gitlab.com/owner/repo", None),
        ("bitbucket:owner/repo", None),
        ("gitlab:owner/repo", None),
        ("", None),
        ("https://example.com/not-github", None),
    ],
)
def test_parse_github_repo(url, expected):
    assert parse_github_repo(url) == expected


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pypi_json(package: str, version: str, source_url: str = "https://github.com/test/pkg") -> dict:
    return {
        "info": {
            "name": package,
            "version": version,
            "project_urls": {"Source Code": source_url},
            "home_page": source_url,
        },
        "urls": [
            {
                "upload_time_iso_8601": "2024-01-10T12:00:00+00:00",
                "filename": f"{package}-{version}.tar.gz",
            }
        ],
    }


def _gh_release(
    author: str = "github-actions[bot]",
    created_at: str = "2024-01-10T12:05:00Z",
    published_at: str = "2024-01-10T12:05:00Z",
    body: str = "Bug fixes and improvements.",
) -> dict:
    return {
        "tag_name": "v1.0.1",
        "author": {"login": author},
        "created_at": created_at,
        "published_at": published_at,
        "body": body,
    }


# ---------------------------------------------------------------------------
# PyPI — fetch_release
# ---------------------------------------------------------------------------


@respx.mock
async def test_pypi_release_success():
    respx.get(f"{PYPI_BASE}/requests/2.32.0/json").mock(
        return_value=httpx.Response(
            200, json=_pypi_json("requests", "2.32.0", "https://github.com/psf/requests")
        )
    )
    respx.get(f"{GH_API}/psf/requests/releases/tags/v2.32.0").mock(
        return_value=httpx.Response(200, json=_gh_release(body="Minor bug fixes."))
    )

    env = ActivityEnvironment()
    result = await env.run(release_check, "pip", "requests", "2.31.0", "2.32.0")
    assert result.github_release_exists is True
    assert result.release_author == "github-actions[bot]"
    assert result.release_is_automated is True
    assert result.release_body == "Minor bug fixes."


@respx.mock
async def test_pypi_release_human_author():
    respx.get(f"{PYPI_BASE}/pkg/1.1.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_json("pkg", "1.1.0"))
    )
    respx.get(f"{GH_API}/test/pkg/releases/tags/v1.1.0").mock(
        return_value=httpx.Response(200, json=_gh_release(author="maintainer-alice"))
    )

    env = ActivityEnvironment()
    result = await env.run(release_check, "pip", "pkg", "1.0.0", "1.1.0")
    assert result.github_release_exists is True
    assert result.release_author == "maintainer-alice"
    assert result.release_is_automated is False


@respx.mock
async def test_pypi_no_source_url():
    """Package with no GitHub URL in project_urls → github_release_exists=False."""
    respx.get(f"{PYPI_BASE}/mypkg/1.1.0/json").mock(
        return_value=httpx.Response(
            200,
            json={
                "info": {"name": "mypkg", "version": "1.1.0", "project_urls": {}, "home_page": ""},
                "urls": [],
            },
        )
    )

    env = ActivityEnvironment()
    result = await env.run(release_check, "pip", "mypkg", "1.0.0", "1.1.0")
    assert result.github_release_exists is False


@respx.mock
async def test_pypi_non_github_source_url():
    respx.get(f"{PYPI_BASE}/mypkg/1.1.0/json").mock(
        return_value=httpx.Response(
            200, json=_pypi_json("mypkg", "1.1.0", "https://gitlab.com/owner/repo")
        )
    )

    env = ActivityEnvironment()
    result = await env.run(release_check, "pip", "mypkg", "1.0.0", "1.1.0")
    assert result.github_release_exists is False


@respx.mock
async def test_pypi_release_not_found_on_github():
    respx.get(f"{PYPI_BASE}/pkg/1.1.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_json("pkg", "1.1.0"))
    )
    # Try both tag formats
    respx.get(f"{GH_API}/test/pkg/releases/tags/v1.1.0").mock(return_value=httpx.Response(404))
    respx.get(f"{GH_API}/test/pkg/releases/tags/1.1.0").mock(return_value=httpx.Response(404))

    env = ActivityEnvironment()
    result = await env.run(release_check, "pip", "pkg", "1.0.0", "1.1.0")
    assert result.github_release_exists is False


@respx.mock
async def test_pypi_metadata_repo_populated_with_release():
    respx.get(f"{PYPI_BASE}/requests/2.32.0/json").mock(
        return_value=httpx.Response(
            200, json=_pypi_json("requests", "2.32.0", "https://github.com/psf/requests")
        )
    )
    respx.get(f"{GH_API}/psf/requests/releases/tags/v2.32.0").mock(
        return_value=httpx.Response(200, json=_gh_release())
    )

    env = ActivityEnvironment()
    result = await env.run(release_check, "pip", "requests", "2.31.0", "2.32.0")
    assert result.metadata_repo == "psf/requests"


@respx.mock
async def test_pypi_metadata_repo_populated_without_release():
    """metadata_repo should be set even when no GitHub release exists."""
    respx.get(f"{PYPI_BASE}/pkg/1.1.0/json").mock(
        return_value=httpx.Response(
            200, json=_pypi_json("pkg", "1.1.0", "https://github.com/owner/pkg")
        )
    )
    respx.get(f"{GH_API}/owner/pkg/releases/tags/v1.1.0").mock(return_value=httpx.Response(404))
    respx.get(f"{GH_API}/owner/pkg/releases/tags/1.1.0").mock(return_value=httpx.Response(404))

    env = ActivityEnvironment()
    result = await env.run(release_check, "pip", "pkg", "1.0.0", "1.1.0")
    assert result.github_release_exists is False
    assert result.metadata_repo == "owner/pkg"


@respx.mock
async def test_pypi_metadata_repo_none_when_no_github_url():
    respx.get(f"{PYPI_BASE}/mypkg/1.1.0/json").mock(
        return_value=httpx.Response(
            200,
            json={
                "info": {"name": "mypkg", "version": "1.1.0", "project_urls": {}, "home_page": ""},
                "urls": [],
            },
        )
    )

    env = ActivityEnvironment()
    result = await env.run(release_check, "pip", "mypkg", "1.0.0", "1.1.0")
    assert result.metadata_repo is None


@respx.mock
async def test_pypi_registry_404():
    respx.get(f"{PYPI_BASE}/missing/1.1.0/json").mock(return_value=httpx.Response(404))

    env = ActivityEnvironment()
    result = await env.run(release_check, "pip", "missing", "1.0.0", "1.1.0")
    assert result.github_release_exists is False


# ---------------------------------------------------------------------------
# npm — fetch_release
# ---------------------------------------------------------------------------


@respx.mock
async def test_npm_release_success():
    respx.get(f"{NPM_BASE}/lodash/4.17.21").mock(
        return_value=httpx.Response(
            200,
            json={
                "repository": {"type": "git", "url": "git+https://github.com/lodash/lodash.git"},
            },
        )
    )
    respx.get(f"{NPM_BASE}/lodash").mock(
        return_value=httpx.Response(200, json={"time": {"4.17.21": "2024-01-10T12:00:00Z"}})
    )
    respx.get(f"{GH_API}/lodash/lodash/releases/tags/v4.17.21").mock(
        return_value=httpx.Response(200, json=_gh_release())
    )

    env = ActivityEnvironment()
    result = await env.run(release_check, "npm", "lodash", "4.17.20", "4.17.21")
    assert result.github_release_exists is True
    assert result.release_is_automated is True


@respx.mock
async def test_npm_release_no_repository_field():
    respx.get(f"{NPM_BASE}/mypkg/1.1.0").mock(
        return_value=httpx.Response(200, json={"name": "mypkg", "version": "1.1.0"})
    )
    respx.get(f"{NPM_BASE}/mypkg").mock(return_value=httpx.Response(200, json={"time": {}}))

    env = ActivityEnvironment()
    result = await env.run(release_check, "npm", "mypkg", "1.0.0", "1.1.0")
    assert result.github_release_exists is False


@respx.mock
async def test_npm_release_github_shorthand_string():
    """repository: "github:owner/repo" shorthand resolves to a GitHub release check."""
    respx.get(f"{NPM_BASE}/mypkg/1.1.0").mock(
        return_value=httpx.Response(200, json={"repository": "github:owner/mypkg"})
    )
    respx.get(f"{NPM_BASE}/mypkg").mock(
        return_value=httpx.Response(200, json={"time": {"1.1.0": "2024-01-10T12:00:00Z"}})
    )
    respx.get(f"{GH_API}/owner/mypkg/releases/tags/v1.1.0").mock(
        return_value=httpx.Response(200, json=_gh_release())
    )

    env = ActivityEnvironment()
    result = await env.run(release_check, "npm", "mypkg", "1.0.0", "1.1.0")
    assert result.github_release_exists is True


@respx.mock
async def test_npm_release_bare_owner_repo_shorthand():
    """repository: "owner/repo" bare shorthand is treated as GitHub by npm convention."""
    respx.get(f"{NPM_BASE}/mypkg/1.1.0").mock(
        return_value=httpx.Response(200, json={"repository": "owner/mypkg"})
    )
    respx.get(f"{NPM_BASE}/mypkg").mock(
        return_value=httpx.Response(200, json={"time": {"1.1.0": "2024-01-10T12:00:00Z"}})
    )
    respx.get(f"{GH_API}/owner/mypkg/releases/tags/v1.1.0").mock(
        return_value=httpx.Response(200, json=_gh_release())
    )

    env = ActivityEnvironment()
    result = await env.run(release_check, "npm", "mypkg", "1.0.0", "1.1.0")
    assert result.github_release_exists is True


# ---------------------------------------------------------------------------
# RubyGems — fetch_release
# ---------------------------------------------------------------------------


@respx.mock
async def test_rubygems_release_success():
    respx.get(f"{RUBYGEMS_GEM}/rails.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "source_code_uri": "https://github.com/rails/rails",
            },
        )
    )
    respx.get(f"{RUBYGEMS_VER}/rails.json").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"number": "7.1.0", "created_at": "2024-01-10T12:00:00.000Z"},
            ],
        )
    )
    respx.get(f"{GH_API}/rails/rails/releases/tags/v7.1.0").mock(
        return_value=httpx.Response(200, json=_gh_release())
    )

    env = ActivityEnvironment()
    result = await env.run(release_check, "rubygems", "rails", "7.0.0", "7.1.0")
    assert result.github_release_exists is True


# ---------------------------------------------------------------------------
# Timestamp alignment
# ---------------------------------------------------------------------------


@respx.mock
async def test_release_timestamp_skew_calculated():
    """Registry publish at T; GitHub release at T+3h → skew = 180 minutes."""
    respx.get(f"{PYPI_BASE}/pkg/1.1.0/json").mock(
        return_value=httpx.Response(
            200,
            json={
                "info": {
                    "project_urls": {"Source Code": "https://github.com/test/pkg"},
                    "home_page": "",
                },
                "urls": [{"upload_time_iso_8601": "2024-01-10T12:00:00+00:00"}],
            },
        )
    )
    respx.get(f"{GH_API}/test/pkg/releases/tags/v1.1.0").mock(
        return_value=httpx.Response(
            200,
            json=_gh_release(
                created_at="2024-01-10T15:00:00Z", published_at="2024-01-10T15:00:00Z"
            ),
        )
    )

    env = ActivityEnvironment()
    result = await env.run(release_check, "pip", "pkg", "1.0.0", "1.1.0")
    assert result.timestamp_skew_minutes is not None
    assert abs(result.timestamp_skew_minutes - 180.0) < 1.0


@respx.mock
async def test_release_possible_rerelease():
    """Release drafted 2 days before publishing → possible_rerelease=True."""
    respx.get(f"{PYPI_BASE}/pkg/1.1.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_json("pkg", "1.1.0"))
    )
    respx.get(f"{GH_API}/test/pkg/releases/tags/v1.1.0").mock(
        return_value=httpx.Response(
            200,
            json=_gh_release(
                created_at="2024-01-08T12:00:00Z",
                published_at="2024-01-10T12:00:00Z",
            ),
        )
    )

    env = ActivityEnvironment()
    result = await env.run(release_check, "pip", "pkg", "1.0.0", "1.1.0")
    assert result.possible_rerelease is True


@respx.mock
async def test_release_not_possible_rerelease_when_same_timestamps():
    respx.get(f"{PYPI_BASE}/pkg/1.1.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_json("pkg", "1.1.0"))
    )
    respx.get(f"{GH_API}/test/pkg/releases/tags/v1.1.0").mock(
        return_value=httpx.Response(
            200,
            json=_gh_release(
                created_at="2024-01-10T12:00:00Z",
                published_at="2024-01-10T12:00:00Z",
            ),
        )
    )

    env = ActivityEnvironment()
    result = await env.run(release_check, "pip", "pkg", "1.0.0", "1.1.0")
    assert result.possible_rerelease is False


# ---------------------------------------------------------------------------
# Release notes truncation
# ---------------------------------------------------------------------------


@respx.mock
async def test_release_body_truncated_at_3000_chars():
    long_body = "x" * 4000
    respx.get(f"{PYPI_BASE}/pkg/1.1.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_json("pkg", "1.1.0"))
    )
    respx.get(f"{GH_API}/test/pkg/releases/tags/v1.1.0").mock(
        return_value=httpx.Response(200, json=_gh_release(body=long_body))
    )

    env = ActivityEnvironment()
    result = await env.run(release_check, "pip", "pkg", "1.0.0", "1.1.0")
    assert result.release_body is not None
    assert len(result.release_body) < 4100  # 3000 chars + truncation marker
    assert "truncated" in result.release_body


# ---------------------------------------------------------------------------
# Tag signature helpers
# ---------------------------------------------------------------------------


def _git_ref(tag_name: str, sha: str = "tagsha0001", obj_type: str = "tag") -> dict:
    return {"ref": f"refs/tags/{tag_name}", "object": {"sha": sha, "type": obj_type}}


def _git_tag_verified(sha: str = "tagsha0001", verified: bool = True) -> dict:
    return {
        "sha": sha,
        "verification": {
            "verified": verified,
            "reason": "valid" if verified else "unsigned",
            "signature": "-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----"
            if verified
            else None,
            "payload": "object ...\ntype commit\n...",
        },
    }


# ---------------------------------------------------------------------------
# Tag signature — fetch_release integration
# ---------------------------------------------------------------------------


@respx.mock
async def test_release_tag_signature_verified():
    """New version has a GPG-signed annotated tag verified by GitHub."""
    respx.get(f"{PYPI_BASE}/pkg/1.1.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_json("pkg", "1.1.0"))
    )
    respx.get(f"{GH_API}/test/pkg/releases/tags/v1.1.0").mock(
        return_value=httpx.Response(200, json=_gh_release())
    )
    # New version: annotated tag → verified
    respx.get(f"{GH_API}/test/pkg/git/refs/tags/v1.1.0").mock(
        return_value=httpx.Response(200, json=_git_ref("v1.1.0"))
    )
    respx.get(f"{GH_API}/test/pkg/git/tags/tagsha0001").mock(
        return_value=httpx.Response(200, json=_git_tag_verified(verified=True))
    )
    # Old version: no tag
    respx.get(f"{GH_API}/test/pkg/git/refs/tags/v1.0.0").mock(return_value=httpx.Response(404))
    respx.get(f"{GH_API}/test/pkg/git/refs/tags/1.0.0").mock(return_value=httpx.Response(404))

    env = ActivityEnvironment()
    result = await env.run(release_check, "pip", "pkg", "1.0.0", "1.1.0")
    assert result.tag_signature_verified is True
    assert result.tag_was_previously_signed is False  # old had no tag, so no regression


@respx.mock
async def test_release_tag_signature_unverified():
    """Tag exists but GitHub cannot verify the signature."""
    respx.get(f"{PYPI_BASE}/pkg/1.1.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_json("pkg", "1.1.0"))
    )
    respx.get(f"{GH_API}/test/pkg/releases/tags/v1.1.0").mock(
        return_value=httpx.Response(200, json=_gh_release())
    )
    respx.get(f"{GH_API}/test/pkg/git/refs/tags/v1.1.0").mock(
        return_value=httpx.Response(200, json=_git_ref("v1.1.0"))
    )
    respx.get(f"{GH_API}/test/pkg/git/tags/tagsha0001").mock(
        return_value=httpx.Response(200, json=_git_tag_verified(verified=False))
    )
    respx.get(f"{GH_API}/test/pkg/git/refs/tags/v1.0.0").mock(return_value=httpx.Response(404))
    respx.get(f"{GH_API}/test/pkg/git/refs/tags/1.0.0").mock(return_value=httpx.Response(404))

    env = ActivityEnvironment()
    result = await env.run(release_check, "pip", "pkg", "1.0.0", "1.1.0")
    assert result.tag_signature_verified is False
    assert result.tag_was_previously_signed is False


@respx.mock
async def test_release_tag_signing_regression():
    """Old version had a verified signed tag; new version does not → tag_was_previously_signed."""
    respx.get(f"{PYPI_BASE}/pkg/1.1.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_json("pkg", "1.1.0"))
    )
    respx.get(f"{GH_API}/test/pkg/releases/tags/v1.1.0").mock(
        return_value=httpx.Response(200, json=_gh_release())
    )
    # New version: lightweight tag — no signature
    respx.get(f"{GH_API}/test/pkg/git/refs/tags/v1.1.0").mock(
        return_value=httpx.Response(200, json=_git_ref("v1.1.0", obj_type="commit"))
    )
    # Old version: annotated + verified tag
    respx.get(f"{GH_API}/test/pkg/git/refs/tags/v1.0.0").mock(
        return_value=httpx.Response(200, json=_git_ref("v1.0.0", sha="oldtagsha"))
    )
    respx.get(f"{GH_API}/test/pkg/git/tags/oldtagsha").mock(
        return_value=httpx.Response(200, json=_git_tag_verified(sha="oldtagsha", verified=True))
    )

    env = ActivityEnvironment()
    result = await env.run(release_check, "pip", "pkg", "1.0.0", "1.1.0")
    assert result.tag_signature_verified is None  # lightweight tag → no signature
    assert result.tag_was_previously_signed is True


@respx.mock
async def test_release_tag_no_regression_when_both_unsigned():
    """Neither version signed → no regression flag."""
    respx.get(f"{PYPI_BASE}/pkg/1.1.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_json("pkg", "1.1.0"))
    )
    respx.get(f"{GH_API}/test/pkg/releases/tags/v1.1.0").mock(
        return_value=httpx.Response(200, json=_gh_release())
    )
    respx.get(f"{GH_API}/test/pkg/git/refs/tags/v1.1.0").mock(return_value=httpx.Response(404))
    respx.get(f"{GH_API}/test/pkg/git/refs/tags/1.1.0").mock(return_value=httpx.Response(404))
    respx.get(f"{GH_API}/test/pkg/git/refs/tags/v1.0.0").mock(return_value=httpx.Response(404))
    respx.get(f"{GH_API}/test/pkg/git/refs/tags/1.0.0").mock(return_value=httpx.Response(404))

    env = ActivityEnvironment()
    result = await env.run(release_check, "pip", "pkg", "1.0.0", "1.1.0")
    assert result.tag_signature_verified is None
    assert result.tag_was_previously_signed is False


# ---------------------------------------------------------------------------
# Classifier integration
# ---------------------------------------------------------------------------


def test_rule_based_flags_possible_rerelease():
    from classifiers import _rule_based

    signals = PackageSignals(
        ecosystem="pip",
        package_name="pkg",
        old_version="1.0.0",
        new_version="1.0.1",
        age=ReleaseAgeSignals(release_age_hours=200.0),
        release=ReleaseSignals(possible_rerelease=True),
    )
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    assert any("re-release" in f for f in verdict.flags)


def test_rule_based_flags_large_timestamp_skew():
    from classifiers import _rule_based

    signals = PackageSignals(
        ecosystem="pip",
        package_name="pkg",
        old_version="1.0.0",
        new_version="1.0.1",
        age=ReleaseAgeSignals(release_age_hours=200.0),
        release=ReleaseSignals(timestamp_skew_minutes=300.0),
    )
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    assert any("300" in f for f in verdict.flags)


def test_rule_based_flags_tag_signing_regression():
    from classifiers import _rule_based

    signals = PackageSignals(
        ecosystem="pip",
        package_name="pkg",
        old_version="1.0.0",
        new_version="1.0.1",
        age=ReleaseAgeSignals(release_age_hours=200.0),
        release=ReleaseSignals(tag_was_previously_signed=True, tag_signature_verified=None),
    )
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    assert any("tag signing dropped" in f for f in verdict.flags)
