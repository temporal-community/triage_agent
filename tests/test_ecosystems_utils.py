"""
Tests for shared utility functions in activities/ecosystems/__init__.py.

Covers: parse_vcs_repo, fetch_vcs_release, fetch_vcs_tag_signature,
build_release_signals, fetch_vcs_account_age, detect_stale_version_line,
and registry helpers (get_provider, get_dependabot_slug_map, get_name_re).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import quote

import httpx
import pytest
import respx

from activities.ecosystems import (
    build_release_signals,
    detect_stale_version_line,
    fetch_vcs_account_age,
    fetch_vcs_release,
    fetch_vcs_tag_signature,
    parse_vcs_repo,
)
from activities.models import VersionLineSignals

# ---------------------------------------------------------------------------
# parse_vcs_repo
# ---------------------------------------------------------------------------


def test_parse_vcs_repo_github_https():
    result = parse_vcs_repo("https://github.com/owner/repo")
    assert result == ("github", "owner/repo")


def test_parse_vcs_repo_github_git_suffix():
    result = parse_vcs_repo("https://github.com/owner/repo.git")
    assert result == ("github", "owner/repo")


def test_parse_vcs_repo_github_shorthand():
    result = parse_vcs_repo("github:owner/repo")
    assert result == ("github", "owner/repo")


def test_parse_vcs_repo_gitlab_com():
    result = parse_vcs_repo("https://gitlab.com/owner/repo.git")
    assert result == ("gitlab", "owner/repo")


def test_parse_vcs_repo_custom_gitlab_base_url(monkeypatch):
    monkeypatch.setenv("GITLAB_BASE_URL", "https://gitlab.company.com")
    result = parse_vcs_repo("https://gitlab.company.com/myteam/myrepo.git")
    assert result == ("gitlab", "myteam/myrepo")


def test_parse_vcs_repo_returns_none_for_unknown_host(monkeypatch):
    monkeypatch.delenv("GITLAB_BASE_URL", raising=False)
    result = parse_vcs_repo("https://bitbucket.org/owner/repo")
    assert result is None


def test_parse_vcs_repo_empty_string():
    result = parse_vcs_repo("")
    assert result is None


# ---------------------------------------------------------------------------
# detect_stale_version_line — edge cases
# ---------------------------------------------------------------------------


def test_detect_stale_version_line_non_numeric_new_version():
    result = detect_stale_version_line(["1.0.0", "1.1.0"], "not-a-version")
    assert result == VersionLineSignals()


def test_detect_stale_version_line_no_stable_versions():
    result = detect_stale_version_line(["1.0.0-alpha", "1.0.0-rc1"], "1.0.0-beta")
    assert result == VersionLineSignals()


# ---------------------------------------------------------------------------
# get_provider — unknown ecosystem raises ValueError
# ---------------------------------------------------------------------------


def test_get_provider_raises_for_unknown_ecosystem():
    from activities.ecosystems import get_provider

    with pytest.raises(ValueError, match="Unknown ecosystem"):
        get_provider("unknown_ecosystem_xyz_abc")


# ---------------------------------------------------------------------------
# get_dependabot_slug_map / get_name_re — lazy init branches
# ---------------------------------------------------------------------------


def test_get_dependabot_slug_map_reinitializes_if_none(monkeypatch):
    import activities.ecosystems as eco

    monkeypatch.setattr(eco, "_PROVIDERS", None)
    result = eco.get_dependabot_slug_map()
    assert isinstance(result, dict)
    assert len(result) > 0


def test_get_name_re_reinitializes_if_none(monkeypatch):
    import activities.ecosystems as eco

    monkeypatch.setattr(eco, "_PROVIDERS", None)
    result = eco.get_name_re("pip")
    assert result is not None


def test_get_name_re_returns_none_for_unknown(monkeypatch):
    import activities.ecosystems as eco

    monkeypatch.setattr(eco, "_PROVIDERS", None)
    result = eco.get_name_re("unknown_eco")
    assert result is None


# ---------------------------------------------------------------------------
# fetch_vcs_release — GitLab path
# ---------------------------------------------------------------------------


@respx.mock
async def test_fetch_vcs_release_gitlab_success(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "glpat_test")
    encoded = quote("owner/repo", safe="")
    respx.get(f"https://gitlab.com/api/v4/projects/{encoded}/releases/v1.0.0").mock(
        return_value=httpx.Response(
            200,
            json={
                "released_at": "2024-01-15T12:00:00.000Z",
                "description": "Great release",
                "author": {"username": "alice"},
            },
        )
    )
    result = await fetch_vcs_release("gitlab", "owner", "repo", "1.0.0", None)
    assert result is not None
    assert result["created_at"] == "2024-01-15T12:00:00.000Z"
    assert result["body"] == "Great release"
    assert result["author"]["login"] == "alice"


@respx.mock
async def test_fetch_vcs_release_gitlab_no_release(monkeypatch):
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    encoded = quote("owner/repo", safe="")
    respx.get(f"https://gitlab.com/api/v4/projects/{encoded}/releases/v1.0.0").mock(
        return_value=httpx.Response(404)
    )
    respx.get(f"https://gitlab.com/api/v4/projects/{encoded}/releases/1.0.0").mock(
        return_value=httpx.Response(404)
    )
    result = await fetch_vcs_release("gitlab", "owner", "repo", "1.0.0", None)
    assert result is None


async def test_fetch_vcs_release_unknown_platform():
    result = await fetch_vcs_release("bitbucket", "owner", "repo", "1.0.0", None)
    assert result is None


# ---------------------------------------------------------------------------
# fetch_vcs_tag_signature — array response and edge cases
# ---------------------------------------------------------------------------


@respx.mock
async def test_tag_sig_array_no_exact_match():
    # Ref endpoint returns array where no entry matches the expected ref exactly
    respx.get(re.compile(r"https://api\.github\.com/repos/owner/repo/git/refs/.*")).mock(
        return_value=httpx.Response(
            200,
            json=[{"ref": "refs/tags/v1.0.0-rc1", "object": {"type": "commit"}}],
        )
    )
    result = await fetch_vcs_tag_signature("github", "owner", "repo", "1.0.0", None)
    assert result is None


@respx.mock
async def test_tag_sig_array_with_exact_match_annotated():
    sha = "abc123tagsha"
    respx.get("https://api.github.com/repos/owner/repo/git/refs/tags/v1.0.0").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"ref": "refs/tags/v1.0.0", "object": {"type": "tag", "sha": sha}},
                {"ref": "refs/tags/v1.0.0-rc1", "object": {"type": "commit"}},
            ],
        )
    )
    respx.get(f"https://api.github.com/repos/owner/repo/git/tags/{sha}").mock(
        return_value=httpx.Response(200, json={"verification": {"verified": True}})
    )
    result = await fetch_vcs_tag_signature("github", "owner", "repo", "1.0.0", None)
    assert result is True


@respx.mock
async def test_tag_sig_empty_sha_returns_none():
    respx.get(re.compile(r"https://api\.github\.com/repos/owner/repo/git/refs/.*")).mock(
        return_value=httpx.Response(
            200,
            json={"ref": "refs/tags/v1.0.0", "object": {"type": "tag", "sha": ""}},
        )
    )
    result = await fetch_vcs_tag_signature("github", "owner", "repo", "1.0.0", None)
    assert result is None


@respx.mock
async def test_tag_sig_tag_object_fetch_404_returns_none():
    sha = "annotated_tag_sha"
    respx.get("https://api.github.com/repos/owner/repo/git/refs/tags/v1.0.0").mock(
        return_value=httpx.Response(
            200,
            json={"ref": "refs/tags/v1.0.0", "object": {"type": "tag", "sha": sha}},
        )
    )
    respx.get(f"https://api.github.com/repos/owner/repo/git/tags/{sha}").mock(
        return_value=httpx.Response(404)
    )
    result = await fetch_vcs_tag_signature("github", "owner", "repo", "1.0.0", None)
    assert result is None


async def test_tag_sig_non_github_platform_returns_none():
    result = await fetch_vcs_tag_signature("gitlab", "owner", "repo", "1.0.0", None)
    assert result is None


@respx.mock
async def test_fetch_tag_signature_compat_alias():
    # backward-compat alias should delegate to fetch_vcs_tag_signature("github", ...)
    from activities.ecosystems import fetch_tag_signature

    respx.get(re.compile(r"https://api\.github\.com/.*")).mock(return_value=httpx.Response(404))
    result = await fetch_tag_signature("owner", "repo", "1.0.0", None)
    assert result is None


# ---------------------------------------------------------------------------
# build_release_signals — exception paths
# ---------------------------------------------------------------------------


def test_build_release_signals_invalid_skew_date_caught():
    release = {
        "created_at": "not-a-valid-datetime",
        "published_at": "also-invalid",
        "body": "",
        "author": {"login": "alice"},
    }
    registry_time = datetime.now(timezone.utc)
    result = build_release_signals(release, registry_time=registry_time)
    assert result.timestamp_skew_minutes is None
    assert result.github_release_exists is True


def test_build_release_signals_invalid_published_at_caught():
    release = {
        "created_at": "2024-01-15T12:00:00Z",
        "published_at": "not-a-valid-date",  # different from created_at
        "body": "",
        "author": {"login": "alice"},
    }
    result = build_release_signals(release)
    assert result.possible_rerelease is False
    assert result.github_release_exists is True


def test_build_release_signals_bot_author_is_automated():
    release = {
        "created_at": "2024-01-15T12:00:00Z",
        "published_at": "2024-01-15T12:00:00Z",
        "body": "",
        "author": {"login": "github-actions[bot]"},
    }
    result = build_release_signals(release)
    assert result.release_is_automated is True


# ---------------------------------------------------------------------------
# fetch_vcs_account_age — GitLab path
# ---------------------------------------------------------------------------


@respx.mock
async def test_fetch_vcs_account_age_gitlab_success(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "test-token")
    respx.get("https://gitlab.com/api/v4/users").mock(
        return_value=httpx.Response(
            200,
            json=[{"id": 1, "created_at": "2020-01-01T00:00:00Z"}],
        )
    )
    result = await fetch_vcs_account_age("gitlab", "myorg")
    assert result is not None
    assert result > 0


@respx.mock
async def test_fetch_vcs_account_age_gitlab_no_token(monkeypatch):
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    result = await fetch_vcs_account_age("gitlab", "myorg")
    assert result is None


@respx.mock
async def test_fetch_vcs_account_age_gitlab_empty_user_list(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "test-token")
    respx.get("https://gitlab.com/api/v4/users").mock(return_value=httpx.Response(200, json=[]))
    result = await fetch_vcs_account_age("gitlab", "nobody")
    assert result is None


async def test_fetch_vcs_account_age_unknown_platform():
    result = await fetch_vcs_account_age("bitbucket", "owner")
    assert result is None


async def test_fetch_github_account_age_compat_alias(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    from activities.ecosystems import fetch_github_account_age

    result = await fetch_github_account_age("owner")
    assert result is None
