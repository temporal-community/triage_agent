"""Tests for activities/depsdev.py and activities/scorecard.py."""

from __future__ import annotations

import httpx
import pytest
import respx
from temporalio.testing import ActivityEnvironment

from activities.depsdev import fetch as depsdev_fetch
from activities.scorecard import fetch as scorecard_fetch
from models import (
    PackageSignals,
    PyPISignals,
    SocketSignals,
    OSVSignals,
    DiffSignals,
    ReleaseAgeSignals,
    MaintainerSignals,
    DepsDevSignals,
    ScorecardSignals,
)

DEPSDEV_BASE = "https://api.deps.dev/v3alpha/systems"
SCORECARD_BASE = "https://api.securityscorecards.dev/projects/github.com"


# ---------------------------------------------------------------------------
# depsdev.fetch
# ---------------------------------------------------------------------------


@respx.mock
async def test_depsdev_deprecated_true():
    """200 response with isDeprecated=True → DepsDevSignals(is_deprecated=True)."""
    respx.get(f"{DEPSDEV_BASE}/pypi/packages/requests/versions/2.32.0").mock(
        return_value=httpx.Response(
            200,
            json={
                "isDeprecated": True,
                "deprecatedReason": "Use httpx instead",
            },
        )
    )
    env = ActivityEnvironment()
    result = await env.run(depsdev_fetch, "pip", "requests", "2.31.0", "2.32.0")
    assert result.is_deprecated is True
    assert result.deprecated_reason == "Use httpx instead"


@respx.mock
async def test_depsdev_404_returns_empty():
    """Non-200 response → empty DepsDevSignals, no exception."""
    respx.get(f"{DEPSDEV_BASE}/pypi/packages/requests/versions/2.32.0").mock(
        return_value=httpx.Response(404)
    )
    env = ActivityEnvironment()
    result = await env.run(depsdev_fetch, "pip", "requests", "2.31.0", "2.32.0")
    assert result.is_deprecated is False
    assert result.deprecated_reason is None


@respx.mock
async def test_depsdev_200_no_deprecated_field():
    """200 response without isDeprecated field → DepsDevSignals(is_deprecated=False)."""
    respx.get(f"{DEPSDEV_BASE}/pypi/packages/requests/versions/2.32.0").mock(
        return_value=httpx.Response(200, json={"versionKey": {"version": "2.32.0"}})
    )
    env = ActivityEnvironment()
    result = await env.run(depsdev_fetch, "pip", "requests", "2.31.0", "2.32.0")
    assert result.is_deprecated is False
    assert result.deprecated_reason is None


async def test_depsdev_unknown_ecosystem_returns_empty():
    """Unknown ecosystem → empty DepsDevSignals without making any HTTP call."""
    env = ActivityEnvironment()
    result = await env.run(depsdev_fetch, "cargo", "serde", "1.0.0", "1.1.0")
    assert result.is_deprecated is False


# ---------------------------------------------------------------------------
# scorecard.fetch
# ---------------------------------------------------------------------------


@respx.mock
async def test_scorecard_successful_flow():
    """Full happy path: deps.dev returns relatedProject, Scorecard returns score and checks."""
    respx.get(f"{DEPSDEV_BASE}/pypi/packages/requests/versions/2.32.0").mock(
        return_value=httpx.Response(
            200,
            json={
                "relatedProjects": [
                    {
                        "projectKey": {"id": "github.com/psf/requests"},
                        "relationProvenance": "GO_ORIGIN",
                    }
                ]
            },
        )
    )
    respx.get(f"{SCORECARD_BASE}/psf/requests").mock(
        return_value=httpx.Response(
            200,
            json={
                "score": 8.5,
                "checks": [
                    {"name": "Maintained", "score": 10},
                    {"name": "Dangerous-Workflow", "score": 10},
                    {"name": "Token-Permissions", "score": 7},
                    {"name": "Branch-Protection", "score": 6},
                    {"name": "Signed-Releases", "score": -1},
                ],
            },
        )
    )
    env = ActivityEnvironment()
    result = await env.run(scorecard_fetch, "pip", "requests", "2.31.0", "2.32.0")
    assert result.scorecard_score == pytest.approx(8.5)
    assert result.scorecard_repo == "psf/requests"
    assert result.scorecard_maintained == 10
    assert result.scorecard_dangerous_workflow == 10
    assert result.scorecard_token_permissions == 7
    assert result.scorecard_branch_protection == 6
    assert result.scorecard_signed_releases is None  # -1 → None


@respx.mock
async def test_scorecard_no_related_projects_returns_empty():
    """deps.dev returns no relatedProjects → empty ScorecardSignals()."""
    respx.get(f"{DEPSDEV_BASE}/pypi/packages/requests/versions/2.32.0").mock(
        return_value=httpx.Response(200, json={"relatedProjects": [], "links": []})
    )
    env = ActivityEnvironment()
    result = await env.run(scorecard_fetch, "pip", "requests", "2.31.0", "2.32.0")
    assert result.scorecard_score is None
    assert result.scorecard_repo is None


@respx.mock
async def test_scorecard_scorecard_404_returns_repo_only():
    """Scorecard API returns 404 → ScorecardSignals(scorecard_repo=...) with no score."""
    respx.get(f"{DEPSDEV_BASE}/pypi/packages/requests/versions/2.32.0").mock(
        return_value=httpx.Response(
            200, json={"relatedProjects": [{"projectKey": {"id": "github.com/owner/repo"}}]}
        )
    )
    respx.get(f"{SCORECARD_BASE}/owner/repo").mock(return_value=httpx.Response(404))
    env = ActivityEnvironment()
    result = await env.run(scorecard_fetch, "pip", "requests", "2.31.0", "2.32.0")
    assert result.scorecard_repo == "owner/repo"
    assert result.scorecard_score is None
    assert result.scorecard_maintained is None


@respx.mock
async def test_scorecard_fallback_to_links():
    """No relatedProjects but links[] contains a github.com URL → uses it."""
    respx.get(f"{DEPSDEV_BASE}/npm/packages/lodash/versions/4.17.21").mock(
        return_value=httpx.Response(
            200,
            json={
                "relatedProjects": [],
                "links": [{"url": "https://github.com/lodash/lodash", "label": "SOURCE_REPO"}],
            },
        )
    )
    respx.get(f"{SCORECARD_BASE}/lodash/lodash").mock(
        return_value=httpx.Response(200, json={"score": 7.2, "checks": []})
    )
    env = ActivityEnvironment()
    result = await env.run(scorecard_fetch, "npm", "lodash", "4.17.20", "4.17.21")
    assert result.scorecard_repo == "lodash/lodash"
    assert result.scorecard_score == pytest.approx(7.2)


# ---------------------------------------------------------------------------
# Classifier rules — deprecated, unmaintained, dangerous-workflow
# ---------------------------------------------------------------------------


def _base_signals(**overrides):
    return PackageSignals(
        ecosystem=overrides.pop("ecosystem", "pip"),
        package_name=overrides.pop("package_name", "mypkg"),
        old_version=overrides.pop("old_version", "1.0.0"),
        new_version=overrides.pop("new_version", "1.1.0"),
        pypi=PyPISignals(
            weekly_downloads=overrides.pop("weekly_downloads", 100_000),
            is_major_bump=overrides.pop("is_major_bump", False),
        ),
        socket=SocketSignals(
            socket_score=overrides.pop("socket_score", 80),
            socket_alerts=overrides.pop("socket_alerts", []),
        ),
        osv=OSVSignals(osv_vulnerabilities=overrides.pop("osv_vulnerabilities", [])),
        diff=DiffSignals(
            diff_summary=overrides.pop("diff_summary", "Minor changes."),
            diff_size_bytes=overrides.pop("diff_size_bytes", 100),
        ),
        age=ReleaseAgeSignals(release_age_hours=overrides.pop("release_age_hours", 500.0)),
        maintainer=MaintainerSignals(maintainer_changed=overrides.pop("maintainer_changed", False)),
        deps_dev=DepsDevSignals(
            is_deprecated=overrides.pop("is_deprecated", False),
            deprecated_reason=overrides.pop("deprecated_reason", None),
        ),
        scorecard=ScorecardSignals(
            scorecard_maintained=overrides.pop("scorecard_maintained", None),
            scorecard_repo=overrides.pop("scorecard_repo", None),
            scorecard_dangerous_workflow=overrides.pop("scorecard_dangerous_workflow", None),
            scorecard_token_permissions=overrides.pop("scorecard_token_permissions", None),
        ),
    )


def test_classifier_deprecated_is_yellow():
    """is_deprecated=True → YELLOW flag containing 'deprecated'."""
    from classifiers import _rule_based

    signals = _base_signals(is_deprecated=True, deprecated_reason="Use newpkg instead")
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    assert any("deprecated" in f for f in verdict.flags)
    assert any("Use newpkg instead" in f for f in verdict.flags)


def test_classifier_scorecard_maintained_zero_is_yellow():
    """scorecard_maintained=0 → YELLOW flag containing 'unmaintained'."""
    from classifiers import _rule_based

    signals = _base_signals(scorecard_maintained=0, scorecard_repo="owner/repo")
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    assert any("unmaintained" in f for f in verdict.flags)
    assert any("owner/repo" in f for f in verdict.flags)


def test_classifier_scorecard_dangerous_workflow_zero_is_yellow():
    """scorecard_dangerous_workflow=0 → YELLOW flag containing 'dangerous'."""
    from classifiers import _rule_based

    signals = _base_signals(scorecard_dangerous_workflow=0)
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    assert any("dangerous" in f.lower() for f in verdict.flags)


def test_classifier_scorecard_token_permissions_low_is_yellow():
    """scorecard_token_permissions < 5 → YELLOW flag."""
    from classifiers import _rule_based

    signals = _base_signals(scorecard_token_permissions=3)
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    assert any("overprivileged" in f for f in verdict.flags)


def test_classifier_scorecard_token_permissions_at_boundary():
    """scorecard_token_permissions=5 → not flagged."""
    from classifiers import _rule_based

    signals = _base_signals(scorecard_token_permissions=5)
    verdict = _rule_based(signals)
    assert verdict.classification == "green"


def test_classifier_scorecard_maintained_nonzero_not_flagged():
    """scorecard_maintained=5 → not flagged as unmaintained."""
    from classifiers import _rule_based

    signals = _base_signals(scorecard_maintained=5)
    verdict = _rule_based(signals)
    assert verdict.classification == "green"


def test_classifier_deprecated_no_reason():
    """is_deprecated=True with no reason → still YELLOW, no colon/None in flag."""
    from classifiers import _rule_based

    signals = _base_signals(is_deprecated=True)
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    assert any("deprecated" in f for f in verdict.flags)
    # Should not have "None" in the flag text
    assert not any("None" in f for f in verdict.flags)
