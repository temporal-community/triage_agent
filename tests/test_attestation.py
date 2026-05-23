"""Tests for attestation signals: PyPI PEP 740, npm SLSA provenance, RubyGems stub."""
from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx
from temporalio.testing import ActivityEnvironment

from activities.attestation import check as attestation_check
from activities.models import AttestationSignals

PYPI_BASE = "https://pypi.org/pypi"
PYPI_INTEGRITY = "https://pypi.org/integrity"
NPM_ATT_BASE = "https://registry.npmjs.org/-/npm/v1/attestations"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pypi_urls(package: str, version: str, filename: str | None = None) -> dict:
    fname = filename or f"{package}-{version}.tar.gz"
    return {
        "info": {"name": package, "version": version},
        "urls": [{"packagetype": "sdist", "filename": fname, "url": "https://files.pythonhosted.org/x", "digests": {}}],
    }


def _pypi_provenance(kind: str = "GitHub", repo: str = "psf/requests", with_dsse: bool = False) -> dict:
    attestations: list = []
    if with_dsse:
        payload = base64.b64encode(json.dumps({
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {"digest": {"gitCommit": "abc123def456abc123def456abc123def456abc1"}}
                    ]
                },
                "runDetails": {
                    "metadata": {
                        "invocationID": "https://github.com/psf/requests/actions/runs/99887766"
                    }
                },
            },
        }).encode()).decode()
        attestations = [{
            "bundle": {
                "dsseEnvelope": {
                    "payload": payload,
                    "payloadType": "application/vnd.in-toto+json",
                    "signatures": [],
                }
            }
        }]
    return {
        "metadata": {"kind": "publish-attestation", "version": "1"},
        "attestation_bundles": [
            {
                "publisher": {
                    "kind": kind,
                    "claims": {"repository": repo, "ref": "refs/tags/2.32.0", "workflow": ".github/workflows/publish.yml"},
                },
                "attestations": attestations,
            }
        ],
    }


def _npm_attestation_bundle(
    repo_url: str = "https://github.com/owner/pkg",
    commit_sha: str | None = None,
    invocation_id: str | None = None,
) -> dict:
    resolved = [{"digest": {"gitCommit": commit_sha}}] if commit_sha else []
    run_details: dict = {}
    if invocation_id:
        run_details = {"metadata": {"invocationID": invocation_id}}
    payload = base64.b64encode(json.dumps({
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "externalParameters": {
                    "workflow": {
                        "repository": repo_url,
                        "ref": "refs/tags/v1.1.0",
                        "path": ".github/workflows/publish.yml",
                    }
                },
                "resolvedDependencies": resolved,
            },
            "runDetails": run_details,
        },
    }).encode()).decode()
    return {
        "attestations": [
            {
                "predicateType": "https://slsa.dev/provenance/v1",
                "bundle": {
                    "dsseEnvelope": {
                        "payload": payload,
                        "payloadType": "application/vnd.in-toto+json",
                        "signatures": [],
                    }
                },
            }
        ]
    }


# ---------------------------------------------------------------------------
# PyPI — fetch_attestations
# ---------------------------------------------------------------------------

@respx.mock
async def test_pypi_attestation_success():
    respx.get(f"{PYPI_BASE}/requests/2.31.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("requests", "2.31.0"))
    )
    respx.get(f"{PYPI_BASE}/requests/2.32.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("requests", "2.32.0"))
    )
    respx.get(f"{PYPI_INTEGRITY}/requests/2.31.0/requests-2.31.0.tar.gz/provenance").mock(
        return_value=httpx.Response(200, json=_pypi_provenance(repo="psf/requests"))
    )
    respx.get(f"{PYPI_INTEGRITY}/requests/2.32.0/requests-2.32.0.tar.gz/provenance").mock(
        return_value=httpx.Response(200, json=_pypi_provenance(repo="psf/requests"))
    )

    env = ActivityEnvironment()
    result = await env.run(attestation_check, "pip", "requests", "2.31.0", "2.32.0")
    assert result.has_attestation is True
    assert result.publisher_kind == "GitHub"
    assert result.publisher_repo == "psf/requests"
    assert result.publisher_changed is False
    assert result.old_publisher_repo is None


@respx.mock
async def test_pypi_attestation_no_provenance_endpoint():
    respx.get(f"{PYPI_BASE}/requests/2.31.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("requests", "2.31.0"))
    )
    respx.get(f"{PYPI_BASE}/requests/2.32.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("requests", "2.32.0"))
    )
    respx.get(f"{PYPI_INTEGRITY}/requests/2.31.0/requests-2.31.0.tar.gz/provenance").mock(
        return_value=httpx.Response(404)
    )
    respx.get(f"{PYPI_INTEGRITY}/requests/2.32.0/requests-2.32.0.tar.gz/provenance").mock(
        return_value=httpx.Response(404)
    )

    env = ActivityEnvironment()
    result = await env.run(attestation_check, "pip", "requests", "2.31.0", "2.32.0")
    assert result.has_attestation is False
    assert result.publisher_kind is None


@respx.mock
async def test_pypi_attestation_publisher_changed():
    respx.get(f"{PYPI_BASE}/pkg/1.0.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("pkg", "1.0.0"))
    )
    respx.get(f"{PYPI_BASE}/pkg/1.1.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("pkg", "1.1.0"))
    )
    respx.get(f"{PYPI_INTEGRITY}/pkg/1.0.0/pkg-1.0.0.tar.gz/provenance").mock(
        return_value=httpx.Response(200, json=_pypi_provenance(repo="original/repo"))
    )
    respx.get(f"{PYPI_INTEGRITY}/pkg/1.1.0/pkg-1.1.0.tar.gz/provenance").mock(
        return_value=httpx.Response(200, json=_pypi_provenance(repo="attacker/fork"))
    )

    env = ActivityEnvironment()
    result = await env.run(attestation_check, "pip", "pkg", "1.0.0", "1.1.0")
    assert result.has_attestation is True
    assert result.publisher_repo == "attacker/fork"
    assert result.publisher_changed is True
    assert result.old_publisher_repo == "original/repo"


@respx.mock
async def test_pypi_attestation_old_version_not_attested():
    """New version attested, old version was not — publisher_changed should be False."""
    respx.get(f"{PYPI_BASE}/pkg/1.0.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("pkg", "1.0.0"))
    )
    respx.get(f"{PYPI_BASE}/pkg/1.1.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("pkg", "1.1.0"))
    )
    respx.get(f"{PYPI_INTEGRITY}/pkg/1.0.0/pkg-1.0.0.tar.gz/provenance").mock(
        return_value=httpx.Response(404)
    )
    respx.get(f"{PYPI_INTEGRITY}/pkg/1.1.0/pkg-1.1.0.tar.gz/provenance").mock(
        return_value=httpx.Response(200, json=_pypi_provenance(repo="org/pkg"))
    )

    env = ActivityEnvironment()
    result = await env.run(attestation_check, "pip", "pkg", "1.0.0", "1.1.0")
    assert result.has_attestation is True
    assert result.publisher_changed is False  # old had none, so not "changed"


@respx.mock
async def test_pypi_attestation_package_json_404():
    respx.get(f"{PYPI_BASE}/missing/1.0.0/json").mock(return_value=httpx.Response(404))
    respx.get(f"{PYPI_BASE}/missing/1.1.0/json").mock(return_value=httpx.Response(404))

    env = ActivityEnvironment()
    result = await env.run(attestation_check, "pip", "missing", "1.0.0", "1.1.0")
    assert result.has_attestation is False


# ---------------------------------------------------------------------------
# npm — fetch_attestations
# ---------------------------------------------------------------------------

@respx.mock
async def test_npm_attestation_success():
    respx.get(f"{NPM_ATT_BASE}/lodash@4.17.20").mock(
        return_value=httpx.Response(200, json=_npm_attestation_bundle("https://github.com/lodash/lodash"))
    )
    respx.get(f"{NPM_ATT_BASE}/lodash@4.17.21").mock(
        return_value=httpx.Response(200, json=_npm_attestation_bundle("https://github.com/lodash/lodash"))
    )

    env = ActivityEnvironment()
    result = await env.run(attestation_check, "npm", "lodash", "4.17.20", "4.17.21")
    assert result.has_attestation is True
    assert result.publisher_kind == "GitHub"
    assert result.publisher_repo == "lodash/lodash"
    assert result.publisher_changed is False


@respx.mock
async def test_npm_attestation_no_provenance():
    respx.get(f"{NPM_ATT_BASE}/mypkg@1.0.0").mock(return_value=httpx.Response(404))
    respx.get(f"{NPM_ATT_BASE}/mypkg@1.1.0").mock(return_value=httpx.Response(404))

    env = ActivityEnvironment()
    result = await env.run(attestation_check, "npm", "mypkg", "1.0.0", "1.1.0")
    assert result.has_attestation is False


@respx.mock
async def test_npm_attestation_publisher_changed():
    respx.get(f"{NPM_ATT_BASE}/mypkg@1.0.0").mock(
        return_value=httpx.Response(200, json=_npm_attestation_bundle("https://github.com/original/mypkg"))
    )
    respx.get(f"{NPM_ATT_BASE}/mypkg@1.1.0").mock(
        return_value=httpx.Response(200, json=_npm_attestation_bundle("https://github.com/attacker/mypkg"))
    )

    env = ActivityEnvironment()
    result = await env.run(attestation_check, "npm", "mypkg", "1.0.0", "1.1.0")
    assert result.has_attestation is True
    assert result.publisher_changed is True
    assert result.publisher_repo == "attacker/mypkg"
    assert result.old_publisher_repo == "original/mypkg"


@respx.mock
async def test_npm_attestation_no_provenance_predicate_in_bundle():
    """Endpoint returns 200 but bundle has no provenance predicate."""
    respx.get(f"{NPM_ATT_BASE}/mypkg@1.0.0").mock(
        return_value=httpx.Response(200, json={"attestations": [
            {"predicateType": "https://in-toto.io/Link/v1", "bundle": {}}
        ]})
    )
    respx.get(f"{NPM_ATT_BASE}/mypkg@1.1.0").mock(return_value=httpx.Response(404))

    env = ActivityEnvironment()
    result = await env.run(attestation_check, "npm", "mypkg", "1.0.0", "1.1.0")
    assert result.has_attestation is False  # new version has no attestation


# ---------------------------------------------------------------------------
# RubyGems — fetch_attestations (stub)
# ---------------------------------------------------------------------------

async def test_rubygems_attestation_returns_empty():
    env = ActivityEnvironment()
    result = await env.run(attestation_check, "rubygems", "rails", "7.0.0", "7.1.0")
    assert result.has_attestation is False
    assert result.publisher_kind is None
    assert result.publisher_repo is None
    assert result.publisher_changed is False


# ---------------------------------------------------------------------------
# Classifier: rule-based publisher_changed flag
# ---------------------------------------------------------------------------

def test_rule_based_classifier_flags_publisher_changed():
    from activities.classifier import _rule_based
    from activities.models import PackageSignals

    signals = PackageSignals(
        ecosystem="pip",
        package_name="pkg",
        old_version="1.0.0",
        new_version="1.1.0",
        release_age_hours=500.0,
        is_major_bump=False,
        socket_score=None,
        socket_alerts=[],
        osv_vulnerabilities=[],
        diff_summary="[no significant changes detected]",
        diff_size_bytes=0,
        maintainer_changed=False,
        weekly_downloads=100_000,
        publisher_account_age_days=None,
        publisher_changed=True,
        old_publisher_repo="trusted/repo",
        publisher_repo="new/repo",
        has_attestation=True,
    )
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    assert any("trusted publisher changed" in f for f in verdict.flags)
    assert "trusted/repo" in " ".join(verdict.flags)


# ---------------------------------------------------------------------------
# Publisher account age — fetch_github_account_age + classifier integration
# ---------------------------------------------------------------------------

@respx.mock
async def test_pypi_attestation_populates_publisher_account_age(monkeypatch):
    """publisher_account_age_days is populated via GitHub users API when GITHUB_TOKEN is set."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    respx.get(f"{PYPI_BASE}/requests/2.31.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("requests", "2.31.0"))
    )
    respx.get(f"{PYPI_BASE}/requests/2.32.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("requests", "2.32.0"))
    )
    respx.get(f"{PYPI_INTEGRITY}/requests/2.31.0/requests-2.31.0.tar.gz/provenance").mock(
        return_value=httpx.Response(200, json=_pypi_provenance(repo="psf/requests"))
    )
    respx.get(f"{PYPI_INTEGRITY}/requests/2.32.0/requests-2.32.0.tar.gz/provenance").mock(
        return_value=httpx.Response(200, json=_pypi_provenance(repo="psf/requests"))
    )
    respx.get("https://api.github.com/users/psf").mock(
        return_value=httpx.Response(200, json={"login": "psf", "created_at": "2010-03-15T00:00:00Z"})
    )

    env = ActivityEnvironment()
    result = await env.run(attestation_check, "pip", "requests", "2.31.0", "2.32.0")
    assert result.has_attestation is True
    assert result.publisher_account_age_days is not None
    assert result.publisher_account_age_days > 3000  # psf org is well over 8 years old


@respx.mock
async def test_publisher_account_age_none_without_token(monkeypatch):
    """publisher_account_age_days stays None when GITHUB_TOKEN is absent."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    respx.get(f"{PYPI_BASE}/requests/2.31.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("requests", "2.31.0"))
    )
    respx.get(f"{PYPI_BASE}/requests/2.32.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("requests", "2.32.0"))
    )
    respx.get(f"{PYPI_INTEGRITY}/requests/2.31.0/requests-2.31.0.tar.gz/provenance").mock(
        return_value=httpx.Response(200, json=_pypi_provenance(repo="psf/requests"))
    )
    respx.get(f"{PYPI_INTEGRITY}/requests/2.32.0/requests-2.32.0.tar.gz/provenance").mock(
        return_value=httpx.Response(200, json=_pypi_provenance(repo="psf/requests"))
    )

    env = ActivityEnvironment()
    result = await env.run(attestation_check, "pip", "requests", "2.31.0", "2.32.0")
    assert result.has_attestation is True
    assert result.publisher_account_age_days is None


def test_rule_based_classifier_flags_young_publisher_account():
    from activities.classifier import _rule_based
    from activities.models import PackageSignals

    signals = PackageSignals(
        ecosystem="npm",
        package_name="coolpkg",
        old_version="1.0.0",
        new_version="1.0.1",
        release_age_hours=200.0,
        is_major_bump=False,
        socket_score=None,
        socket_alerts=[],
        osv_vulnerabilities=[],
        diff_summary="[no significant changes detected]",
        diff_size_bytes=0,
        maintainer_changed=False,
        weekly_downloads=50_000,
        has_attestation=True,
        publisher_repo="neworg/coolpkg",
        publisher_account_age_days=30,
    )
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    assert any("30 days old" in f for f in verdict.flags)


def test_rule_based_classifier_install_script_added_is_red():
    from activities.classifier import _rule_based
    from activities.models import PackageSignals

    signals = PackageSignals(
        ecosystem="pip",
        package_name="mypkg",
        old_version="1.0.0",
        new_version="1.0.1",
        release_age_hours=300.0,
        is_major_bump=False,
        socket_score=80,
        socket_alerts=[],
        osv_vulnerabilities=[],
        diff_summary="+ setup.py",
        diff_size_bytes=100,
        maintainer_changed=False,
        weekly_downloads=100_000,
        install_script_added=True,
    )
    verdict = _rule_based(signals)
    assert verdict.classification == "red"
    assert "install script added" in verdict.flags


def test_rule_based_classifier_install_script_changed_is_yellow():
    from activities.classifier import _rule_based
    from activities.models import PackageSignals

    signals = PackageSignals(
        ecosystem="pip",
        package_name="mypkg",
        old_version="1.0.0",
        new_version="1.0.1",
        release_age_hours=300.0,
        is_major_bump=False,
        socket_score=80,
        socket_alerts=[],
        osv_vulnerabilities=[],
        diff_summary="--- setup.py\n+++ setup.py\n-version='1.0.0'\n+version='1.0.1'",
        diff_size_bytes=100,
        maintainer_changed=False,
        weekly_downloads=100_000,
        install_script_changed=True,
    )
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    assert any("install script modified" in f for f in verdict.flags)


# ---------------------------------------------------------------------------
# SLSA chain fields — source_ref, source_commit_sha, build_invocation_id
# ---------------------------------------------------------------------------

@respx.mock
async def test_pypi_attestation_populates_source_ref_from_claims():
    """source_ref comes from publisher.claims.ref even without a DSSE envelope."""
    respx.get(f"{PYPI_BASE}/pkg/1.0.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("pkg", "1.0.0"))
    )
    respx.get(f"{PYPI_BASE}/pkg/1.1.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("pkg", "1.1.0"))
    )
    respx.get(f"{PYPI_INTEGRITY}/pkg/1.0.0/pkg-1.0.0.tar.gz/provenance").mock(
        return_value=httpx.Response(200, json=_pypi_provenance(repo="org/pkg"))
    )
    respx.get(f"{PYPI_INTEGRITY}/pkg/1.1.0/pkg-1.1.0.tar.gz/provenance").mock(
        return_value=httpx.Response(200, json=_pypi_provenance(repo="org/pkg"))
    )

    env = ActivityEnvironment()
    result = await env.run(attestation_check, "pip", "pkg", "1.0.0", "1.1.0")
    assert result.has_attestation is True
    assert result.source_ref == "refs/tags/2.32.0"
    assert result.source_commit_sha is None  # no DSSE envelope
    assert result.build_invocation_id is None


@respx.mock
async def test_pypi_attestation_populates_commit_sha_and_invocation_from_dsse():
    """source_commit_sha and build_invocation_id are extracted from the DSSE payload."""
    respx.get(f"{PYPI_BASE}/pkg/1.0.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("pkg", "1.0.0"))
    )
    respx.get(f"{PYPI_BASE}/pkg/1.1.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("pkg", "1.1.0"))
    )
    respx.get(f"{PYPI_INTEGRITY}/pkg/1.0.0/pkg-1.0.0.tar.gz/provenance").mock(
        return_value=httpx.Response(200, json=_pypi_provenance(repo="org/pkg"))
    )
    respx.get(f"{PYPI_INTEGRITY}/pkg/1.1.0/pkg-1.1.0.tar.gz/provenance").mock(
        return_value=httpx.Response(200, json=_pypi_provenance(repo="org/pkg", with_dsse=True))
    )

    env = ActivityEnvironment()
    result = await env.run(attestation_check, "pip", "pkg", "1.0.0", "1.1.0")
    assert result.has_attestation is True
    assert result.source_commit_sha == "abc123def456abc123def456abc123def456abc1"
    assert result.build_invocation_id == "https://github.com/psf/requests/actions/runs/99887766"


@respx.mock
async def test_npm_attestation_populates_slsa_chain_fields():
    """source_ref, source_commit_sha, and build_invocation_id all extracted from npm SLSA payload."""
    sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    inv_id = "https://github.com/owner/pkg/actions/runs/12345678"
    respx.get(f"{NPM_ATT_BASE}/mypkg@1.0.0").mock(
        return_value=httpx.Response(200, json=_npm_attestation_bundle("https://github.com/owner/mypkg"))
    )
    respx.get(f"{NPM_ATT_BASE}/mypkg@1.1.0").mock(
        return_value=httpx.Response(200, json=_npm_attestation_bundle(
            "https://github.com/owner/mypkg",
            commit_sha=sha,
            invocation_id=inv_id,
        ))
    )

    env = ActivityEnvironment()
    result = await env.run(attestation_check, "npm", "mypkg", "1.0.0", "1.1.0")
    assert result.has_attestation is True
    assert result.source_ref == "refs/tags/v1.1.0"
    assert result.source_commit_sha == sha
    assert result.build_invocation_id == inv_id


# ---------------------------------------------------------------------------
# Repo mismatch (Critical #4 + #7) — metadata_repo vs publisher_repo cross-check
# ---------------------------------------------------------------------------

def _signals_with_attestation(**overrides):
    """Minimal PackageSignals with attestation for classifier rule tests."""
    from activities.models import PackageSignals
    base = dict(
        ecosystem="pip",
        package_name="pkg",
        old_version="1.0.0",
        new_version="1.1.0",
        release_age_hours=500.0,
        is_major_bump=False,
        socket_score=None,
        socket_alerts=[],
        osv_vulnerabilities=[],
        diff_summary="[no significant changes detected]",
        diff_size_bytes=0,
        maintainer_changed=False,
        weekly_downloads=100_000,
        has_attestation=True,
        publisher_repo="psf/requests",
        metadata_repo="psf/requests",
    )
    base.update(overrides)
    return PackageSignals(**base)


def test_rule_based_repo_mismatch_is_red():
    """publisher_repo != metadata_repo with attestation → automatic RED."""
    from activities.classifier import _rule_based
    signals = _signals_with_attestation(
        publisher_repo="attacker/evil-fork",
        metadata_repo="psf/requests",
    )
    verdict = _rule_based(signals)
    assert verdict.classification == "red"
    assert verdict.confidence >= 0.90
    assert any("mismatch" in f for f in verdict.flags)
    assert "attacker/evil-fork" in " ".join(verdict.flags)
    assert "psf/requests" in " ".join(verdict.flags)


def test_rule_based_repo_mismatch_case_insensitive():
    """Comparison ignores case — same repo spelled differently is not a mismatch."""
    from activities.classifier import _rule_based
    signals = _signals_with_attestation(
        publisher_repo="PSF/Requests",
        metadata_repo="psf/requests",
    )
    verdict = _rule_based(signals)
    assert verdict.classification != "red" or not any("mismatch" in f for f in verdict.flags)


def test_rule_based_no_mismatch_when_metadata_repo_none():
    """No mismatch flag when metadata_repo is absent (no GitHub URL in registry metadata)."""
    from activities.classifier import _rule_based
    signals = _signals_with_attestation(metadata_repo=None)
    verdict = _rule_based(signals)
    assert not any("mismatch" in f for f in verdict.flags)


def test_rule_based_no_mismatch_when_no_attestation():
    """Mismatch check is skipped when has_attestation=False — no provenance to compare against."""
    from activities.classifier import _rule_based
    signals = _signals_with_attestation(
        has_attestation=False,
        publisher_repo=None,
        metadata_repo="psf/requests",
    )
    verdict = _rule_based(signals)
    assert not any("mismatch" in f for f in verdict.flags)


def test_rule_based_non_tag_source_ref_is_yellow():
    """source_ref pointing to a branch (not a tag) with attestation → YELLOW flag."""
    from activities.classifier import _rule_based
    signals = _signals_with_attestation(source_ref="refs/heads/main")
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    assert any("source_ref" in f for f in verdict.flags)
    assert any("tag" in f for f in verdict.flags)


def test_rule_based_tag_source_ref_not_flagged():
    """Proper refs/tags/... source_ref should not be flagged."""
    from activities.classifier import _rule_based
    signals = _signals_with_attestation(source_ref="refs/tags/v1.1.0")
    verdict = _rule_based(signals)
    assert not any("source_ref" in f for f in verdict.flags)


def test_rule_based_non_tag_source_ref_no_flag_without_attestation():
    """source_ref check is skipped when has_attestation=False."""
    from activities.classifier import _rule_based
    signals = _signals_with_attestation(
        has_attestation=False,
        source_ref="refs/heads/main",
    )
    verdict = _rule_based(signals)
    assert not any("source_ref" in f for f in verdict.flags)


def test_rule_based_publisher_changed_same_repo_is_lower_concern():
    """publisher_changed=True where new repo matches metadata_repo → 'CI migration' flag text."""
    from activities.classifier import _rule_based
    signals = _signals_with_attestation(
        publisher_changed=True,
        old_publisher_repo="psf/requests-old-workflow",
        publisher_repo="psf/requests",
        metadata_repo="psf/requests",
    )
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    flags_text = " ".join(verdict.flags)
    assert "migration" in flags_text or "CI" in flags_text


@respx.mock
async def test_pypi_attestation_oidc_first_time_true():
    """oidc_first_time=True when old version 404s on provenance but new has it."""
    respx.get(f"{PYPI_BASE}/pkg/1.0.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("pkg", "1.0.0"))
    )
    respx.get(f"{PYPI_INTEGRITY}/pkg/1.0.0/pkg-1.0.0.tar.gz/provenance").mock(
        return_value=httpx.Response(404)
    )
    respx.get(f"{PYPI_BASE}/pkg/1.1.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_urls("pkg", "1.1.0"))
    )
    respx.get(f"{PYPI_INTEGRITY}/pkg/1.1.0/pkg-1.1.0.tar.gz/provenance").mock(
        return_value=httpx.Response(200, json=_pypi_provenance(repo="org/pkg"))
    )

    from activities.attestation import check as attestation_check
    env = ActivityEnvironment()
    result = await env.run(attestation_check, "pip", "pkg", "1.0.0", "1.1.0")
    assert result.has_attestation is True
    assert result.oidc_first_time is True
    assert result.publisher_changed is False  # not "changed" — just first time


@respx.mock
async def test_pypi_attestation_oidc_first_time_false_when_both_had_attestation():
    """oidc_first_time=False when both old and new versions have attestation."""
    for version in ("1.0.0", "1.1.0"):
        respx.get(f"{PYPI_BASE}/pkg/{version}/json").mock(
            return_value=httpx.Response(200, json=_pypi_urls("pkg", version))
        )
        respx.get(f"{PYPI_INTEGRITY}/pkg/{version}/pkg-{version}.tar.gz/provenance").mock(
            return_value=httpx.Response(200, json=_pypi_provenance(repo="org/pkg"))
        )

    from activities.attestation import check as attestation_check
    env = ActivityEnvironment()
    result = await env.run(attestation_check, "pip", "pkg", "1.0.0", "1.1.0")
    assert result.has_attestation is True
    assert result.oidc_first_time is False


@respx.mock
async def test_publisher_changed_false_when_only_commit_sha_differs():
    """publisher_changed must not fire when the same repo built different commits (the normal case)."""
    old_sha = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"
    new_sha = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"
    respx.get(f"{NPM_ATT_BASE}/mypkg@1.0.0").mock(
        return_value=httpx.Response(200, json=_npm_attestation_bundle(
            "https://github.com/org/mypkg", commit_sha=old_sha
        ))
    )
    respx.get(f"{NPM_ATT_BASE}/mypkg@1.1.0").mock(
        return_value=httpx.Response(200, json=_npm_attestation_bundle(
            "https://github.com/org/mypkg", commit_sha=new_sha
        ))
    )

    env = ActivityEnvironment()
    result = await env.run(attestation_check, "npm", "mypkg", "1.0.0", "1.1.0")
    assert result.has_attestation is True
    assert result.publisher_changed is False  # same repo, different commits is expected
