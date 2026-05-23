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


def _pypi_provenance(kind: str = "GitHub", repo: str = "psf/requests") -> dict:
    return {
        "metadata": {"kind": "publish-attestation", "version": "1"},
        "attestation_bundles": [
            {
                "publisher": {
                    "kind": kind,
                    "claims": {"repository": repo, "ref": "refs/tags/2.32.0", "workflow": ".github/workflows/publish.yml"},
                },
                "attestations": [],
            }
        ],
    }


def _npm_attestation_bundle(repo_url: str = "https://github.com/owner/pkg") -> dict:
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
                }
            }
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
        publish_account_age_days=None,
        publisher_changed=True,
        old_publisher_repo="trusted/repo",
        publisher_repo="new/repo",
        has_attestation=True,
    )
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    assert any("trusted publisher changed" in f for f in verdict.flags)
    assert "trusted/repo" in " ".join(verdict.flags)
