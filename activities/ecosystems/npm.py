from __future__ import annotations

import asyncio
import io
import re
import tarfile
from datetime import datetime, timezone

import httpx
from temporalio.exceptions import ApplicationError

from activities.ecosystems import (
    build_release_signals,
    fetch_vcs_account_age,
    fetch_vcs_release,
    fetch_vcs_tag_signature,
    is_major,
    parse_vcs_repo,
    parse_upload_time,
    safe_tar_extractall,
    validate_archive_url,
)
from activities.models import (
    AttestationSignals,
    MaintainerSignals,
    PyPISignals,
    ReleaseAgeSignals,
    ReleaseSignals,
)
from helpers.http import get_client


class NpmProvider:
    ecosystem_name = "npm"
    osv_name = "npm"
    dependabot_slug = "npm_and_yarn"
    name_re = re.compile(r"^(@[A-Za-z0-9._-]+/)?[A-Za-z0-9][A-Za-z0-9._-]{0,213}$")

    # ------------------------------------------------------------------
    # fetch_metadata
    # ------------------------------------------------------------------

    async def fetch_metadata(self, package: str, old_version: str, new_version: str) -> PyPISignals:
        client = get_client()
        resp = await client.get(f"https://registry.npmjs.org/{package}/{new_version}", timeout=15.0)
        if resp.status_code == 404:
            raise ApplicationError(
                f"{package}@{new_version} not found on npm registry",
                type="PackageNotFound",
                non_retryable=True,
            )
        resp.raise_for_status()
        data = resp.json()

        summary = (data.get("description") or "")[:500] or None
        weekly_downloads = await _fetch_weekly_downloads(client, package)

        return PyPISignals(
            weekly_downloads=weekly_downloads,
            is_major_bump=is_major(old_version, new_version),
            package_description=summary,
        )

    # ------------------------------------------------------------------
    # fetch_release_age
    # ------------------------------------------------------------------

    async def fetch_release_age(self, package: str, new_version: str) -> ReleaseAgeSignals:
        client = get_client()
        # Full package document contains the `time` map: {version: ISO timestamp}
        resp = await client.get(f"https://registry.npmjs.org/{package}", timeout=15.0)
        if resp.status_code == 404:
            raise ApplicationError(
                f"{package}@{new_version} not found on npm registry",
                type="PackageNotFound",
                non_retryable=True,
            )
        resp.raise_for_status()
        data = resp.json()

        raw = (data.get("time") or {}).get(new_version, "")
        if not raw:
            return ReleaseAgeSignals(release_age_hours=None)

        upload_time = parse_upload_time(raw)
        hours = (datetime.now(timezone.utc) - upload_time).total_seconds() / 3600
        return ReleaseAgeSignals(release_age_hours=max(0.0, hours))

    # ------------------------------------------------------------------
    # fetch_maintainer
    # ------------------------------------------------------------------

    async def fetch_maintainer(
        self, package: str, old_version: str, new_version: str
    ) -> MaintainerSignals:
        client = get_client()
        old_data, new_data = await asyncio.gather(
            _fetch_version(client, package, old_version),
            _fetch_version(client, package, new_version),
        )

        if old_data is None or new_data is None:
            return MaintainerSignals(maintainer_changed=False)

        old_set = _maintainer_set(old_data)
        new_set = _maintainer_set(new_data)
        return MaintainerSignals(maintainer_changed=bool(new_set - old_set))

    # ------------------------------------------------------------------
    # get_archive_url
    # ------------------------------------------------------------------

    async def get_archive_url(
        self, client: httpx.AsyncClient, package: str, version: str
    ) -> tuple[str, str, str] | None:
        resp = await client.get(f"https://registry.npmjs.org/{package}/{version}")
        if resp.status_code == 404:
            raise ApplicationError(
                f"{package}@{version} not found on npm registry",
                type="PackageNotFound",
                non_retryable=True,
            )
        resp.raise_for_status()
        dist = resp.json().get("dist") or {}
        tarball_url = dist.get("tarball", "")
        if not tarball_url:
            return None
        validate_archive_url(tarball_url)
        return tarball_url, tarball_url.split("/")[-1], dist.get("integrity", "")

    # ------------------------------------------------------------------
    # extract_archive
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # fetch_attestations
    # ------------------------------------------------------------------

    async def fetch_attestations(
        self, package: str, old_version: str, new_version: str
    ) -> AttestationSignals:
        client = get_client()
        new_pub, old_pub = await asyncio.gather(
            _fetch_npm_publisher(client, package, new_version),
            _fetch_npm_publisher(client, package, old_version),
        )

        if new_pub is None:
            return AttestationSignals(has_attestation=False)

        age_days = None
        if new_pub.get("repo"):
            owner = new_pub["repo"].split("/")[0]
            age_days = await fetch_vcs_account_age("github", owner)

        publisher_changed = old_pub is not None and old_pub.get("repo") != new_pub.get("repo")
        return AttestationSignals(
            has_attestation=True,
            publisher_kind=new_pub.get("kind"),
            publisher_repo=new_pub.get("repo"),
            publisher_changed=publisher_changed,
            old_publisher_repo=old_pub.get("repo")
            if (old_pub is not None and publisher_changed)
            else None,
            publisher_account_age_days=age_days,
            source_ref=new_pub.get("source_ref"),
            source_commit_sha=new_pub.get("source_commit_sha"),
            build_invocation_id=new_pub.get("build_invocation_id"),
            oidc_first_time=old_pub is None,
        )

    # ------------------------------------------------------------------
    # fetch_release
    # ------------------------------------------------------------------

    async def fetch_release(self, package: str, old_version: str, version: str) -> ReleaseSignals:
        import os

        token = os.environ.get("GITHUB_TOKEN")
        client = get_client()
        v_resp, pkg_resp = await asyncio.gather(
            client.get(f"https://registry.npmjs.org/{package}/{version}", timeout=15.0),
            client.get(f"https://registry.npmjs.org/{package}", timeout=15.0),
        )

        if v_resp.status_code != 200:
            return ReleaseSignals()
        vdata = v_resp.json()

        # Source URL — check repository field then homepage
        repo_field = vdata.get("repository") or {}
        source_url = repo_field.get("url", "") if isinstance(repo_field, dict) else str(repo_field)
        if not source_url:
            source_url = vdata.get("homepage", "")
        # Normalize npm bare "owner/repo" shorthand (no scheme → GitHub by npm convention)
        if source_url and "://" not in source_url and not source_url.startswith("github:"):
            parts = source_url.split("/")
            if len(parts) == 2 and all(re.match(r"^[A-Za-z0-9_.-]+$", p) for p in parts if p):
                source_url = "https://github.com/" + source_url

        vcs = parse_vcs_repo(source_url)
        if not vcs:
            return ReleaseSignals()
        platform, owner_repo = vcs

        # Registry timestamp for skew calculation
        registry_time = None
        if pkg_resp.status_code == 200:
            raw = (pkg_resp.json().get("time") or {}).get(version, "")
            if raw:
                try:
                    registry_time = parse_upload_time(raw)
                except Exception:  # noqa: BLE001
                    pass

        owner, repo = owner_repo.split("/", 1)
        release, new_sig, old_sig = await asyncio.gather(
            fetch_vcs_release(platform, owner, repo, version, token),
            fetch_vcs_tag_signature(platform, owner, repo, version, token),
            fetch_vcs_tag_signature(platform, owner, repo, old_version, token),
        )
        if release:
            return build_release_signals(release, registry_time, new_sig, old_sig).model_copy(
                update={"metadata_repo": owner_repo}
            )
        return ReleaseSignals(metadata_repo=owner_repo)

    def extract_archive(self, archive_bytes: bytes, filename: str, dest: str) -> None:
        buf = io.BytesIO(archive_bytes)
        with tarfile.open(fileobj=buf) as tf:
            safe_tar_extractall(tf, dest)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


async def _fetch_weekly_downloads(client: httpx.AsyncClient, package: str) -> int | None:
    try:
        resp = await client.get(f"https://api.npmjs.org/downloads/point/last-week/{package}")
        if resp.status_code == 200:
            return resp.json().get("downloads")
    except Exception:
        pass
    return None


async def _fetch_version(client: httpx.AsyncClient, package: str, version: str) -> dict | None:
    try:
        resp = await client.get(f"https://registry.npmjs.org/{package}/{version}")
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def _maintainer_set(data: dict) -> set[str]:
    result = set()
    for m in data.get("maintainers") or []:
        name = (m.get("name") or "").strip().lower()
        if name:
            result.add(name)
    return result


async def _fetch_npm_publisher(
    client: httpx.AsyncClient, package: str, version: str
) -> dict | None:
    """Return provenance dict or None.

    npm provenance is available via the attestations endpoint introduced in 2023.
    The SLSA v1 predicate encodes the source repository, ref, commit SHA, and
    CI invocation ID in the buildDefinition and runDetails sections.
    """
    import base64
    import json as _json

    try:
        resp = await client.get(
            f"https://registry.npmjs.org/-/npm/v1/attestations/{package}@{version}"
        )
        if resp.status_code != 200:
            return None
        attestations = resp.json().get("attestations", [])
        for att in attestations:
            if "provenance" not in att.get("predicateType", "").lower():
                continue
            payload_b64 = att.get("bundle", {}).get("dsseEnvelope", {}).get("payload", "")
            if not payload_b64:
                continue
            # DSSE payload is standard base64 (may lack padding)
            padding = 4 - len(payload_b64) % 4
            payload = _json.loads(base64.b64decode(payload_b64 + "=" * (padding % 4)))
            pred = payload.get("predicate", {})
            build_def = pred.get("buildDefinition", {})
            workflow = build_def.get("externalParameters", {}).get("workflow", {})
            repo_url = workflow.get("repository", "")
            if repo_url:
                kind = "GitHub" if "github.com" in repo_url.lower() else "unknown"
                # Normalize "https://github.com/owner/repo" → "owner/repo"
                if repo_url.startswith("https://github.com/"):
                    repo_url = repo_url[len("https://github.com/") :]
                resolved = build_def.get("resolvedDependencies", [])
                commit_sha = resolved[0].get("digest", {}).get("gitCommit") if resolved else None
                return {
                    "kind": kind,
                    "repo": repo_url,
                    "source_ref": workflow.get("ref"),
                    "source_commit_sha": commit_sha,
                    "build_invocation_id": (
                        pred.get("runDetails", {}).get("metadata", {}).get("invocationID")
                    ),
                }
        # Endpoint returned 200 but no parseable provenance predicate
        return {
            "kind": None,
            "repo": None,
            "source_ref": None,
            "source_commit_sha": None,
            "build_invocation_id": None,
        }
    except Exception:
        return None
