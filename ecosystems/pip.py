from __future__ import annotations

import asyncio
import io
import re
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
from temporalio.exceptions import ApplicationError

from ecosystems import (
    EcosystemProviderBase,
    build_release_checks,
    fetch_vcs_account_age,
    fetch_vcs_ci_workflow_changes,
    fetch_vcs_release,
    fetch_vcs_tag_signature,
    is_major,
    parse_vcs_repo,
    parse_upload_time,
    safe_tar_extractall,
    safe_zip_extractall,
    validate_archive_url,
)
from models import (
    AttestationChecks,
    MaintainerChecks,
    MetadataChecks,
    ReleaseAgeChecks,
    ReleaseChecks,
)
from helpers.http import get_client


class PipProvider(EcosystemProviderBase):
    ecosystem_name = "pip"
    osv_name = "PyPI"
    dependabot_slug = "pip"
    name_re = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,213}$")

    # ------------------------------------------------------------------
    # fetch_metadata
    # ------------------------------------------------------------------

    async def fetch_metadata(self, package: str, old_version: str, new_version: str) -> MetadataChecks:
        client = get_client()
        resp = await client.get(f"https://pypi.org/pypi/{package}/{new_version}/json", timeout=15.0)
        if resp.status_code == 404:
            raise ApplicationError(
                f"{package}=={new_version} not found on PyPI",
                type="PackageNotFound",
                non_retryable=True,
            )
        resp.raise_for_status()
        data = resp.json()

        summary = data.get("info", {}).get("summary") or None
        if summary:
            summary = summary[:500]

        weekly_downloads = await _fetch_weekly_downloads(client, package)

        return MetadataChecks(
            weekly_downloads=weekly_downloads,
            is_major_bump=is_major(old_version, new_version),
            package_description=summary,
        )

    # ------------------------------------------------------------------
    # fetch_release_age
    # ------------------------------------------------------------------

    async def fetch_release_age(self, package: str, new_version: str) -> ReleaseAgeChecks:
        client = get_client()
        resp = await client.get(f"https://pypi.org/pypi/{package}/{new_version}/json", timeout=15.0)
        if resp.status_code == 404:
            raise ApplicationError(
                f"{package}=={new_version} not found on PyPI",
                type="PackageNotFound",
                non_retryable=True,
            )
        resp.raise_for_status()
        data = resp.json()

        urls = data.get("urls", [])
        if not urls:
            return ReleaseAgeChecks(release_age_hours=None)

        raw = urls[0].get("upload_time_iso_8601") or urls[0].get("upload_time", "")
        if not raw:
            return ReleaseAgeChecks(release_age_hours=None)

        upload_time = parse_upload_time(raw)
        hours = (datetime.now(timezone.utc) - upload_time).total_seconds() / 3600
        return ReleaseAgeChecks(release_age_hours=max(0.0, hours))

    # ------------------------------------------------------------------
    # fetch_maintainer
    # ------------------------------------------------------------------

    async def fetch_maintainer(
        self, package: str, old_version: str, new_version: str
    ) -> MaintainerChecks:
        client = get_client()
        old_info, new_info = await asyncio.gather(
            _fetch_version_info(client, package, old_version),
            _fetch_version_info(client, package, new_version),
        )

        if old_info is None or new_info is None:
            return MaintainerChecks(maintainer_changed=False)

        old_set = _maintainer_set(old_info)
        new_set = _maintainer_set(new_info)
        return MaintainerChecks(maintainer_changed=bool(new_set - old_set))

    # ------------------------------------------------------------------
    # get_archive_url
    # ------------------------------------------------------------------

    async def get_archive_url(
        self, client: httpx.AsyncClient, package: str, version: str
    ) -> tuple[str, str, str] | None:
        resp = await client.get(f"https://pypi.org/pypi/{package}/{version}/json")
        if resp.status_code == 404:
            raise ApplicationError(
                f"{package}=={version} not found on PyPI",
                type="PackageNotFound",
                non_retryable=True,
            )
        resp.raise_for_status()
        urls: list[dict] = resp.json().get("urls", [])

        for pkg_type in ("sdist", "bdist_wheel"):
            for entry in urls:
                if entry.get("packagetype") == pkg_type:
                    url = entry["url"]
                    validate_archive_url(url)
                    return url, entry["filename"], entry.get("digests", {}).get("sha256", "")

        return None

    # ------------------------------------------------------------------
    # extract_archive
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # fetch_attestations
    # ------------------------------------------------------------------

    async def fetch_attestations(
        self, package: str, old_version: str, new_version: str
    ) -> AttestationChecks:
        client = get_client()
        new_pub, old_pub = await asyncio.gather(
            _fetch_pypi_publisher(client, package, new_version),
            _fetch_pypi_publisher(client, package, old_version),
        )

        if new_pub is None:
            return AttestationChecks(has_attestation=False)

        age_days = None
        if new_pub.get("repo"):
            owner = new_pub["repo"].split("/")[0]
            age_days = await fetch_vcs_account_age("github", owner)

        publisher_changed = old_pub is not None and old_pub.get("repo") != new_pub.get("repo")
        return AttestationChecks(
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

    async def fetch_release(self, package: str, old_version: str, version: str) -> ReleaseChecks:
        import os

        token = os.environ.get("GITHUB_TOKEN")
        client = get_client()
        resp = await client.get(f"https://pypi.org/pypi/{package}/{version}/json", timeout=15.0)
        if resp.status_code != 200:
            return ReleaseChecks()
        data = resp.json()

        # Registry publish timestamp for skew calculation
        registry_time = None
        urls = data.get("urls", [])
        if urls:
            raw = urls[0].get("upload_time_iso_8601") or urls[0].get("upload_time", "")
            if raw:
                try:
                    registry_time = parse_upload_time(raw)
                except Exception:  # noqa: BLE001
                    pass

        # Source repo URL — try common project_urls keys before falling back to home_page
        info = data.get("info", {})
        project_urls = info.get("project_urls") or {}
        source_url = (
            project_urls.get("Source Code")
            or project_urls.get("Source")
            or project_urls.get("Repository")
            or project_urls.get("Homepage")
            or info.get("home_page")
            or ""
        )
        vcs = parse_vcs_repo(source_url)
        if not vcs:
            return ReleaseChecks()
        platform, owner_repo = vcs
        owner, repo = owner_repo.split("/", 1)
        release, new_sig, old_sig, ci_days = await asyncio.gather(
            fetch_vcs_release(platform, owner, repo, version, token),
            fetch_vcs_tag_signature(platform, owner, repo, version, token),
            fetch_vcs_tag_signature(platform, owner, repo, old_version, token),
            fetch_vcs_ci_workflow_changes(platform, owner, repo),
        )
        extra: dict = {"metadata_repo": owner_repo}
        if ci_days is not None:
            extra["ci_workflow_changed_days_ago"] = ci_days
        if release:
            return build_release_checks(release, registry_time, new_sig, old_sig).model_copy(
                update=extra
            )
        return ReleaseChecks(**extra)

    def extract_archive(self, archive_bytes: bytes, filename: str, dest: str) -> None:
        buf = io.BytesIO(archive_bytes)
        dest_path = Path(dest).resolve()
        lower = filename.lower()
        if lower.endswith((".tar.gz", ".tar.bz2", ".tgz")):
            with tarfile.open(fileobj=buf) as tf:
                safe_tar_extractall(tf, dest)
        elif lower.endswith((".whl", ".zip")):
            with zipfile.ZipFile(buf) as zf:
                safe_zip_extractall(zf, dest_path)
        else:
            raise ValueError(f"Unsupported PyPI archive format: {filename}")


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


async def _fetch_weekly_downloads(client: httpx.AsyncClient, package: str) -> int | None:
    try:
        resp = await client.get(
            f"https://pypistats.org/api/packages/{package.lower()}/recent",
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 200:
            return resp.json()["data"]["last_week"]
    except Exception:
        pass
    return None


async def _fetch_version_info(client: httpx.AsyncClient, package: str, version: str) -> dict | None:
    try:
        resp = await client.get(f"https://pypi.org/pypi/{package}/{version}/json")
        if resp.status_code == 200:
            return resp.json().get("info", {})
    except Exception:
        pass
    return None


def _maintainer_set(info: dict) -> set[str]:
    result = set()
    for field in ("author", "maintainer", "author_email", "maintainer_email"):
        val = (info.get(field) or "").strip().lower()
        if val and val not in ("none", "unknown", ""):
            result.add(val)
    return result


async def _fetch_pypi_publisher(
    client: httpx.AsyncClient, package: str, version: str
) -> dict | None:
    """Return provenance dict from the PEP 740 provenance endpoint, or None.

    PyPI generates attestations automatically for packages published via a
    Trusted Publisher (GitHub Actions, GitLab CI, etc.).  A 404 means the
    version was uploaded with a plain API token and has no attestation.
    """
    import base64
    import json as _json

    try:
        resp = await client.get(f"https://pypi.org/pypi/{package}/{version}/json")
        if resp.status_code != 200:
            return None
        urls = resp.json().get("urls", [])
        # Prefer sdist; any file works since provenance is per-file
        filename = next(
            (u["filename"] for u in urls if u.get("packagetype") == "sdist"),
            urls[0]["filename"] if urls else None,
        )
        if not filename:
            return None

        prov = await client.get(
            f"https://pypi.org/integrity/{package}/{version}/{filename}/provenance"
        )
        if prov.status_code != 200:
            return None

        bundles = prov.json().get("attestation_bundles", [])
        if not bundles:
            return None
        bundle = bundles[0]
        pub = bundle.get("publisher", {})
        claims = pub.get("claims", {})
        result: dict = {
            "kind": pub.get("kind"),
            "repo": claims.get("repository"),
            "source_ref": claims.get("ref"),
            "source_commit_sha": None,
            "build_invocation_id": None,
        }

        # Extract cryptographic chain fields from the DSSE envelope in the first attestation
        attestations = bundle.get("attestations", [])
        if attestations:
            payload_b64 = (
                attestations[0].get("bundle", {}).get("dsseEnvelope", {}).get("payload", "")
            )
            if payload_b64:
                padding = 4 - len(payload_b64) % 4
                payload = _json.loads(base64.b64decode(payload_b64 + "=" * (padding % 4)))
                pred = payload.get("predicate", {})
                build_def = pred.get("buildDefinition", {})
                resolved = build_def.get("resolvedDependencies", [])
                if resolved:
                    result["source_commit_sha"] = resolved[0].get("digest", {}).get("gitCommit")
                result["build_invocation_id"] = (
                    pred.get("runDetails", {}).get("metadata", {}).get("invocationID")
                )

        return result
    except Exception:
        return None
