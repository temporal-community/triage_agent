from __future__ import annotations

import asyncio
import io
import re
import tarfile
from datetime import date, datetime, timedelta, timezone

import httpx
from temporalio.exceptions import ApplicationError

from ecosystems import (
    EcosystemProviderBase,
    build_release_signals,
    fetch_vcs_release,
    fetch_vcs_tag_signature,
    is_major,
    parse_vcs_repo,
    parse_upload_time,
    safe_tar_extractall,
    validate_archive_url,
)
from models import (
    AttestationSignals,
    MaintainerSignals,
    PyPISignals,
    ReleaseAgeSignals,
    ReleaseSignals,
)
from helpers.http import get_client


class RubyGemsProvider(EcosystemProviderBase):
    ecosystem_name = "rubygems"
    osv_name = "RubyGems"
    dependabot_slug = "bundler"
    name_re = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,213}$")

    # ------------------------------------------------------------------
    # fetch_metadata
    # ------------------------------------------------------------------

    async def fetch_metadata(self, package: str, old_version: str, new_version: str) -> PyPISignals:
        client = get_client()
        gem_resp, dl_resp = await asyncio.gather(
            client.get(f"https://rubygems.org/api/v1/gems/{package}.json", timeout=15.0),
            _fetch_weekly_downloads(client, package),
        )
        if gem_resp.status_code == 404:
            raise ApplicationError(
                f"{package} not found on RubyGems",
                type="PackageNotFound",
                non_retryable=True,
            )
        gem_resp.raise_for_status()
        data = gem_resp.json()

        summary = (data.get("info") or "")[:500] or None
        return PyPISignals(
            weekly_downloads=dl_resp,
            is_major_bump=is_major(old_version, new_version),
            package_description=summary,
        )

    # ------------------------------------------------------------------
    # fetch_release_age
    # ------------------------------------------------------------------

    async def fetch_release_age(self, package: str, new_version: str) -> ReleaseAgeSignals:
        client = get_client()
        resp = await client.get(
            f"https://rubygems.org/api/v1/versions/{package}.json", timeout=15.0
        )
        if resp.status_code == 404:
            raise ApplicationError(
                f"{package} not found on RubyGems",
                type="PackageNotFound",
                non_retryable=True,
            )
        resp.raise_for_status()
        versions = resp.json()

        for v in versions:
            if v.get("number") == new_version:
                raw = v.get("created_at", "")
                if not raw:
                    return ReleaseAgeSignals(release_age_hours=None)
                upload_time = parse_upload_time(raw)
                hours = (datetime.now(timezone.utc) - upload_time).total_seconds() / 3600
                return ReleaseAgeSignals(release_age_hours=max(0.0, hours))

        return ReleaseAgeSignals(release_age_hours=None)

    # ------------------------------------------------------------------
    # fetch_maintainer
    # ------------------------------------------------------------------

    async def fetch_maintainer(
        self, package: str, old_version: str, new_version: str
    ) -> MaintainerSignals:
        client = get_client()
        try:
            resp = await client.get(
                f"https://rubygems.org/api/v1/versions/{package}.json", timeout=15.0
            )
            if resp.status_code != 200:
                return MaintainerSignals(maintainer_changed=False)
            versions = resp.json()
        except Exception:
            return MaintainerSignals(maintainer_changed=False)

        old_authors: set[str] = set()
        new_authors: set[str] = set()
        for v in versions:
            num = v.get("number", "")
            if num == old_version:
                old_authors = _author_set(v)
            elif num == new_version:
                new_authors = _author_set(v)

        if not old_authors or not new_authors:
            return MaintainerSignals(maintainer_changed=False)

        return MaintainerSignals(maintainer_changed=bool(new_authors - old_authors))

    # ------------------------------------------------------------------
    # get_archive_url
    # ------------------------------------------------------------------

    async def get_archive_url(
        self, client: httpx.AsyncClient, package: str, version: str
    ) -> tuple[str, str, str] | None:
        resp = await client.get(f"https://rubygems.org/api/v1/versions/{package}.json")
        if resp.status_code == 404:
            raise ApplicationError(
                f"{package} not found on RubyGems",
                type="PackageNotFound",
                non_retryable=True,
            )
        resp.raise_for_status()
        versions = resp.json()

        for v in versions:
            if v.get("number") == version:
                sha256 = v.get("sha", "")
                filename = f"{package}-{version}.gem"
                url = f"https://rubygems.org/gems/{filename}"
                validate_archive_url(url)
                return url, filename, sha256

        return None

    # ------------------------------------------------------------------
    # extract_archive
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # fetch_attestations
    # ------------------------------------------------------------------

    async def fetch_attestations(
        self, package: str, old_version: str, new_version: str
    ) -> AttestationSignals:
        # RubyGems does not yet support SLSA provenance or Sigstore attestations.
        return AttestationSignals(has_attestation=False)

    # ------------------------------------------------------------------
    # fetch_release
    # ------------------------------------------------------------------

    async def fetch_release(self, package: str, old_version: str, version: str) -> ReleaseSignals:
        import os

        token = os.environ.get("GITHUB_TOKEN")
        client = get_client()
        gem_resp, versions_resp = await asyncio.gather(
            client.get(f"https://rubygems.org/api/v1/gems/{package}.json", timeout=15.0),
            client.get(f"https://rubygems.org/api/v1/versions/{package}.json", timeout=15.0),
        )

        if gem_resp.status_code != 200:
            return ReleaseSignals()
        gem_data = gem_resp.json()

        source_url = gem_data.get("source_code_uri") or gem_data.get("homepage_uri") or ""
        vcs = parse_vcs_repo(source_url)
        if not vcs:
            return ReleaseSignals()
        platform, owner_repo = vcs

        # Registry timestamp for skew calculation
        registry_time = None
        if versions_resp.status_code == 200:
            for v in versions_resp.json():
                if v.get("number") == version:
                    raw = v.get("created_at", "")
                    if raw:
                        try:
                            registry_time = parse_upload_time(raw)
                        except Exception:  # noqa: BLE001
                            pass
                    break

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
        """Extract a RubyGems .gem file (outer tar → data.tar.gz → source tree)."""
        buf = io.BytesIO(archive_bytes)
        with tarfile.open(fileobj=buf) as outer:
            data_member = next((m for m in outer.getmembers() if m.name == "data.tar.gz"), None)
            if data_member is None:
                raise ValueError("No data.tar.gz found in .gem archive")
            data_fobj = outer.extractfile(data_member)
            if data_fobj is None:
                raise ValueError("Could not read data.tar.gz from .gem archive")
            inner_buf = io.BytesIO(data_fobj.read())

        with tarfile.open(fileobj=inner_buf, mode="r:gz") as inner:
            safe_tar_extractall(inner, dest)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _author_set(version_data: dict) -> set[str]:
    # "authors" is a comma-separated string like "Alice, Bob"
    raw = (version_data.get("authors") or "").lower()
    return {a.strip() for a in raw.split(",") if a.strip()}


async def _fetch_weekly_downloads(client: httpx.AsyncClient, package: str) -> int | None:
    """Return approximate weekly downloads for a RubyGem via the daily-stats search endpoint.

    RubyGems exposes per-day download counts at /api/v1/downloads/search.json.
    Summing the last 7 completed days gives a figure comparable to PyPI/npm weekly stats.
    Falls back to None on any error so the rest of metadata fetch is unaffected.
    """
    try:
        to_date = date.today() - timedelta(days=1)  # yesterday (most recent complete day)
        from_date = to_date - timedelta(days=6)  # 7 days total
        resp = await client.get(
            "https://rubygems.org/api/v1/downloads/search.json",
            params={
                "from": from_date.isoformat(),
                "to": to_date.isoformat(),
                "gem_name": package,
            },
        )
        if resp.status_code == 200:
            daily = resp.json().get("rubygems") or {}
            total = sum(daily.values())
            return total if total > 0 else None
    except Exception:  # noqa: BLE001
        pass
    return None
