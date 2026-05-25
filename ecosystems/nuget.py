"""Ecosystem provider for NuGet (.NET packages).

Package IDs are case-insensitive; all API URL paths use the lower-cased ID.
Names use flat {id} format: e.g. "Newtonsoft.Json", "Microsoft.Extensions.Logging"
"""

from __future__ import annotations

import asyncio
import io
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

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
    safe_zip_extractall,
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

_NUGET_REG = "https://api.nuget.org/v3/registration5"
_NUGET_FLAT = "https://api.nuget.org/v3-flatcontainer"
_NUGET_SEARCH = "https://azuresearch-usnc.nuget.org/query"


class NuGetProvider(EcosystemProviderBase):
    ecosystem_name = "nuget"
    osv_name = "NuGet"
    dependabot_slug = "nuget"
    name_re = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,213}$")

    # ------------------------------------------------------------------
    # fetch_metadata
    # ------------------------------------------------------------------

    async def fetch_metadata(self, package: str, old_version: str, new_version: str) -> PyPISignals:
        id_lower = package.lower()
        client = get_client()
        reg_resp, search_resp = await asyncio.gather(
            client.get(f"{_NUGET_REG}/{id_lower}/index.json", timeout=15.0),
            client.get(
                _NUGET_SEARCH,
                params={"q": f"PackageId:{package}", "prerelease": "false", "take": "1"},
                timeout=15.0,
            ),
        )

        if reg_resp.status_code == 404:
            raise ApplicationError(
                f"{package} not found on NuGet",
                type="PackageNotFound",
                non_retryable=True,
            )
        reg_resp.raise_for_status()

        description: str | None = None
        if search_resp.status_code == 200:
            results = search_resp.json().get("data", [])
            if results:
                description = (results[0].get("description") or "").strip()[:500] or None

        return PyPISignals(
            weekly_downloads=None,  # NuGet only exposes lifetime total downloads, not weekly
            is_major_bump=is_major(old_version, new_version),
            package_description=description,
        )

    # ------------------------------------------------------------------
    # fetch_release_age
    # ------------------------------------------------------------------

    async def fetch_release_age(self, package: str, new_version: str) -> ReleaseAgeSignals:
        catalog = await _fetch_catalog_entry(package, new_version)
        if not catalog:
            return ReleaseAgeSignals()
        raw = catalog.get("published", "")
        # NuGet uses 1900-01-01 as the published date for unlisted (deleted) versions
        if not raw or raw.startswith("1900"):
            return ReleaseAgeSignals()
        try:
            upload_time = parse_upload_time(raw)
            hours = (datetime.now(timezone.utc) - upload_time).total_seconds() / 3600
            return ReleaseAgeSignals(release_age_hours=max(0.0, hours))
        except Exception:  # noqa: BLE001
            return ReleaseAgeSignals()

    # ------------------------------------------------------------------
    # fetch_maintainer
    # ------------------------------------------------------------------

    async def fetch_maintainer(
        self, package: str, old_version: str, new_version: str
    ) -> MaintainerSignals:
        old_cat, new_cat = await asyncio.gather(
            _fetch_catalog_entry(package, old_version),
            _fetch_catalog_entry(package, new_version),
        )
        if not old_cat or not new_cat:
            return MaintainerSignals()
        old_owners = _parse_owners(old_cat.get("owners", ""))
        new_owners = _parse_owners(new_cat.get("owners", ""))
        if not old_owners or not new_owners:
            return MaintainerSignals()
        return MaintainerSignals(maintainer_changed=bool(new_owners - old_owners))

    # ------------------------------------------------------------------
    # get_archive_url
    # ------------------------------------------------------------------

    async def get_archive_url(
        self, client: httpx.AsyncClient, package: str, version: str
    ) -> tuple[str, str, str] | None:
        id_lower = package.lower()
        ver_lower = version.lower()
        url = f"{_NUGET_FLAT}/{id_lower}/{ver_lower}/{id_lower}.{ver_lower}.nupkg"
        validate_archive_url(url)
        return url, f"{package}.{version}.nupkg", ""

    # ------------------------------------------------------------------
    # extract_archive
    # ------------------------------------------------------------------

    def extract_archive(self, archive_bytes: bytes, filename: str, dest: str) -> None:
        """NuGet .nupkg files are standard ZIP archives."""
        buf = io.BytesIO(archive_bytes)
        dest_path = Path(dest).resolve()
        with zipfile.ZipFile(buf) as zf:
            safe_zip_extractall(zf, dest_path)

    # ------------------------------------------------------------------
    # fetch_attestations
    # ------------------------------------------------------------------

    async def fetch_attestations(
        self, package: str, old_version: str, new_version: str
    ) -> AttestationSignals:
        # NuGet does not yet have SLSA/Sigstore attestation support.
        return AttestationSignals(has_attestation=False)

    # ------------------------------------------------------------------
    # fetch_release
    # ------------------------------------------------------------------

    async def fetch_release(self, package: str, old_version: str, version: str) -> ReleaseSignals:
        import os

        token = os.environ.get("GITHUB_TOKEN")
        catalog = await _fetch_catalog_entry(package, version)
        if not catalog:
            return ReleaseSignals()

        registry_time: datetime | None = None
        raw = catalog.get("published", "")
        if raw and not raw.startswith("1900"):
            try:
                registry_time = parse_upload_time(raw)
            except Exception:  # noqa: BLE001
                pass

        project_url = catalog.get("projectUrl") or ""
        vcs = parse_vcs_repo(project_url)
        if not vcs:
            return ReleaseSignals()
        platform, owner_repo = vcs

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


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _parse_owners(raw: str | list) -> set[str]:
    """NuGet owners field may be a comma-separated string or a list."""
    if isinstance(raw, list):
        return {str(o).lower().strip() for o in raw if str(o).strip()}
    return {o.lower().strip() for o in str(raw).split(",") if o.strip()}


async def _fetch_catalog_entry(package: str, version: str) -> dict | None:
    """Return the NuGet registration catalog entry for a specific package version.

    Registration5 pages may be inline (items present) or referenced by URL (must be fetched).
    Handles both small packages (all versions inline) and large packages (paginated).
    """
    id_lower = package.lower()
    ver_lower = version.lower()
    try:
        client = get_client()
        resp = await client.get(f"{_NUGET_REG}/{id_lower}/index.json", timeout=15.0)
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            return None
        index = resp.json()

        for page in index.get("items", []):
            # Inline items: present in the index response
            # Referenced items: page["items"] is None/absent — fetch the page URL
            if "items" in page and page["items"] is not None:
                page_items = page["items"]
            else:
                page_resp = await client.get(page["@id"], timeout=15.0)
                if page_resp.status_code != 200:
                    continue
                page_items = page_resp.json().get("items", [])

            for item in page_items:
                entry = item.get("catalogEntry", {})
                if (entry.get("version") or "").lower() == ver_lower:
                    return entry
    except Exception:  # noqa: BLE001
        pass
    return None
