"""Ecosystem provider for Maven Central (Java/JVM packages).

Package names use Maven coordinate format: groupId:artifactId
e.g. "com.google.guava:guava", "org.springframework.boot:spring-boot-starter"
"""
from __future__ import annotations

import asyncio
import io
import re
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
from temporalio.exceptions import ApplicationError

from activities.ecosystems import (
    build_release_signals,
    fetch_github_release,
    fetch_tag_signature,
    is_major,
    parse_github_repo,
    parse_upload_time,
    safe_zip_extractall,
    validate_archive_url,
)
from activities.models import (
    AttestationSignals,
    MaintainerSignals,
    PyPISignals,
    ReleaseAgeSignals,
    ReleaseSignals,
)

_CENTRAL = "https://repo1.maven.org/maven2"
_SEARCH   = "https://search.maven.org/solrsearch/select"


class MavenProvider:
    ecosystem_name = "maven"
    osv_name = "Maven"
    dependabot_slug = "maven"
    name_re = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,213}:[A-Za-z0-9][A-Za-z0-9._-]{0,213}$")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse(self, package: str) -> tuple[str, str]:
        """Split 'groupId:artifactId' → (group_id, artifact_id)."""
        if ":" not in package:
            raise ApplicationError(
                f"Invalid Maven package format: {package!r} — expected groupId:artifactId",
                non_retryable=True,
            )
        group_id, artifact_id = package.split(":", 1)
        return group_id, artifact_id

    def _group_path(self, group_id: str) -> str:
        """com.google.guava → com/google/guava"""
        return group_id.replace(".", "/")

    def _artifact_base(self, group_id: str, artifact_id: str, version: str) -> str:
        return f"{_CENTRAL}/{self._group_path(group_id)}/{artifact_id}/{version}/{artifact_id}-{version}"

    # ------------------------------------------------------------------
    # fetch_metadata
    # ------------------------------------------------------------------

    async def fetch_metadata(
        self, package: str, old_version: str, new_version: str
    ) -> PyPISignals:
        group_id, artifact_id = self._parse(package)
        pom_url = f"{self._artifact_base(group_id, artifact_id, new_version)}.pom"

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(pom_url)

        if resp.status_code == 404:
            raise ApplicationError(
                f"{package}:{new_version} not found on Maven Central",
                type="PackageNotFound",
                non_retryable=True,
            )
        resp.raise_for_status()

        pom = _parse_pom(resp.text)
        description = pom.get("description")

        return PyPISignals(
            weekly_downloads=None,  # no public weekly-download API for Maven Central
            is_major_bump=is_major(old_version, new_version),
            package_description=description,
        )

    # ------------------------------------------------------------------
    # fetch_release_age
    # ------------------------------------------------------------------

    async def fetch_release_age(self, package: str, new_version: str) -> ReleaseAgeSignals:
        group_id, artifact_id = self._parse(package)
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                _SEARCH,
                params={
                    "q": f"g:{group_id} AND a:{artifact_id} AND v:{new_version}",
                    "core": "gav",
                    "rows": "1",
                    "wt": "json",
                },
            )

        if resp.status_code != 200:
            return ReleaseAgeSignals(release_age_hours=None)

        docs = resp.json().get("response", {}).get("docs", [])
        if not docs:
            return ReleaseAgeSignals(release_age_hours=None)

        ts_ms = docs[0].get("timestamp")
        if ts_ms is None:
            return ReleaseAgeSignals(release_age_hours=None)

        upload_time = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
        hours = (datetime.now(timezone.utc) - upload_time).total_seconds() / 3600
        return ReleaseAgeSignals(release_age_hours=max(0.0, hours))

    # ------------------------------------------------------------------
    # fetch_maintainer
    # ------------------------------------------------------------------

    async def fetch_maintainer(
        self, package: str, old_version: str, new_version: str
    ) -> MaintainerSignals:
        group_id, artifact_id = self._parse(package)
        old_url = f"{self._artifact_base(group_id, artifact_id, old_version)}.pom"
        new_url = f"{self._artifact_base(group_id, artifact_id, new_version)}.pom"

        async with httpx.AsyncClient(timeout=15.0) as client:
            old_resp, new_resp = await asyncio.gather(
                client.get(old_url), client.get(new_url)
            )

        if old_resp.status_code != 200 or new_resp.status_code != 200:
            return MaintainerSignals(maintainer_changed=False)

        old_devs = _parse_pom(old_resp.text).get("developers", set())
        new_devs = _parse_pom(new_resp.text).get("developers", set())

        if not old_devs or not new_devs:
            return MaintainerSignals(maintainer_changed=False)

        return MaintainerSignals(maintainer_changed=bool(new_devs - old_devs))

    # ------------------------------------------------------------------
    # get_archive_url
    # ------------------------------------------------------------------

    async def get_archive_url(
        self, client: httpx.AsyncClient, package: str, version: str
    ) -> tuple[str, str, str] | None:
        group_id, artifact_id = self._parse(package)
        base = self._artifact_base(group_id, artifact_id, version)

        # Prefer sources JAR — contains readable .java files, far better for diffing
        # than compiled bytecode.  Fall back to regular JAR if sources aren't published.
        for suffix, fname_suffix in (
            ("-sources.jar", f"{artifact_id}-{version}-sources.jar"),
            (".jar",         f"{artifact_id}-{version}.jar"),
        ):
            url = f"{base}{suffix}"
            validate_archive_url(url)

            # Try to fetch a SHA-256 checksum for integrity verification
            sha256 = ""
            sha_resp = await client.get(f"{url}.sha256")
            if sha_resp.status_code == 200:
                sha256 = sha_resp.text.strip().split()[0]  # some files have trailing filename

            # Confirm the artifact exists
            head = await client.head(url)
            if head.status_code == 200:
                return url, fname_suffix, sha256

        return None

    # ------------------------------------------------------------------
    # extract_archive
    # ------------------------------------------------------------------

    def extract_archive(self, archive_bytes: bytes, filename: str, dest: str) -> None:
        """Extract a JAR/sources-JAR (which is a ZIP) to dest."""
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
        # Maven Central's Sigstore/SLSA attestation support is nascent (2024+)
        # and coverage is very limited. Skip for now.
        return AttestationSignals(has_attestation=False)

    # ------------------------------------------------------------------
    # fetch_release
    # ------------------------------------------------------------------

    async def fetch_release(
        self, package: str, old_version: str, version: str
    ) -> ReleaseSignals:
        import os
        token = os.environ.get("GITHUB_TOKEN")
        group_id, artifact_id = self._parse(package)

        async with httpx.AsyncClient(timeout=15.0) as client:
            new_pom_resp, search_resp = await asyncio.gather(
                client.get(f"{self._artifact_base(group_id, artifact_id, version)}.pom"),
                client.get(
                    _SEARCH,
                    params={
                        "q": f"g:{group_id} AND a:{artifact_id} AND v:{version}",
                        "core": "gav",
                        "rows": "1",
                        "wt": "json",
                    },
                ),
            )

        if new_pom_resp.status_code != 200:
            return ReleaseSignals()

        pom = _parse_pom(new_pom_resp.text)
        owner_repo = parse_github_repo(pom.get("scm_url", ""))
        if not owner_repo:
            return ReleaseSignals()

        # Registry publish timestamp for skew calculation
        registry_time: datetime | None = None
        docs = search_resp.json().get("response", {}).get("docs", []) if search_resp.status_code == 200 else []
        if docs:
            ts_ms = docs[0].get("timestamp")
            if ts_ms is not None:
                registry_time = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)

        owner, repo = owner_repo.split("/", 1)
        release, new_sig, old_sig = await asyncio.gather(
            fetch_github_release(owner, repo, version, token),
            fetch_tag_signature(owner, repo, version, token),
            fetch_tag_signature(owner, repo, old_version, token),
        )
        if release:
            return build_release_signals(release, registry_time, new_sig, old_sig).model_copy(
                update={"metadata_repo": owner_repo}
            )
        return ReleaseSignals(metadata_repo=owner_repo)


# ---------------------------------------------------------------------------
# POM parsing helpers
# ---------------------------------------------------------------------------

def _parse_pom(xml_text: str) -> dict:
    """Extract description, SCM URL, and developer list from a Maven POM.

    Strips the xmlns attribute so ElementTree can use simple tag names without
    namespace prefixes.
    """
    try:
        import re
        clean = re.sub(r'\s+xmlns(?::\w+)?="[^"]*"', "", xml_text)
        root = ET.fromstring(clean)

        description = root.findtext("description")
        if description:
            description = description.strip()[:500] or None

        scm_url = (
            root.findtext("scm/url")
            or root.findtext("url")
            or ""
        ).strip()

        developers: set[str] = set()
        for dev in root.findall(".//developer"):
            name  = (dev.findtext("name")  or "").lower().strip()
            email = (dev.findtext("email") or "").lower().strip()
            if name:
                developers.add(name)
            elif email:
                developers.add(email)

        return {"description": description, "scm_url": scm_url, "developers": developers}
    except Exception:  # noqa: BLE001
        return {"description": None, "scm_url": "", "developers": set()}
