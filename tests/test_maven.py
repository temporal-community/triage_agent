"""
Unit tests for the Maven ecosystem provider.
HTTP calls mocked with respx; Temporal activity context via ActivityEnvironment.
"""

from __future__ import annotations

import io
import zipfile

import httpx
import pytest
import respx
from temporalio.exceptions import ApplicationError
from temporalio.testing import ActivityEnvironment

from ecosystems.maven import MavenProvider, _parse_pom

_CENTRAL = "https://repo1.maven.org/maven2"
_SEARCH = "https://search.maven.org/solrsearch/select"

# ---------------------------------------------------------------------------
# POM XML helpers
# ---------------------------------------------------------------------------

_SIMPLE_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>mylib</artifactId>
  <version>1.2.3</version>
  <description>A simple example library.</description>
  <scm>
    <url>https://github.com/example/mylib</url>
  </scm>
  <developers>
    <developer>
      <name>Alice Smith</name>
      <email>alice@example.com</email>
    </developer>
  </developers>
</project>
"""

_POM_TWO_DEVS = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>mylib</artifactId>
  <version>2.0.0</version>
  <developers>
    <developer>
      <name>Alice Smith</name>
    </developer>
    <developer>
      <name>Bob Jones</name>
    </developer>
  </developers>
</project>
"""

_POM_NO_SCM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>bare</artifactId>
  <version>0.1.0</version>
</project>
"""


# ---------------------------------------------------------------------------
# _parse_pom
# ---------------------------------------------------------------------------


def test_parse_pom_description_and_scm():
    result = _parse_pom(_SIMPLE_POM)
    assert result["description"] == "A simple example library."
    assert "github.com/example/mylib" in result["scm_url"]
    assert "alice smith" in result["developers"]


def test_parse_pom_multiple_developers():
    result = _parse_pom(_POM_TWO_DEVS)
    assert result["developers"] == {"alice smith", "bob jones"}


def test_parse_pom_no_description_or_scm():
    result = _parse_pom(_POM_NO_SCM)
    assert result["description"] is None
    assert result["scm_url"] == ""
    assert result["developers"] == set()


def test_parse_pom_malformed_xml():
    result = _parse_pom("not xml at all <<<")
    assert result == {"description": None, "scm_url": "", "developers": set()}


# ---------------------------------------------------------------------------
# MavenProvider._parse
# ---------------------------------------------------------------------------


def test_parse_valid_coordinate():
    p = MavenProvider()
    g, a = p._parse("com.google.guava:guava")
    assert g == "com.google.guava"
    assert a == "guava"


def test_parse_invalid_coordinate():
    p = MavenProvider()
    with pytest.raises(ApplicationError):
        p._parse("no-colon-here")


def test_group_path():
    p = MavenProvider()
    assert p._group_path("com.google.guava") == "com/google/guava"


# ---------------------------------------------------------------------------
# fetch_metadata
# ---------------------------------------------------------------------------


@respx.mock
async def test_fetch_metadata_success():
    pom_url = f"{_CENTRAL}/com/example/mylib/1.2.3/mylib-1.2.3.pom"
    respx.get(pom_url).mock(return_value=httpx.Response(200, text=_SIMPLE_POM))

    env = ActivityEnvironment()
    provider = MavenProvider()
    result = await env.run(provider.fetch_metadata, "com.example:mylib", "1.0.0", "1.2.3")
    assert result.package_description == "A simple example library."
    assert result.is_major_bump is False
    assert result.weekly_downloads is None  # no public API


@respx.mock
async def test_fetch_metadata_major_bump():
    pom_url = f"{_CENTRAL}/com/example/mylib/2.0.0/mylib-2.0.0.pom"
    respx.get(pom_url).mock(return_value=httpx.Response(200, text=_POM_TWO_DEVS))

    env = ActivityEnvironment()
    provider = MavenProvider()
    result = await env.run(provider.fetch_metadata, "com.example:mylib", "1.9.0", "2.0.0")
    assert result.is_major_bump is True


@respx.mock
async def test_fetch_metadata_404():
    pom_url = f"{_CENTRAL}/com/example/missing/9.9.9/missing-9.9.9.pom"
    respx.get(pom_url).mock(return_value=httpx.Response(404))

    env = ActivityEnvironment()
    provider = MavenProvider()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(provider.fetch_metadata, "com.example:missing", "9.0.0", "9.9.9")
    assert exc_info.value.non_retryable is True


# ---------------------------------------------------------------------------
# fetch_release_age
# ---------------------------------------------------------------------------


@respx.mock
async def test_fetch_release_age_success():
    import time

    # 48 hours ago in ms
    ts_ms = int((time.time() - 48 * 3600) * 1000)
    respx.get(_SEARCH).mock(
        return_value=httpx.Response(200, json={"response": {"docs": [{"timestamp": ts_ms}]}})
    )

    env = ActivityEnvironment()
    provider = MavenProvider()
    result = await env.run(provider.fetch_release_age, "com.example:mylib", "1.2.3")
    assert result.release_age_hours is not None
    assert 47 < result.release_age_hours < 49


@respx.mock
async def test_fetch_release_age_no_docs():
    respx.get(_SEARCH).mock(return_value=httpx.Response(200, json={"response": {"docs": []}}))

    env = ActivityEnvironment()
    provider = MavenProvider()
    result = await env.run(provider.fetch_release_age, "com.example:mylib", "1.2.3")
    assert result.release_age_hours is None


@respx.mock
async def test_fetch_release_age_api_error():
    respx.get(_SEARCH).mock(return_value=httpx.Response(500))

    env = ActivityEnvironment()
    provider = MavenProvider()
    result = await env.run(provider.fetch_release_age, "com.example:mylib", "1.2.3")
    assert result.release_age_hours is None


# ---------------------------------------------------------------------------
# fetch_maintainer
# ---------------------------------------------------------------------------


@respx.mock
async def test_fetch_maintainer_unchanged():
    old_url = f"{_CENTRAL}/com/example/mylib/1.0.0/mylib-1.0.0.pom"
    new_url = f"{_CENTRAL}/com/example/mylib/1.2.3/mylib-1.2.3.pom"
    respx.get(old_url).mock(return_value=httpx.Response(200, text=_SIMPLE_POM))
    respx.get(new_url).mock(return_value=httpx.Response(200, text=_SIMPLE_POM))

    env = ActivityEnvironment()
    provider = MavenProvider()
    result = await env.run(provider.fetch_maintainer, "com.example:mylib", "1.0.0", "1.2.3")
    assert result.maintainer_changed is False


@respx.mock
async def test_fetch_maintainer_new_developer():
    old_url = f"{_CENTRAL}/com/example/mylib/1.0.0/mylib-1.0.0.pom"
    new_url = f"{_CENTRAL}/com/example/mylib/2.0.0/mylib-2.0.0.pom"
    respx.get(old_url).mock(return_value=httpx.Response(200, text=_SIMPLE_POM))
    respx.get(new_url).mock(return_value=httpx.Response(200, text=_POM_TWO_DEVS))

    env = ActivityEnvironment()
    provider = MavenProvider()
    result = await env.run(provider.fetch_maintainer, "com.example:mylib", "1.0.0", "2.0.0")
    assert result.maintainer_changed is True


@respx.mock
async def test_fetch_maintainer_fetch_failure():
    old_url = f"{_CENTRAL}/com/example/mylib/1.0.0/mylib-1.0.0.pom"
    new_url = f"{_CENTRAL}/com/example/mylib/2.0.0/mylib-2.0.0.pom"
    respx.get(old_url).mock(return_value=httpx.Response(404))
    respx.get(new_url).mock(return_value=httpx.Response(200, text=_POM_TWO_DEVS))

    env = ActivityEnvironment()
    provider = MavenProvider()
    result = await env.run(provider.fetch_maintainer, "com.example:mylib", "1.0.0", "2.0.0")
    assert result.maintainer_changed is False


# ---------------------------------------------------------------------------
# fetch_attestations
# ---------------------------------------------------------------------------


async def test_fetch_attestations_returns_empty():
    env = ActivityEnvironment()
    provider = MavenProvider()
    result = await env.run(provider.fetch_attestations, "com.example:mylib", "1.0.0", "1.2.3")
    assert result.has_attestation is False


# ---------------------------------------------------------------------------
# extract_archive
# ---------------------------------------------------------------------------


def test_extract_archive_jar():
    """JAR is a ZIP — extract_archive should unpack it."""
    import tempfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("com/example/Hello.java", "public class Hello {}")
        zf.writestr("pom.xml", "<project/>")
    jar_bytes = buf.getvalue()

    provider = MavenProvider()
    with tempfile.TemporaryDirectory() as dest:
        provider.extract_archive(jar_bytes, "mylib-1.2.3-sources.jar", dest)
        from pathlib import Path

        assert (Path(dest) / "pom.xml").exists()
        assert (Path(dest) / "com/example/Hello.java").exists()


# ---------------------------------------------------------------------------
# get_archive_url — prefers sources JAR
# ---------------------------------------------------------------------------


@respx.mock
async def test_get_archive_url_prefers_sources():
    base = f"{_CENTRAL}/com/example/mylib/1.2.3/mylib-1.2.3"
    # sources JAR exists
    respx.get(f"{base}-sources.jar.sha256").mock(return_value=httpx.Response(200, text="abc123"))
    respx.head(f"{base}-sources.jar").mock(return_value=httpx.Response(200))

    async with httpx.AsyncClient(timeout=15.0) as client:
        provider = MavenProvider()
        result = await provider.get_archive_url(client, "com.example:mylib", "1.2.3")

    assert result is not None
    url, fname, sha = result
    assert "-sources.jar" in url
    assert sha == "abc123"


@respx.mock
async def test_get_archive_url_falls_back_to_jar():
    base = f"{_CENTRAL}/com/example/mylib/1.2.3/mylib-1.2.3"
    # sources JAR missing
    respx.get(f"{base}-sources.jar.sha256").mock(return_value=httpx.Response(404))
    respx.head(f"{base}-sources.jar").mock(return_value=httpx.Response(404))
    # regular JAR present
    respx.get(f"{base}.jar.sha256").mock(return_value=httpx.Response(404))
    respx.head(f"{base}.jar").mock(return_value=httpx.Response(200))

    async with httpx.AsyncClient(timeout=15.0) as client:
        provider = MavenProvider()
        result = await provider.get_archive_url(client, "com.example:mylib", "1.2.3")

    assert result is not None
    url, fname, sha = result
    assert "-sources" not in url
    assert url.endswith(".jar")


@respx.mock
async def test_get_archive_url_none_when_both_missing():
    base = f"{_CENTRAL}/com/example/mylib/1.2.3/mylib-1.2.3"
    respx.get(f"{base}-sources.jar.sha256").mock(return_value=httpx.Response(404))
    respx.head(f"{base}-sources.jar").mock(return_value=httpx.Response(404))
    respx.get(f"{base}.jar.sha256").mock(return_value=httpx.Response(404))
    respx.head(f"{base}.jar").mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient(timeout=15.0) as client:
        provider = MavenProvider()
        result = await provider.get_archive_url(client, "com.example:mylib", "1.2.3")

    assert result is None


# ---------------------------------------------------------------------------
# pr_parser — maven coordinate handling
# ---------------------------------------------------------------------------


def test_pr_parser_maven_coordinate():
    from helpers.pr_parser import parse_pr

    result = parse_pr(
        "Bump com.google.guava:guava from 31.0-jre to 33.0-jre",
        branch="dependabot/maven/com.google.guava-guava-33.0-jre",
    )
    assert result is not None
    assert result.package == "com.google.guava:guava"
    assert result.old_version == "31.0-jre"
    assert result.new_version == "33.0-jre"
    assert result.ecosystem == "maven"


def test_pr_parser_maven_ecosystem_from_branch():
    from helpers.pr_parser import parse_pr

    result = parse_pr(
        "Bump org.springframework.boot:spring-boot-starter from 3.1.0 to 3.2.0",
        branch="dependabot/maven/org.springframework.boot-spring-boot-starter-3.2.0",
    )
    assert result is not None
    assert result.ecosystem == "maven"


# ---------------------------------------------------------------------------
# webhook validation — maven name regex
# ---------------------------------------------------------------------------


def test_webhook_validates_maven_name():
    from api.webhook import _validate_parsed_package

    assert (
        _validate_parsed_package("maven", "com.google.guava:guava", "31.0-jre", "33.0-jre") is None
    )


def test_webhook_rejects_maven_name_without_colon():
    from api.webhook import _validate_parsed_package

    err = _validate_parsed_package("maven", "com.google.guava", "1.0", "2.0")
    assert err is not None


def test_webhook_rejects_maven_name_with_injection():
    from api.webhook import _validate_parsed_package

    err = _validate_parsed_package("maven", "com.evil:../../../etc/passwd", "1.0", "2.0")
    assert err is not None


# ---------------------------------------------------------------------------
# version_lineage — maven
# ---------------------------------------------------------------------------


@respx.mock
async def test_version_lineage_maven_stale():
    from activities.version_lineage import check as lineage_check
    import time

    now_ms = int(time.time() * 1000)
    one_year_ms = 365 * 24 * 3600 * 1000
    respx.get(_SEARCH).mock(
        return_value=httpx.Response(
            200,
            json={
                "response": {
                    "docs": [
                        {"v": "0.9.0", "timestamp": now_ms - 3 * one_year_ms},
                        {"v": "0.8.0", "timestamp": now_ms - 4 * one_year_ms},
                        {"v": "1.0.0", "timestamp": now_ms - one_year_ms // 2},
                    ]
                }
            },
        )
    )
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "maven", "com.example:mylib", "0.8.0", "0.9.0")
    assert result.stale_version_line is True
    assert result.latest_major == 1
    assert result.bump_major == 0


@respx.mock
async def test_version_lineage_maven_current():
    from activities.version_lineage import check as lineage_check
    import time

    now_ms = int(time.time() * 1000)
    one_year_ms = 365 * 24 * 3600 * 1000
    respx.get(_SEARCH).mock(
        return_value=httpx.Response(
            200,
            json={
                "response": {
                    "docs": [
                        {"v": "1.2.3", "timestamp": now_ms - 3600_000},
                        {"v": "1.2.2", "timestamp": now_ms - one_year_ms},
                    ]
                }
            },
        )
    )
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "maven", "com.example:mylib", "1.2.2", "1.2.3")
    assert result.stale_version_line is False


@respx.mock
async def test_version_lineage_maven_filters_snapshots():
    from activities.version_lineage import check as lineage_check
    import time

    now_ms = int(time.time() * 1000)
    respx.get(_SEARCH).mock(
        return_value=httpx.Response(
            200,
            json={
                "response": {
                    "docs": [
                        {"v": "2.0.0-SNAPSHOT", "timestamp": now_ms},
                        {"v": "1.0.0", "timestamp": now_ms - 3600_000},
                    ]
                }
            },
        )
    )
    env = ActivityEnvironment()
    result = await env.run(lineage_check, "maven", "com.example:mylib", "0.9.0", "1.0.0")
    # SNAPSHOT filtered out — 1.0.0 is the only stable, so no stale line
    assert result.stale_version_line is False
