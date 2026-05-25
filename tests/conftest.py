import pytest
from helpers.cache import clear_all_caches
from models import (
    AttestationChecks,
    PackageDiffChecks,
    OSVChecks,
    PackageChecks,
    MetadataChecks,
    ReleaseAgeChecks,
    SocketChecks,
)


@pytest.fixture(autouse=True)
def reset_activity_caches():
    """Clear all ActivityCache instances before each test.

    Prevents cache hits from earlier tests from masking expected HTTP calls
    or error paths in later tests.
    """
    clear_all_caches()
    yield
    clear_all_caches()


@pytest.fixture
def base_signals():
    return PackageChecks(
        ecosystem="pip",
        package_name="requests",
        old_version="2.31.0",
        new_version="2.32.0",
        metadata=MetadataChecks(weekly_downloads=5_000_000, is_major_bump=False),
        socket=SocketChecks(socket_score=80, socket_alerts=[]),
        osv=OSVChecks(osv_vulnerabilities=[]),
        diff=PackageDiffChecks(diff_summary="Minor internal refactor.", diff_size_bytes=512),
        age=ReleaseAgeChecks(release_age_hours=200.0),
        attestation=AttestationChecks(publisher_account_age_days=1800),
    )
