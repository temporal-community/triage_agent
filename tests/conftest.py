import pytest
from helpers.cache import clear_all_caches
from models import (
    AttestationSignals,
    DiffSignals,
    OSVSignals,
    PackageSignals,
    PyPISignals,
    ReleaseAgeSignals,
    SocketSignals,
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
    return PackageSignals(
        ecosystem="pip",
        package_name="requests",
        old_version="2.31.0",
        new_version="2.32.0",
        pypi=PyPISignals(weekly_downloads=5_000_000, is_major_bump=False),
        socket=SocketSignals(socket_score=80, socket_alerts=[]),
        osv=OSVSignals(osv_vulnerabilities=[]),
        diff=DiffSignals(diff_summary="Minor internal refactor.", diff_size_bytes=512),
        age=ReleaseAgeSignals(release_age_hours=200.0),
        attestation=AttestationSignals(publisher_account_age_days=1800),
    )
