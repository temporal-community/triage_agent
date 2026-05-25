import pytest
from helpers.cache import clear_all_caches


@pytest.fixture(autouse=True)
def reset_activity_caches():
    """Clear all ActivityCache instances before each test.

    Prevents cache hits from earlier tests from masking expected HTTP calls
    or error paths in later tests.
    """
    clear_all_caches()
    yield
    clear_all_caches()
