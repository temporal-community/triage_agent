from temporalio import activity

from ecosystems import get_provider
from models import ReleaseChecks


@activity.defn(name="activities.release_notes.check")
async def check(ecosystem: str, package: str, old_version: str, new_version: str) -> ReleaseChecks:
    """Fetch the GitHub or GitLab release for the new version and check whether the release tag is cryptographically signed and whether the publish time matches the registry upload time.

    Returns a ``ReleaseChecks`` with the release notes text and integrity flags."""
    return await get_provider(ecosystem).fetch_release(package, old_version, new_version)
