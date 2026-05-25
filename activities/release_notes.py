from temporalio import activity

from ecosystems import get_provider
from models import ReleaseChecks


@activity.defn(name="activities.release_notes.check")
async def check(ecosystem: str, package: str, old_version: str, new_version: str) -> ReleaseChecks:
    return await get_provider(ecosystem).fetch_release(package, old_version, new_version)
