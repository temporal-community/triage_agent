from activities.ecosystems import get_provider
from activities.models import ReleaseAgeSignals
from temporalio import activity


@activity.defn(name="activities.release_age.check")
async def check(ecosystem: str, package: str, old_version: str, new_version: str) -> ReleaseAgeSignals:
    return await get_provider(ecosystem).fetch_release_age(package, new_version)
