from temporalio import activity
from activities.models import ReleaseAgeSignals


@activity.defn(name="activities.release_age.check")
async def check(ecosystem: str, package: str, old_version: str, new_version: str) -> ReleaseAgeSignals:
    activity.logger.info(f"[stub] Checking release age for {package} {new_version}")
    return ReleaseAgeSignals(release_age_hours=200.0)
