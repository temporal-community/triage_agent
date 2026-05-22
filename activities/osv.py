from temporalio import activity
from activities.models import OSVSignals


@activity.defn(name="activities.osv.check")
async def check(ecosystem: str, package: str, old_version: str, new_version: str) -> OSVSignals:
    activity.logger.info(f"[stub] Checking OSV for {package} {new_version}")
    return OSVSignals(osv_vulnerabilities=[])
