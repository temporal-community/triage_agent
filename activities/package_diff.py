from temporalio import activity
from activities.models import DiffSignals


@activity.defn(name="activities.package_diff.compute")
async def compute(ecosystem: str, package: str, old_version: str, new_version: str) -> DiffSignals:
    activity.logger.info(f"[stub] Computing package diff for {package} {old_version} -> {new_version}")
    return DiffSignals(
        diff_summary="[stub] Minor changes in helpers and test files.",
        diff_size_bytes=1024,
    )
