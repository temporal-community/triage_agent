from temporalio import activity
from activities.models import PyPISignals


@activity.defn(name="activities.pypi_metadata.fetch")
async def fetch(ecosystem: str, package: str, old_version: str, new_version: str) -> PyPISignals:
    activity.logger.info(f"[stub] Fetching PyPI metadata for {package} {new_version}")
    return PyPISignals(
        weekly_downloads=50_000,
        publish_account_age_days=365,
        is_major_bump=_is_major(old_version, new_version),
    )


def _is_major(old: str, new: str) -> bool:
    try:
        return int(new.split(".")[0]) > int(old.split(".")[0])
    except (ValueError, IndexError):
        return False
