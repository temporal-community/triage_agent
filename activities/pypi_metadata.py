from activities.ecosystems import get_provider
from activities.models import PyPISignals
from temporalio import activity


@activity.defn(name="activities.pypi_metadata.fetch")
async def fetch(ecosystem: str, package: str, old_version: str, new_version: str) -> PyPISignals:
    return await get_provider(ecosystem).fetch_metadata(package, old_version, new_version)
