from ecosystems import get_provider
from models import MetadataChecks
from temporalio import activity


@activity.defn(name="activities.metadata.fetch")
async def fetch(ecosystem: str, package: str, old_version: str, new_version: str) -> MetadataChecks:
    return await get_provider(ecosystem).fetch_metadata(package, old_version, new_version)
