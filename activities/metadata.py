from ecosystems import get_provider
from models import MetadataChecks
from temporalio import activity


@activity.defn(name="activities.metadata.fetch")
async def fetch(ecosystem: str, package: str, old_version: str, new_version: str) -> MetadataChecks:
    """Fetch registry metadata for the package, including weekly download counts, whether the bump is a major version change, and the package description.

    Returns a ``MetadataChecks`` populated from the ecosystem registry (e.g. PyPI, npm)."""
    return await get_provider(ecosystem).fetch_metadata(package, old_version, new_version)
