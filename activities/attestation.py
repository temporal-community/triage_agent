from activities.ecosystems import get_provider
from activities.models import AttestationSignals
from temporalio import activity


@activity.defn(name="activities.attestation.check")
async def check(
    ecosystem: str, package: str, old_version: str, new_version: str
) -> AttestationSignals:
    return await get_provider(ecosystem).fetch_attestations(package, old_version, new_version)
