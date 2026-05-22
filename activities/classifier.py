from temporalio import activity
from activities.models import PackageSignals, Verdict


@activity.defn(name="activities.classifier.classify")
async def classify(signals: PackageSignals) -> Verdict:
    activity.logger.info(
        f"[stub] Classifying {signals.package_name} {signals.new_version} — returning hardcoded green"
    )
    return Verdict(
        classification="green",
        confidence=0.9,
        reasoning=(
            f"[stub] {signals.package_name} {signals.old_version} → {signals.new_version}: "
            f"patch bump, {signals.release_age_hours:.0f}h old, no CVEs, no socket alerts."
        ),
        flags=[],
    )
