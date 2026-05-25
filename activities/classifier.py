from temporalio import activity

from classifiers import RuleBasedClassifier, get_classifier
from models import PackageChecks, Verdict


@activity.defn(name="activities.classifier.classify")
async def classify(signals: PackageChecks) -> Verdict:
    clf = get_classifier()
    if isinstance(clf, RuleBasedClassifier):
        activity.logger.info("No LLM configured — using rule-based classifier")
    else:
        activity.logger.info("Using classifier: %s", type(clf).__name__)
    return await clf.classify(signals)
