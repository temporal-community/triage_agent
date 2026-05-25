"""
Classifier protocol — abstracts the decision engine that turns PackageChecks into a Verdict.

Built-in classifiers:
  AnthropicClassifier      — Anthropic API (ANTHROPIC_API_KEY + optional ANTHROPIC_MODEL)
  OpenAIClassifier      — OpenAI API via httpx (OPENAI_API_KEY + optional OPENAI_MODEL)
  OllamaClassifier      — local Ollama instance (OLLAMA_HOST + OLLAMA_MODEL, no key needed)
  RuleBasedClassifier   — deterministic threshold rules, zero API keys required

Selection order:
  1. CLASSIFIER env var — name of a dependency_scout.classifiers entry point or a built-in name
     (claude, openai, ollama, rule_based)
  2. ANTHROPIC_API_KEY set → AnthropicClassifier
  3. Fallback → RuleBasedClassifier

Third-party classifiers register via entry point:

    [project.entry-points."dependency_scout.classifiers"]
    my_gemini = "my_package:GeminiClassifier"

Then set CLASSIFIER=my_gemini in .env.
"""

import logging
import os
from importlib.metadata import entry_points
from typing import Protocol

from temporalio import activity

from models import PackageChecks, Verdict
from classifiers._helpers import _build_message, _rule_based  # noqa: F401 — kept for back-compat
from classifiers.anthropic import AnthropicClassifier
from classifiers.openai import OpenAIClassifier
from classifiers.ollama import OllamaClassifier

_logger = logging.getLogger(__name__)


class Classifier(Protocol):
    """Classifies a dependency bump as green / yellow / red given collected signals."""

    async def classify(self, signals: PackageChecks) -> Verdict: ...


class RuleBasedClassifier:
    """Deterministic threshold rules — zero API keys required."""

    async def classify(self, signals: PackageChecks) -> Verdict:
        return _rule_based(signals)


_BUILTIN_CLASSIFIERS: dict[str, type] = {
    "claude": AnthropicClassifier,
    "openai": OpenAIClassifier,
    "ollama": OllamaClassifier,
    "rule_based": RuleBasedClassifier,
}


def get_classifier() -> Classifier:
    """Return the active Classifier.

    Selection order:
    1. CLASSIFIER env var → look up in dependency_scout.classifiers entry points, then built-in names.
    2. Default: AnthropicClassifier when ANTHROPIC_API_KEY is set, else RuleBasedClassifier.
    """
    name = os.environ.get("CLASSIFIER")
    if name:
        try:
            for ep in entry_points(group="dependency_scout.classifiers"):
                if ep.name == name:
                    return ep.load()()
        except Exception as exc:  # noqa: BLE001
            _logger.warning("Failed to load classifier %r from entry points: %s", name, exc)
        if name in _BUILTIN_CLASSIFIERS:
            return _BUILTIN_CLASSIFIERS[name]()
        _logger.warning(
            "CLASSIFIER=%r not found in dependency_scout.classifiers entry points or built-in names "
            "('claude', 'rule_based') — falling back to default",
            name,
        )

    if not os.environ.get("ANTHROPIC_API_KEY"):
        return RuleBasedClassifier()
    return AnthropicClassifier()


@activity.defn(name="activities.classifier.classify")
async def classify(signals: PackageChecks) -> Verdict:
    clf = get_classifier()
    if not os.environ.get("ANTHROPIC_API_KEY") and isinstance(clf, RuleBasedClassifier):
        activity.logger.info("No ANTHROPIC_API_KEY — using rule-based classifier")
    else:
        activity.logger.info("Using classifier: %s", type(clf).__name__)
    return await clf.classify(signals)
