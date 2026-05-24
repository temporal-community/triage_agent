"""
Structural tests that catch three classes of wiring bugs:

1. An activity name string in the workflow has no registered handler in the worker
   (silent runtime failure after the workflow has already started).

2. A PackageSignals sub-model is gathered and stored but never read by the classifier
   (dead code — the signal runs, costs latency, and changes nothing).

3. A provider's ecosystem_name is not in the Literal type annotations in models.py
   (Pydantic will reject that ecosystem at runtime even though the provider exists).
"""
import inspect
import typing

from activities.models import PackageSignals, PRContext


def test_all_signal_activities_registered_with_worker():
    """Every activity name string in SIGNAL_ACTIVITY_NAMES is in the worker's ACTIVITIES list."""
    from worker import ACTIVITIES
    from workflows.package_triage_workflow import SIGNAL_ACTIVITY_NAMES
    from temporalio.activity import _Definition

    registered = {
        defn.name
        for fn in ACTIVITIES
        if (defn := _Definition.from_callable(fn)) is not None
    }
    missing = [name for name in SIGNAL_ACTIVITY_NAMES if name not in registered]
    assert not missing, (
        f"Activities referenced in PackageTriageWorkflow but missing from worker.ACTIVITIES:\n"
        + "\n".join(f"  {name}" for name in missing)
    )


def test_all_signal_sub_models_used_in_classifier():
    """Every PackageSignals sub-model field has at least one field access in classifier.py."""
    import activities.classifier as classifier_module

    source = inspect.getsource(classifier_module)

    identity_fields = {"ecosystem", "package_name", "old_version", "new_version"}
    unused = []
    for field_name, field_info in PackageSignals.model_fields.items():
        if field_name in identity_fields:
            continue
        if f"signals.{field_name}." not in source:
            unused.append(field_name)

    assert not unused, (
        f"PackageSignals sub-models with no field accesses in classifier.py "
        f"(signal gathered but result never used):\n"
        + "\n".join(f"  signals.{name}.*" for name in unused)
    )


def test_all_providers_in_ecosystem_literal():
    """Every discovered provider's ecosystem_name is in the Literal type in models.py.

    The Literal type can't be auto-discovered (Python type system limitation), so this
    test catches the gap: provider exists, but Pydantic will reject it at runtime.
    """
    from activities.ecosystems import _build_provider_registry

    providers = _build_provider_registry()
    valid = set(typing.get_args(PRContext.model_fields["ecosystem"].annotation))
    missing = [name for name in providers if name not in valid]
    assert not missing, (
        f"Ecosystem providers exist but their names are missing from the "
        f"Literal type in activities/models.py — Pydantic will reject them at runtime:\n"
        + "\n".join(f"  {name!r}" for name in missing)
    )
