"""
Structural tests that catch two classes of wiring bugs:

1. An activity name string in the workflow has no registered handler in the worker
   (silent runtime failure after the workflow has already started).

2. A PackageSignals sub-model is gathered and stored but never read by the classifier
   (dead code — the signal runs, costs latency, and changes nothing).
"""

import inspect

from models import PackageSignals


def test_all_signal_activities_registered_with_worker():
    """Every activity name string in SIGNAL_ACTIVITY_NAMES is in the worker's ACTIVITIES list."""
    from worker import ACTIVITIES
    from workflows.package_triage_workflow import SIGNAL_ACTIVITY_NAMES
    from temporalio.activity import _Definition

    registered = {
        defn.name for fn in ACTIVITIES if (defn := _Definition.from_callable(fn)) is not None
    }
    missing = [name for name in SIGNAL_ACTIVITY_NAMES if name not in registered]
    assert not missing, (
        "Activities referenced in PackageTriageWorkflow but missing from worker.ACTIVITIES:\n"
        + "\n".join(f"  {name}" for name in missing)
    )


def test_all_signal_sub_models_used_in_classifier():
    """Every PackageSignals sub-model field has at least one field access in classifier.py."""
    import re
    import classifiers as classifier_module

    source = inspect.getsource(classifier_module)
    # Strip single-line comments so a field mentioned only in a comment isn't counted as used.
    code_only = re.sub(r"#[^\n]*", "", source)

    identity_fields = {"ecosystem", "package_name", "old_version", "new_version"}
    # Dict fields are accessed as `signals.field` (no dot into sub-fields); sub-models use `signals.field.attr`.
    dict_fields = {
        name
        for name, info in PackageSignals.model_fields.items()
        if hasattr(info.annotation, "__origin__") and info.annotation.__origin__ is dict
    }
    unused = []
    for field_name, field_info in PackageSignals.model_fields.items():
        if field_name in identity_fields:
            continue
        pattern = f"signals.{field_name}" if field_name in dict_fields else f"signals.{field_name}."
        if pattern not in code_only:
            unused.append(field_name)

    assert not unused, (
        "PackageSignals sub-models with no field accesses in classifier.py "
        "(signal gathered but result never used):\n"
        + "\n".join(f"  signals.{name}.*" for name in unused)
    )
