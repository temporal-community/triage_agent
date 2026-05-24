import asyncio
import importlib
import os
import pkgutil

import activities as _activities_pkg
from dotenv import load_dotenv
from temporalio.activity import _Definition
from temporalio.client import Client
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.worker import Worker

from workflows.package_triage_workflow import PackageTriageWorkflow
from workflows.pr_action_workflow import PRActionWorkflow

load_dotenv()


def _discover_activities() -> list:
    """Return every @activity.defn-decorated function found in activities/*.py (non-recursive).

    Scans only top-level modules — activities/ecosystems/ contains provider helpers, not activities.
    """
    seen: set[int] = set()
    fns = []
    for mod_info in pkgutil.iter_modules(_activities_pkg.__path__, prefix="activities."):
        mod = importlib.import_module(mod_info.name)
        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if callable(obj) and id(obj) not in seen and _Definition.from_callable(obj) is not None:
                seen.add(id(obj))
                fns.append(obj)
    return fns


def _discover_plugin_activities() -> list:
    """Load @activity.defn-decorated functions from the triage_agent.activities entry point group.

    Plugin packages declare activities in their pyproject.toml:
        [project.entry-points."triage_agent.activities"]
        my_signal = "my_package.activities:check"

    Each entry point must point to a single @activity.defn-decorated callable.
    Non-activity callables and load failures are silently skipped.

    Security note: plugin activities run in-process alongside core activities — the same
    trust boundary as any installed pip dependency or triage_agent.ecosystems plugin.
    Results land in PackageSignals.custom_signals which is rendered in the sandboxed
    <untrusted_custom> section of the LLM prompt, not the trusted signals block.
    """
    try:
        from importlib.metadata import entry_points
    except ImportError:
        return []

    seen: set[int] = set()
    fns = []
    for ep in entry_points(group="triage_agent.activities"):
        try:
            fn = ep.load()
            if callable(fn) and id(fn) not in seen and _Definition.from_callable(fn) is not None:
                seen.add(id(fn))
                fns.append(fn)
        except Exception:  # noqa: BLE001
            pass
    return fns


# Auto-discovered from activities/*.py plus any installed triage_agent.activities plugins.
# Adding a new built-in activity file is sufficient — no manual registration needed.
# Exposed at module level for test_signal_wiring.py.
ACTIVITIES = _discover_activities() + _discover_plugin_activities()


async def main() -> None:
    client = await Client.connect(
        os.environ.get("TEMPORAL_ADDRESS", "localhost:7233"),
        namespace=os.environ.get("TEMPORAL_NAMESPACE", "default"),
        data_converter=pydantic_data_converter,
    )
    task_queue = os.environ.get("TEMPORAL_TASK_QUEUE", "dependency-triage")
    worker = Worker(
        client,
        task_queue=task_queue,
        workflows=[PackageTriageWorkflow, PRActionWorkflow],
        activities=ACTIVITIES,
    )
    print(f"Worker started on task queue: {task_queue}")
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
