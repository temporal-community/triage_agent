import asyncio
import importlib
import logging
import os
import pkgutil

import activities as _activities_pkg
from dotenv import load_dotenv
from temporalio.activity import _Definition
from temporalio.client import Client, TLSConfig
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.worker import Worker

from workflows.package_triage_workflow import PackageTriageWorkflow
from workflows.pr_action_workflow import PRActionWorkflow

load_dotenv()

logger = logging.getLogger(__name__)


def _check_config() -> None:
    """Warn at startup about missing or suspicious configuration."""
    has_github_secret = os.environ.get("GITHUB_WEBHOOK_SECRET")
    has_gitlab_secret = os.environ.get("GITLAB_WEBHOOK_SECRET")
    if not has_github_secret and not has_gitlab_secret:
        logger.warning(
            "Neither GITHUB_WEBHOOK_SECRET nor GITLAB_WEBHOOK_SECRET is set — "
            "the webhook server will reject all requests. "
            "This is fine if you're testing with start_workflow directly."
        )
    has_github = os.environ.get("GITHUB_TOKEN") or os.environ.get("GITHUB_APP_ID")
    has_gitlab = os.environ.get("GITLAB_TOKEN")
    if not has_github and not has_gitlab:
        logger.warning(
            "No platform credentials (GITHUB_TOKEN, GITHUB_APP_ID, or GITLAB_TOKEN). "
            "The worker will run but cannot post PR comments or take actions."
        )
    classifier = os.environ.get("CLASSIFIER", "")
    if not classifier and not os.environ.get("ANTHROPIC_API_KEY"):
        logger.info(
            "No LLM configured (ANTHROPIC_API_KEY / CLASSIFIER not set) — using rule-based classifier."
        )
    if not os.environ.get("SOCKET_API_KEY"):
        logger.info(
            "SOCKET_API_KEY not set — Socket.dev supply-chain score signal will be skipped."
        )


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
    """Load @activity.defn-decorated functions from the dependency_scout.activities entry point group.

    Plugin packages declare activities in their pyproject.toml:
        [project.entry-points."dependency_scout.activities"]
        my_signal = "my_package.activities:check"

    Each entry point must point to a single @activity.defn-decorated callable.
    Non-activity callables and load failures are silently skipped.

    Security note: plugin activities run in-process alongside core activities — the same
    trust boundary as any installed pip dependency or dependency_scout.ecosystems plugin.
    Results land in PackageSignals.custom_signals which is rendered in the sandboxed
    <untrusted_custom> section of the LLM prompt, not the trusted signals block.
    """
    try:
        from importlib.metadata import entry_points
    except ImportError:
        return []

    seen: set[int] = set()
    fns = []
    for ep in entry_points(group="dependency_scout.activities"):
        try:
            fn = ep.load()
            if callable(fn) and id(fn) not in seen and _Definition.from_callable(fn) is not None:
                seen.add(id(fn))
                fns.append(fn)
        except Exception:  # noqa: BLE001
            pass
    return fns


# Auto-discovered from activities/*.py plus any installed dependency_scout.activities plugins.
# Adding a new built-in activity file is sufficient — no manual registration needed.
# Exposed at module level for test_signal_wiring.py.
ACTIVITIES = _discover_activities() + _discover_plugin_activities()


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    _check_config()
    address = os.environ.get("TEMPORAL_ADDRESS", "localhost:7233")
    namespace = os.environ.get("TEMPORAL_NAMESPACE", "default")
    task_queue = os.environ.get("TEMPORAL_TASK_QUEUE", "dependency-triage")

    tls: TLSConfig | bool = False
    cert_path = os.environ.get("TEMPORAL_TLS_CERT")
    key_path = os.environ.get("TEMPORAL_TLS_KEY")
    if cert_path and key_path:
        tls = TLSConfig(
            client_cert=open(cert_path, "rb").read(),
            client_private_key=open(key_path, "rb").read(),
        )
        logger.info("TLS enabled — connecting to Temporal Cloud at %s", address)

    client = await Client.connect(
        address, namespace=namespace, tls=tls, data_converter=pydantic_data_converter
    )
    worker = Worker(
        client,
        task_queue=task_queue,
        workflows=[PackageTriageWorkflow, PRActionWorkflow],
        activities=ACTIVITIES,
    )
    logger.info(
        "Worker started — task_queue=%s temporal=%s activities=%d",
        task_queue,
        address,
        len(ACTIVITIES),
    )
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
