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


def _discover_activity_check_plugins() -> list:
    """Load @activity.defn-decorated functions from dependency_scout.activity_checks entry points.

    Plugin packages declare advanced check activities in their pyproject.toml:
        [project.entry-points."dependency_scout.activity_checks"]
        my_deep_scan = "my_package.activities:deep_scan"

    Each entry point must point to a single @activity.defn-decorated callable that accepts
    a CheckContext and returns dict. Non-activity callables and load failures are skipped
    with a warning (unlike the simple dependency_scout.checks path, a misconfigured
    activity_checks entry point is likely a bug — hence the louder failure).
    """
    try:
        from importlib.metadata import entry_points
    except ImportError:
        return []

    seen: set[int] = set()
    fns = []
    for ep in entry_points(group="dependency_scout.activity_checks"):
        try:
            fn = ep.load()
            if not callable(fn):
                logger.warning(
                    "dependency_scout.activity_checks plugin %r is not callable — skipped", ep.name
                )
                continue
            if _Definition.from_callable(fn) is None:
                logger.warning(
                    "dependency_scout.activity_checks plugin %r is not decorated with "
                    "@activity.defn — skipped. Use dependency_scout.checks for plain async functions.",
                    ep.name,
                )
                continue
            if id(fn) not in seen:
                seen.add(id(fn))
                fns.append(fn)
                logger.info("Registered activity_checks plugin: %r", ep.name)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Failed to load dependency_scout.activity_checks plugin %r: %r", ep.name, exc
            )
    return fns


# Auto-discovered from activities/*.py — adding a new built-in activity file is sufficient,
# no manual registration needed.
# Exposed at module level for test_signal_wiring.py.
ACTIVITIES = _discover_activities() + _discover_activity_check_plugins()


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
