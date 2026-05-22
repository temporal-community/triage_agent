import asyncio
import os
from dotenv import load_dotenv
from temporalio.client import Client
from temporalio.worker import Worker
from temporalio.contrib.pydantic import pydantic_data_converter

from workflows.package_triage_workflow import PackageTriageWorkflow
from workflows.pr_action_workflow import PRActionWorkflow
from activities import pypi_metadata, socket, osv, package_diff, release_age, maintainer
from activities import classifier, repo_config, github

load_dotenv()


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
        activities=[
            pypi_metadata.fetch,
            socket.score,
            osv.check,
            package_diff.compute,
            release_age.check,
            maintainer.history,
            classifier.classify,
            repo_config.fetch,
            github.comment,
            github.merge_pr,
            github.request_review,
            github.label,
            github.get_pr,
        ],
    )
    print(f"Worker started on task queue: {task_queue}")
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
