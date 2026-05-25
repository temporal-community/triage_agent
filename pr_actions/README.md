# PR Actions

**When do you need a new PR action?** When you want the workflow to do something new with the PR after a verdict — e.g. post to Slack, open a Jira ticket, or trigger a downstream pipeline.

These functions are called by `PRActionWorkflow` after a triage verdict is reached. They talk to the GitHub or GitLab API (or any external service) to act on the PR. For the triage check functions that produce the verdict, see [`checks/`](../checks/README.md).

All functions live in `actions.py`.

## Actions

| Activity name | What it does |
|---|---|
| `activities.platform.comment` | Posts the verdict comment on the PR |
| `activities.platform.merge_pr` | Auto-merges the PR |
| `activities.platform.close_pr` | Closes the PR with a reason |
| `activities.platform.label` | Adds a label to the PR |
| `activities.platform.request_review` | Requests review from configured reviewers |
| `activities.platform.check_pr_files` | Checks whether the PR touches unexpected files (CI scripts, Dockerfiles) |
| `activities.platform.fetch_repo_config` | Fetches `.github/dependency-scout.yml` from the target repo |

These are thin wrappers around `PlatformClient` (from `platforms/`) that give each operation a stable, platform-neutral activity name. The actual platform (GitHub, GitLab, ...) is determined at runtime from `pr.platform`.
