#!/usr/bin/env python3
"""
One-command setup for Dependabot Supply Chain Scout.

Checks prerequisites, collects credentials interactively, writes .env,
and prints the repo config snippet to paste into your target repo.

Usage:
    uv run python setup.py
"""
from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

HERE = Path(__file__).parent
ENV_FILE = HERE / ".env"
ENV_EXAMPLE = HERE / ".env.example"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BOLD  = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED   = "\033[31m"
CYAN  = "\033[36m"
RESET = "\033[0m"


def _h(text: str) -> None:
    print(f"\n{BOLD}{CYAN}{text}{RESET}")


def _ok(text: str) -> None:
    print(f"  {GREEN}✓{RESET}  {text}")


def _warn(text: str) -> None:
    print(f"  {YELLOW}!{RESET}  {text}")


def _err(text: str) -> None:
    print(f"  {RED}✗{RESET}  {text}")


def _ask(prompt: str, default: str = "", secret: bool = False) -> str:
    """Prompt the user for input. Returns default if they just press Enter."""
    display = f"  {BOLD}{prompt}{RESET}"
    if default:
        display += f" [{default}]"
    display += ": "
    try:
        if secret:
            import getpass
            value = getpass.getpass(display)
        else:
            value = input(display)
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return value.strip() or default


def _ask_yn(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    raw = _ask(f"{prompt} ({hint})")
    if not raw:
        return default
    return raw.lower().startswith("y")


def _check_cmd(name: str, install_hint: str) -> bool:
    if shutil.which(name):
        _ok(f"{name} found")
        return True
    _err(f"{name} not found — {install_hint}")
    return False


def _run_silent(cmd: list[str]) -> bool:
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

def check_prerequisites() -> bool:
    _h("Checking prerequisites")
    ok = True
    ok &= _check_cmd("uv", "install from https://docs.astral.sh/uv/")
    ok &= _check_cmd("temporal", "install from https://docs.temporal.io/cli  (brew install temporal)")
    if not ok:
        print()
        _err("Please install missing tools and re-run setup.py")
    return ok


def install_dependencies() -> None:
    _h("Installing Python dependencies")
    if _run_silent(["uv", "sync"]):
        _ok("dependencies installed")
    else:
        _warn("uv sync failed — you may need to run it manually")


def collect_github_credentials() -> dict[str, str]:
    """Returns a dict of env key → value for GitHub credentials."""
    _h("GitHub credentials")
    print(textwrap.dedent("""
  The Scout needs GitHub access to read PR files and post comments.
  There are two options:

    1. Personal Access Token (PAT) — easiest for local testing
       Create one at: https://github.com/settings/tokens/new
       Scopes needed: repo (full), read:org (if your repos are in an org)

    2. GitHub App — required for production use across multiple repos
       Gives per-repo permissions, no broad PAT exposure.
    """))

    use_app = _ask_yn("Set up a GitHub App instead of a PAT?", default=False)

    if not use_app:
        token = _ask("Paste your GitHub PAT (or leave blank to skip)", secret=True)
        webhook_secret = secrets.token_hex(32)
        return {
            "GITHUB_TOKEN": token,
            "GITHUB_WEBHOOK_SECRET": webhook_secret,
            "ENABLE_PR_ACTIONS": "false",
        }

    # GitHub App flow
    print(textwrap.dedent("""
  Creating a GitHub App:

  1. Go to: https://github.com/settings/apps/new
     (or https://github.com/organizations/YOUR-ORG/settings/apps/new for an org)

  2. Fill in:
       App name:        dependabot-supply-chain-scout (or any name)
       Homepage URL:    https://github.com/temporal-community/triage-agent
       Webhook URL:     your ngrok/public URL + /webhook  (set up later)
       Webhook secret:  (generate one below)

  3. Permissions — Repository permissions:
       Contents:        Read-only
       Issues:          Read & write  (for PR comments)
       Metadata:        Read-only
       Pull requests:   Read & write

  4. Subscribe to events:  Pull request

  5. Click "Create GitHub App"

  6. On the next page: note your App ID, then click
     "Generate a private key" and save the .pem file.

  7. Install the App on your repos (or "All repositories").
    """))

    webhook_secret = secrets.token_hex(32)
    print(f"  {BOLD}Generated webhook secret (copy this into the GitHub App form):{RESET}")
    print(f"  {CYAN}{webhook_secret}{RESET}\n")

    app_id = _ask("GitHub App ID (from the App settings page)")
    pem_path = _ask("Path to the downloaded .pem private key file")
    installation_id = _ask("Installation ID (visible in the App → Install page URL)", default="")

    credentials = {
        "GITHUB_APP_ID": app_id,
        "GITHUB_APP_PRIVATE_KEY_PATH": pem_path,
        "GITHUB_WEBHOOK_SECRET": webhook_secret,
        "ENABLE_PR_ACTIONS": "false",
    }
    if installation_id:
        credentials["GITHUB_APP_INSTALLATION_ID"] = installation_id
    return credentials


def collect_optional_keys() -> dict[str, str]:
    _h("Optional API keys")
    print(textwrap.dedent("""
  These are optional. The Scout works without them — you'll just get
  fewer signals and rule-based classification instead of Claude.
    """))

    result: dict[str, str] = {}

    if _ask_yn("Add an Anthropic API key? (enables Claude classifier)", default=False):
        key = _ask("Anthropic API key", secret=True)
        if key:
            result["ANTHROPIC_API_KEY"] = key
            result["ANTHROPIC_MODEL"] = "claude-sonnet-4-6"

    if _ask_yn("Add a Socket.dev API key? (adds supply-chain score signal)", default=False):
        key = _ask("Socket API key", secret=True)
        if key:
            result["SOCKET_API_KEY"] = key

    return result


def write_env(values: dict[str, str]) -> None:
    _h("Writing .env")

    # Read the example as the canonical template, then overlay collected values.
    template = ENV_EXAMPLE.read_text() if ENV_EXAMPLE.exists() else ""

    # Build a merged set — template defaults + user-supplied values.
    merged: dict[str, str] = {}
    for line in template.splitlines():
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            merged[k.strip()] = v.strip()
    merged.update(values)

    # Write back in template order, then append any keys not in the template.
    template_keys: list[str] = []
    output_lines: list[str] = []
    for line in template.splitlines():
        stripped = line.strip()
        if "=" in stripped and not stripped.startswith("#"):
            k = stripped.split("=", 1)[0].strip()
            template_keys.append(k)
            output_lines.append(f"{k}={merged.get(k, '')}")
        else:
            output_lines.append(line)

    # Append any extra keys the user supplied that aren't in the template.
    extras = [k for k in merged if k not in template_keys]
    if extras:
        output_lines.append("")
        for k in extras:
            output_lines.append(f"{k}={merged[k]}")

    ENV_FILE.write_text("\n".join(output_lines) + "\n")
    _ok(f".env written to {ENV_FILE}")

    if "GITHUB_TOKEN" in values and values["GITHUB_TOKEN"]:
        _warn(".env contains a secret token — it's in .gitignore but be careful")


def print_repo_config() -> None:
    _h("Repo config snippet")
    print(textwrap.dedent("""
  Add this file to any repo where you want the Scout to do more than comment.
  (Without it, the Scout posts comments but never auto-merges or blocks.)

  Create .github/triage-agent.yml:
    """))
    snippet = textwrap.dedent("""\
    # .github/triage-agent.yml
    # Remove or comment out any section you don't want.

    # Auto-merge green verdicts (safe, well-established packages, no flags)
    auto_merge_enabled: true
    auto_merge_classifications: [green]

    # Request human review on yellow verdicts (add your GitHub usernames)
    # reviewers: [alice, bob]

    # Minimum release age before auto-merge kicks in (default: 168h = 7 days)
    # min_release_age_hours: 168

    # Flag as yellow if a bump adds more than this many new direct dependencies
    # max_new_dependencies: 5

    # Close the PR and add a label on red verdicts
    # block_classifications: [red]
    """)
    for line in snippet.splitlines():
        print(f"    {CYAN}{line}{RESET}")


def print_next_steps(used_app: bool) -> None:
    _h("You're set up. Next steps:")
    print(textwrap.dedent(f"""
  1. Start Temporal (in a separate terminal):
       temporal server start-dev

  2. Start the worker (in a separate terminal):
       uv run python -m worker

  3. Test a triage run against a real public package:
       uv run python -m start_workflow \\
         --repo temporalio/ai-cookbook \\
         --package idna --old-version 3.11 --new-version 3.15 \\
         --pr-number 122

     Watch the run at: http://localhost:8233

  4. To receive live Dependabot webhooks:
       uv run uvicorn api.webhook:app --port 8080
       ngrok http 8080  # then paste the HTTPS URL into GitHub → Settings → Webhooks
    {'5. Register the webhook URL in your GitHub App settings.' if used_app else ''}
    """))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print(f"\n{BOLD}Dependabot Supply Chain Scout — setup{RESET}")
    print("=" * 42)

    if ENV_FILE.exists():
        print()
        _warn(".env already exists")
        if not _ask_yn("Overwrite it?", default=False):
            print("  Aborted.")
            sys.exit(0)

    if not check_prerequisites():
        sys.exit(1)

    install_dependencies()

    github = collect_github_credentials()
    used_app = "GITHUB_APP_ID" in github
    optional = collect_optional_keys()

    temporal_defaults = {
        "TEMPORAL_ADDRESS": "localhost:7233",
        "TEMPORAL_NAMESPACE": "default",
        "TEMPORAL_TASK_QUEUE": "dependency-triage",
        "TEMPORAL_UI_BASE_URL": "http://localhost:8233",
    }

    write_env({**temporal_defaults, **github, **optional})
    print_repo_config()
    print_next_steps(used_app)


if __name__ == "__main__":
    main()
