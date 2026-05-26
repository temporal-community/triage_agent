#!/usr/bin/env python3
"""
One-command setup for Dependency Scout.

Checks prerequisites, collects credentials interactively, writes .env,
and prints the repo config snippet to paste into your target repo.

Usage:
    uv run python setup.py
"""

from __future__ import annotations

import secrets
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

from dotenv import dotenv_values

HERE = Path(__file__).parent
ENV_FILE = HERE / ".env"
ENV_EXAMPLE = HERE / ".env.example"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BOLD = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
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
    if not shutil.which("temporal"):
        _warn(
            "temporal CLI not found — needed for local dev server; not required for Temporal Cloud\n"
            "     install: https://docs.temporal.io/cli  (brew install temporal)"
        )
    else:
        _ok("temporal found")
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
    print(
        textwrap.dedent("""
  The Scout needs GitHub access to read PR files and post comments.

  PAT (Personal Access Token) — pick this if:
    • You're trying this out on your own repos right now
    • You just want to see it work before committing to a full setup
  Downside: the token is tied to YOUR account. If you leave the org,
  or the token expires, the bot silently stops working. It also gets
  broad repo access — not just the repos you care about.

  GitHub App — pick this if:
    • You want this running reliably in production
    • You're installing it across an org or multiple repos
    • You don't want a personal account to be a single point of failure
  The App has its own identity (not tied to any person), auto-rotating
  credentials, and you grant it access only to the repos it needs.
  Takes about 10 extra minutes to set up.

  Not sure? Start with a PAT. You can switch to an App later.
    """)
    )

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
    print(
        textwrap.dedent("""
  Creating a GitHub App:

  1. Go to: https://github.com/settings/apps/new
     (or https://github.com/organizations/YOUR-ORG/settings/apps/new for an org)

  2. Fill in:
       App name:        dependency-scout (or any name)
       Homepage URL:    https://github.com/temporal-community/dependency-scout
       Webhook URL:     https://placeholder.example.com/webhook  (you'll update this in step 5 below)
       Webhook secret:  (generate one below — copy it into this form)

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
    """)
    )

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


def _ask_menu(prompt: str, options: list[tuple[str, str]], allow_zero: bool = True) -> int:
    """Display a numbered menu and return the 1-based choice, or 0 for 'skip'."""
    print(f"\n  {BOLD}{prompt}{RESET}\n")
    for i, (label, description) in enumerate(options, start=1):
        print(f"    {BOLD}{i}){RESET} {CYAN}{label}{RESET} — {description}")
    if allow_zero:
        print(f"    {BOLD}0){RESET} Skip")
    print()
    while True:
        raw = _ask(f"Enter choice (0–{len(options)})", default="0")
        try:
            choice = int(raw)
            if (allow_zero and 0 <= choice <= len(options)) or (
                not allow_zero and 1 <= choice <= len(options)
            ):
                return choice
        except ValueError:
            pass
        _err(f"Please enter a number between {'1' if not allow_zero else '0'} and {len(options)}")


def collect_optional_keys() -> dict[str, str]:
    _h("Optional extras")
    print(
        textwrap.dedent("""
  The Scout works without any of these. Each one unlocks more capability.
    """)
    )

    result: dict[str, str] = {}

    # --- LLM classifier ---
    llm_choice = _ask_menu(
        "Which LLM should the Scout use to classify dependency bumps?",
        [
            ("Claude  (Anthropic)", "best supply chain reasoning — claude.ai/settings/api-keys"),
            ("OpenAI  (GPT-4o)   ", "strong alternative        — platform.openai.com/api-keys"),
            ("Ollama  (local)    ", "free, runs on your machine, no data leaves"),
            (
                "Other              ",
                "any dependency_scout.classifiers plugin — set CLASSIFIER manually",
            ),
        ],
    )

    if llm_choice == 1:
        key = _ask("Anthropic API key", secret=True)
        if key:
            result["ANTHROPIC_API_KEY"] = key
            result["ANTHROPIC_MODEL"] = "claude-sonnet-4-6"
    elif llm_choice == 2:
        key = _ask("OpenAI API key", secret=True)
        if key:
            result["OPENAI_API_KEY"] = key
            result["CLASSIFIER"] = "openai"
        model = _ask("OpenAI model ID (see platform.openai.com/docs/models)")
        if model:
            result["OPENAI_MODEL"] = model
        else:
            _warn("No model set — add OPENAI_MODEL to .env before starting the worker.")
    elif llm_choice == 3:
        host = _ask("Ollama host", default="http://localhost:11434")
        model = _ask("Ollama model (must be pulled locally)", default="llama3.2")
        result["OLLAMA_HOST"] = host
        result["OLLAMA_MODEL"] = model
        result["CLASSIFIER"] = "ollama"
        _warn("Make sure Ollama is running and the model is pulled before starting the worker.")
    elif llm_choice == 4:
        name = _ask("CLASSIFIER entry point name")
        if name:
            result["CLASSIFIER"] = name
        key_var = _ask("API key env var name (blank to skip)", default="")
        if key_var:
            key_val = _ask(f"Value for {key_var}", secret=True)
            if key_val:
                result[key_var] = key_val

    # --- Socket.dev ---
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
    print(
        textwrap.dedent("""
  Add this file to any repo where you want the Scout to do more than comment.
  (Without it, the Scout posts comments but never auto-merges or blocks.)

  Create .github/dependency-scout.yml:
    """)
    )
    snippet = textwrap.dedent("""\
    # .github/dependency-scout.yml
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


def print_next_steps(used_app: bool, temporal_mode: str = "local") -> None:
    _h("You're set up. Next steps:")

    if temporal_mode == "cloud":
        temporal_step = textwrap.dedent("""\
  1. Your worker will connect to Temporal Cloud automatically using the TLS
     credentials in .env — no local server needed. Skip to step 2.
    """)
        workflow_ui = "https://cloud.temporal.io"
    elif temporal_mode == "local":
        temporal_step = textwrap.dedent("""\
  1. Start Temporal (in a separate terminal):
       temporal server start-dev
    """)
        workflow_ui = "http://localhost:8233"
    else:
        temporal_step = textwrap.dedent("""\
  1. Start Temporal (configure TEMPORAL_ADDRESS etc. in .env first):
       temporal server start-dev   # local dev
       # — or — connect to Temporal Cloud (see .env.example for TLS vars)
    """)
        workflow_ui = "http://localhost:8233"

    if used_app:
        webhook_registration = textwrap.dedent("""\
  5. Wire the webhook URL into your GitHub App:
       a. Go to: https://github.com/settings/apps  (or your org's /settings/apps)
       b. Click your app → "General" tab
       c. Under "Webhook", set:
            Webhook URL:    https://<your-ngrok-id>.ngrok-free.app/webhook
            Webhook secret: (already set during app creation — must match GITHUB_WEBHOOK_SECRET in .env)
       d. Save changes.
       e. Open the "Permissions & events" tab and confirm "Pull requests" is checked under Subscribe to events.
    """)
    else:
        webhook_registration = textwrap.dedent("""\
  5. Register the webhook in each repo you want to monitor:
       a. Go to: https://github.com/OWNER/REPO/settings/hooks/new
          (replace OWNER/REPO with your repo — repeat for each repo)
       b. Fill in:
            Payload URL:    https://<your-ngrok-id>.ngrok-free.app/webhook
            Content type:   application/json
            Secret:         (copy GITHUB_WEBHOOK_SECRET from your .env)
            Events:         ✓ Pull requests   (select "Let me select individual events")
       c. Click "Add webhook". GitHub will send a ping — a ✓ means it's wired.
    """)

    print(
        textwrap.dedent(f"""
  {temporal_step.strip()}

  2. Start the worker (in a separate terminal):
       uv run python -m worker

  3. Test a triage run against a real Dependabot PR (no webhook needed):
       uv run python -m start_workflow https://github.com/your-org/your-repo/pull/123

     Watch the run at: {workflow_ui}

  4. To receive live Dependabot webhooks, expose the API server:
       uv run uvicorn api.webhook:app --port 8080
       ngrok http 8080   # note the https:// URL it prints

    """)
        + webhook_registration
    )


def collect_temporal_config() -> tuple[dict[str, str], str]:
    """Returns (env_dict, mode) where mode is 'local', 'cloud', or 'skip'."""
    _h("Temporal — job queue and state store")
    print(
        textwrap.dedent("""
  The Scout uses Temporal to run signal-gathering jobs reliably. Choose how
  you want to run it:

  Local dev server — pick this if:
    • You're trying things out locally right now
    • You don't want to sign up for anything
  Run `temporal server start-dev` in a separate terminal. State is in-memory;
  it resets when you stop the server.

  Temporal Cloud — pick this if:
    • You want the Scout running 24/7 without a server to babysit
    • You're deploying to production
  Free tier available at https://cloud.temporal.io (no credit card).
  State is durable; restarts and failures are handled for you.
    """)
    )

    choice = _ask_menu(
        "Which Temporal setup are you using?",
        [
            ("Local dev server", "temporal server start-dev — easiest to get started"),
            ("Temporal Cloud", "fully managed, no infrastructure to maintain"),
        ],
    )

    if choice == 0:
        _warn("Skipping Temporal config — edit .env manually before starting the worker")
        return {
            "TEMPORAL_ADDRESS": "localhost:7233",
            "TEMPORAL_NAMESPACE": "default",
            "TEMPORAL_TASK_QUEUE": "dependency-triage",
            "TEMPORAL_UI_BASE_URL": "http://localhost:8233",
        }, "skip"

    if choice == 1:
        return {
            "TEMPORAL_ADDRESS": "localhost:7233",
            "TEMPORAL_NAMESPACE": "default",
            "TEMPORAL_TASK_QUEUE": "dependency-triage",
            "TEMPORAL_UI_BASE_URL": "http://localhost:8233",
        }, "local"

    # Temporal Cloud
    print(
        textwrap.dedent("""
  To connect to Temporal Cloud you need:
    1. A namespace — create one at https://cloud.temporal.io
    2. A TLS client certificate + private key for that namespace
       (generate via the Certificates page in the Cloud UI, or bring your own)
    """)
    )
    namespace = _ask("Temporal Cloud namespace (e.g. mynamespace.abc12)")
    default_address = (
        f"{namespace}.tmprl.cloud:7233" if namespace else "your-namespace.tmprl.cloud:7233"
    )
    address = _ask("Temporal Cloud address", default=default_address)
    cert_path = _ask("Path to TLS client certificate (.pem)")
    key_path = _ask("Path to TLS private key (.pem)")

    return {
        "TEMPORAL_ADDRESS": address,
        "TEMPORAL_NAMESPACE": namespace,
        "TEMPORAL_TASK_QUEUE": "dependency-triage",
        "TEMPORAL_UI_BASE_URL": "https://cloud.temporal.io",
        "TEMPORAL_TLS_CERT": cert_path,
        "TEMPORAL_TLS_KEY": key_path,
    }, "cloud"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print(f"\n{BOLD}Dependency Scout — setup{RESET}")
    print("=" * 42)

    if ENV_FILE.exists():
        print()
        _warn(".env already exists")
        if not _ask_yn("Overwrite it?", default=False):
            _ok("Keeping existing .env — skipping credential setup.")
            if not check_prerequisites():
                sys.exit(1)
            existing = dotenv_values(ENV_FILE)
            used_app = "GITHUB_APP_ID" in existing
            temporal_mode = "cloud" if existing.get("TEMPORAL_TLS_CERT") else "local"
            print_repo_config()
            print_next_steps(used_app, temporal_mode)
            return

    if not check_prerequisites():
        sys.exit(1)

    install_dependencies()

    github = collect_github_credentials()
    used_app = "GITHUB_APP_ID" in github
    optional = collect_optional_keys()
    temporal, temporal_mode = collect_temporal_config()

    write_env({**temporal, **github, **optional})
    print_repo_config()
    print_next_steps(used_app, temporal_mode)


if __name__ == "__main__":
    main()
