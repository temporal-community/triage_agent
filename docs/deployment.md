# Deployment Guide

This guide covers running the Scout in production — secrets management, Temporal server options, webhook ingress, and monitoring. For local dev, `uv run python setup.py` is all you need.

Before going to production, read [security.md](security.md) — it covers GitHub token scoping, auto-merge confidence thresholds, and prompt injection hardening.

For a description of the three-process architecture (Temporal server, worker, webhook API), see [architecture.md](architecture.md).

---

## Temporal server

### Option A — Local dev server (start here)

No account, no payment, no sign-up. The Temporal CLI ships a built-in dev server that runs entirely on your machine:

```bash
temporal server start-dev
```

Open **http://localhost:8233** to watch workflows run in the Temporal UI. The dev server uses in-memory storage — workflow history is lost on restart, which is fine for personal use and local testing. When you're ready for durability across restarts, see Option B or C below.

### Option B — Temporal Cloud (optional, for production)

[Temporal Cloud](https://cloud.temporal.io) pre-loads new accounts with credits, which covers low-volume use for a while. No servers to manage, built-in visibility UI.

1. Create a namespace in the Temporal Cloud UI
2. Download your client certificate (`.pem`) and key
3. Set in `.env`:

```env
TEMPORAL_ADDRESS=your-namespace.tmprl.cloud:7233
TEMPORAL_NAMESPACE=your-namespace.your-account
TEMPORAL_TLS_CERT=/path/to/client.pem
TEMPORAL_TLS_KEY=/path/to/client.key
```

### Option C — Self-hosted with Docker Compose

The included `docker-compose.yml` runs a single-node Temporal server suitable for personal use or small teams (a few dozen repos). It uses the in-memory default store — **data is lost on restart**. For durability, add a PostgreSQL backend:

```yaml
# In docker-compose.yml, add to the temporal service:
environment:
  - DB=postgresql
  - DB_PORT=5432
  - POSTGRES_USER=temporal
  - POSTGRES_PWD=temporal
  - POSTGRES_SEEDS=postgres
```

For larger deployments, see the [Temporal self-hosting docs](https://docs.temporal.io/self-hosted-guide).

---

## Secrets management

### Required secrets

| Variable | What it's for |
|---|---|
| `GITHUB_WEBHOOK_SECRET` | HMAC-SHA256 webhook verification — **required**, no fallback |
| `GITHUB_APP_ID` + `GITHUB_APP_PRIVATE_KEY_PATH` | GitHub App credentials for posting comments and taking actions |

### Optional secrets (unlock more checks)

| Variable | What changes without it |
|---|---|
| `ANTHROPIC_API_KEY` | Falls back to rule-based classifier |
| `GITHUB_TOKEN` | Can't post comments or auto-merge (observe-only) |
| `SOCKET_API_KEY` | Socket.dev supply-chain score check is skipped |

### Where to store them

**Docker Compose** — `.env` file (already in `.gitignore`). For production, use Docker secrets:

```yaml
secrets:
  github_webhook_secret:
    external: true
services:
  webhook:
    secrets: [github_webhook_secret]
    environment:
      GITHUB_WEBHOOK_SECRET_FILE: /run/secrets/github_webhook_secret
```

Then read it in a startup shim: `GITHUB_WEBHOOK_SECRET=$(cat $GITHUB_WEBHOOK_SECRET_FILE)`.

**Kubernetes** — use `kubectl create secret generic scout-secrets --from-env-file=.env` and mount as environment variables. Never bake secrets into the image.

**GitHub App private key** — the PEM can be passed inline (no file path needed in containerised deployments):

```env
GITHUB_APP_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----
```

---

## Webhook ingress

The webhook API must be reachable from GitHub's IP ranges over HTTPS.

### Local testing with ngrok (start here)

Before setting up a real server, test end-to-end on your laptop:

```bash
# Terminal 1 — Temporal dev server
temporal server start-dev

# Terminal 2 — Scout worker
uv run python -m worker

# Terminal 3 — webhook API
uv run uvicorn api.webhook:app --port 8080

# Terminal 4 — expose it to the internet
ngrok http 8080
```

ngrok prints a line like `Forwarding https://abc123.ngrok-free.app -> localhost:8080` — that's your webhook URL.

**Register the webhook:**

- **PAT users:** go to `https://github.com/OWNER/REPO/settings/hooks/new` for each repo you want to monitor. Fill in:
  - Payload URL: `https://abc123.ngrok-free.app/webhook`
  - Content type: `application/json`
  - Secret: copy `GITHUB_WEBHOOK_SECRET` from your `.env`
  - Events: select "Let me select individual events" → tick **Pull requests**

- **GitHub App users:** go to `https://github.com/settings/apps/YOUR-APP` → General → Webhook URL: `https://abc123.ngrok-free.app/webhook`. GitHub will send a ping — a ✓ means it's wired.

When a new Dependabot PR opens, GitHub will POST to ngrok → your local API → Temporal → worker. Watch it at **http://localhost:8233**.

---

### Production ingress

When you're ready to run 24/7 without a laptop, swap ngrok for a real reverse proxy.

### Reverse proxy (nginx / Caddy)

```nginx
server {
    listen 443 ssl;
    server_name scout.yourdomain.com;

    location /webhook {
        proxy_pass http://localhost:8080/webhook;
        proxy_set_header X-Real-IP $remote_addr;
    }
    location /healthz {
        proxy_pass http://localhost:8080/healthz;
    }
}
```

[Caddy](https://caddyserver.com) handles TLS automatically:

```
scout.yourdomain.com {
    reverse_proxy localhost:8080
}
```

### GitHub webhook configuration (production)

Same as the ngrok setup above, but use your real domain instead:

- **PAT users:** update each repo's webhook URL to `https://scout.yourdomain.com/webhook`
- **GitHub App users:** update the Webhook URL in your App settings to `https://scout.yourdomain.com/webhook`

GitHub retries failed webhook deliveries with exponential backoff — the Scout returns 200 immediately (before the workflow completes), so delivery failures only happen if the webhook API is down.

---

## Health monitoring

### `/healthz` endpoint

```bash
curl https://scout.yourdomain.com/healthz
# {"status": "ok", "temporal_connected": true}
```

Set up an uptime monitor (UptimeRobot, Better Uptime, etc.) on `/healthz`. A `temporal_connected: false` response means the worker can't pick up work.

### Logs

The webhook API and worker both log to stdout/stderr in structured format:

```
INFO uvicorn: Started server process
INFO worker: Worker started — task_queue=dependency-scout temporal=localhost:7233 activities=12
INFO api.webhook: Started workflow pr-action-myorg-myrepo-123 for myorg/myrepo#123 (pip requests 2.31.0→2.32.0)
WARNING api.webhook: Could not parse package/version from PR title — skipping myorg/myrepo#124. Title: 'Update CI'
```

`WARNING` and above indicate something worth investigating. `INFO` is routine operational traffic.

### Temporal UI

The Temporal Web UI (port 8233 locally, or Temporal Cloud UI) shows every workflow run, its status, and full event history. This is the first place to look when a PR didn't get a comment.

---

## Scaling

The webhook API and worker are stateless. To handle more concurrent workflows:

- Run multiple worker replicas — they compete for tasks on the same task queue; Temporal load-balances automatically
- Scale the webhook API independently — it only starts workflows, not run them
- The bottleneck at scale is typically external API rate limits (GitHub, OSV, Socket), not compute

```bash
# Example: 3 workers
docker compose up --scale worker=3
```

No configuration change needed — each worker discovers the same task queue from `TEMPORAL_TASK_QUEUE`.

---

## Updating

```bash
git pull
docker compose build
docker compose up -d
```

Temporal workflows are durable — in-flight workflows survive a worker restart and resume where they left off once the new worker comes up.
