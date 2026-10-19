# NetGuard AI - Complete Project Context

Last reviewed: 2026-10-10
Branch: `feature/embeddable-sdk`
Current package version: `0.2.0`

## Project Goal

NetGuard AI is a Python network and application intrusion detection project. Its primary product goal is an importable Python SDK that can be added to a specific web application and monitor that application's HTTP traffic without administrator privileges.

The intended developer experience is:

```python
from fastapi import FastAPI
from netguard import NetGuard
from netguard.integrations.fastapi import setup_netguard

app = FastAPI()
guard = NetGuard(project_id="my-app", auth_username="admin", auth_password="secret")
setup_netguard(app, guard)
```

The project also preserves host-level NIDS functionality for offline PCAP analysis, model training, evaluation, and privileged live packet capture.

## Current Stage

The core SDK, application rules, embedded dashboard, standalone dashboard, reverse proxy, notification, Django, and packaging slices are implemented.

Current verification:

```text
75 tests passed
0 warnings
```


Both editable install roots work:

```powershell
python -m pip install -e . --no-deps
python -m pip install -e .\nids-project --no-deps
```

The bundled model loads from an unrelated working directory.

## Repository Layout

```text
D:\nids-project\
├── pyproject.toml                  # outer install configuration
├── .env.example                    # safe configuration template
├── .gitignore                      # secrets, caches, logs, egg-info
├── context.md                      # this handoff document
├── CONTEXT.md                      # earlier context snapshot
└── nids-project\
    ├── pyproject.toml              # inner install configuration
    ├── README.md
    ├── app/streamlit_app.py        # flow-model Streamlit demo
    ├── data/                        # datasets and captures
    ├── examples/fastapi_demo/      # protected app and traffic simulator
    ├── models/                      # training output directory
    ├── netguard/
    │   ├── core.py                  # canonical NetGuard SDK
    │   ├── detection.py             # saved-model loading and prediction
    │   ├── rules.py                 # deterministic HTTP rules
    │   ├── aggregator.py            # HTTP-to-flow feature aggregation
    │   ├── alerts.py                # severity, history, callbacks, delivery
    │   ├── auth.py                  # Basic Auth and bearer API keys
    │   ├── config.py                # environment and SDK configuration
    │   ├── digest.py                # weekly digest scheduler
    │   ├── proxy.py                 # unprivileged reverse proxy
    │   ├── integrations/             # FastAPI, Flask, and Django adapters
    │   ├── notifier/                 # email, webhook, and dashboard delivery
    │   ├── web/                      # embedded and standalone dashboards
    │   └── models/                   # bundled model, scaler, metadata
    ├── src/                         # original training/evaluation modules
    ├── tests/                       # unit and integration tests
    └── tools/generate_synthetic_pcap.py
```

## Implemented Functionality

### Detection engine

`DetectionEngine` loads `best_model.pkl`, `scaler.pkl`, and `metadata.json`. It supports bundled model discovery, custom model directories, missing-feature defaults, single predictions, batch predictions, probabilities, and `PredictionResult` values with a detection source.

The bundled model has 20 CICIDS-style flow features and classes such as `BENIGN`, `DDoS`, `DoS`, `PortScan`, `BruteForce`, and web attack classes.

Important limitation: the model was trained on network-flow data, not a validated web-application dataset. HTTP middleware creates approximate flow features from request and response sizes. Deterministic HTTP rules are the primary web-attack detector.

### Application rules

`ApplicationRuleEngine` detects:

- SQL injection
- XSS
- Path traversal
- Failed-auth bursts on authentication paths
- Sensitive-path scans such as `/.env`, `/.git/config`, and `/wp-login.php`
- DoS request bursts: 25 requests within 2 seconds

Rule results use the same `PredictionResult` and `Alert` structures as ML results, with identifiers such as `http.sqli` and `http.request_burst`.

Failed-auth detection is restricted to paths containing terms such as `/login`, `/auth`, `/token`, `/session`, or `/password`. A normal API endpoint returning `403` is not automatically classified as BruteForce.

### NetGuard core

`NetGuard` owns model loading, HTTP aggregation, rule evaluation, telemetry, IP blocking, alert callbacks, notifiers, flow flushing, and digest scheduling. Core telemetry includes requests, predictions, scored flows, active flows, attacks, attack labels and severities, recent benign/attack events, top client IPs, request rates, and blocked-client state.

### Framework integrations

- FastAPI and Starlette ASGI middleware
- Flask request hooks
- Optional Django middleware
- Unprivileged HTTP reverse proxy mode

`setup_netguard(app, guard)` installs the FastAPI middleware and mounts the authenticated dashboard by default. The ASGI lifespan middleware flushes flows at shutdown without deprecated FastAPI event hooks.

### Embedded dashboard

The authenticated dashboard is mounted at `/netguard/` by default:

```text
/netguard/
/netguard/health
/netguard/api/stats
/netguard/api/alerts
/netguard/api/block-ip
/netguard/api/events
/netguard/ws
```

It provides threat level, request counts, attack counts, blocked clients, traffic timelines, classifications, benign/attack event streams, top clients, manual block/unblock actions, and WebSocket telemetry. Dashboard access supports HTTP Basic Auth and bearer API keys.

### Standalone multi-project dashboard

Run:

```powershell
netguard serve `
  --port 8787 `
  --auth-username admin `
  --auth-password secret `
  --storage netguard-projects.sqlite3
```

The server stores bounded per-project alert history and the latest app telemetry snapshot in SQLite WAL mode. It exposes `/api/projects`, `/api/stats?project_id=my-app`, `/api/alerts?project_id=my-app`, `/api/events`, `/api/telemetry`, and `/ws?project_id=my-app`. Existing default JSON data is imported into `netguard-projects.sqlite3` when that database is first created. Passing a legacy JSON file with `--storage` migrates it in place. Configure each app with `dashboard_mode="separate"` or `"both"` and `NETGUARD_DASHBOARD_URL` so it publishes traffic and client activity. The standalone dashboard includes project selection.

HTTP rule alerts have per-client, per-rule cooldowns, defaulting to 30 or 60 seconds by rule. Repeated detections remain visible in recent events with `alert_suppressed: true`, while duplicate alert delivery is suppressed. Configure overrides with `NETGUARD_RULE_COOLDOWNS` as a JSON object of rule IDs and cooldown seconds.

### Reverse proxy

```powershell
netguard proxy `
  --target http://127.0.0.1:3000 `
  --port 8080 `
  --project-id my-app `
  --auth-username admin `
  --auth-password secret
```

The proxy requires no raw sockets or Administrator privileges, forwards HTTP traffic using `httpx`, measures proxied traffic, mounts the dashboard, and returns `502 Bad Gateway` when the upstream cannot be reached.

### Notifications and email

Available delivery mechanisms:

- Console alerts
- JSON Lines logs
- Gmail-compatible SMTP email
- Generic webhooks
- Discord and Slack payloads
- Standalone dashboard event delivery
- Python callbacks

Instant email is independent of dashboard viewing. It is sent when SMTP is fully configured and an alert meets the minimum severity.

```powershell
$env:NETGUARD_ALERT_EMAIL = "recipient@gmail.com"
$env:NETGUARD_SMTP_HOST = "smtp.gmail.com"
$env:NETGUARD_SMTP_PORT = "587"
$env:NETGUARD_SMTP_USER = "sender@gmail.com"
$env:NETGUARD_SMTP_PASSWORD = "gmail-app-password"
$env:NETGUARD_SMTP_FROM = "sender@gmail.com"
$env:NETGUARD_MIN_ALERT_SEVERITY = "LOW"
```

Use a Gmail App Password, never the normal Gmail password. Variables must be present in the process starting the app or proxy. `.env.local` is ignored but is not automatically loaded by Python.

Manual digest:

```powershell
netguard digest --send
```

Embedded scheduling:

```python
guard.start_digest_scheduler()
# During shutdown:
guard.stop_digest_scheduler()
```

### Existing NIDS workflows

```powershell
python -m netguard.cli --help
python -m netguard.cli info
python -m netguard.cli scan data/test_capture.pcap
python -m netguard.cli scan data/test_capture.pcap --log-file alerts.jsonl
python -m netguard.cli train
python -m netguard.cli evaluate
python -m netguard.cli dashboard
python -m netguard.cli monitor
python -m netguard.cli monitor-dashboard
streamlit run app/streamlit_app.py
```

Raw host capture requires Administrator privileges on Windows. It is separate from the no-admin middleware and proxy modes.

## Running the Main Demo

Start the upstream app from `D:\nids-project\nids-project`:

```powershell
..\.venv\Scripts\python.exe -m uvicorn `
  examples.fastapi_demo.main:app `
  --host 127.0.0.1 `
  --port 3000
```

The upstream dashboard is at `http://127.0.0.1:3000/netguard/`. Start the proxy in a second terminal and use `http://127.0.0.1:8080/netguard/` for the proxy dashboard.

Run the simulator through the proxy:

```powershell
$env:NETGUARD_TARGET_URL = "http://127.0.0.1:8080"
..\.venv\Scripts\python.exe examples/fastapi_demo/simulate_traffic.py
```

The simulator sends benign traffic, SQL injection, XSS, path traversal, scanner traffic, and a concurrent DoS burst. Restart both app and proxy after code changes so stale blocked-IP state and old in-memory rule behavior are cleared.

## Current DoS Recognition Issue and Resolution

### Observed symptoms

- The terminal printed that a DoS burst was sent, but the dashboard remained benign.
- Many requests returned `403`.
- Normal `/api/products` requests appeared as BruteForce.
- Dashboard event rows showed `undefined` fields.
- The visible rate was approximately 2 requests per second.

### Root causes

1. The simulator originally sent requests sequentially.
2. Middleware evaluated rule timing after upstream responses completed rather than at request arrival.
3. `127.0.0.1` could already be blocked, causing all later requests to return `403`.
4. The old failed-auth rule classified every `401`/`403` response as a login failure, including ordinary API endpoints.
5. The dashboard originally received only alert rows and lacked stable benign event fields.
6. Existing processes retained old code and in-memory state until restarted.

### Implemented fixes

- DoS simulation uses concurrent requests.
- Rules use request-arrival timestamps.
- Failed-auth rules apply only to authentication paths.
- Blocked requests are still recorded as detector-visible `403` traffic.
- Benign events appear in dashboard telemetry.
- Dashboard rows have stable client, method, path, label, and status fields.
- Proxy upstream failures return `502` instead of an unhandled `500`.

Use this endpoint as the source of truth:

```powershell
curl.exe -u admin:secret `
  http://127.0.0.1:8080/netguard/api/stats
```

## Testing

Run all tests:

```powershell
cd D:\nids-project\nids-project
..\.venv\Scripts\python.exe -m pytest -q
```

Current result: **75 passed** (0 warnings).

Coverage includes model loading, packaging smoke tests (import, arbitrary cwd loading, FastAPI integration), configuration, aggregation, application rules, burst timing, FastAPI middleware, authentication, dashboard REST and WebSocket behavior, IP blocking, remote event ingestion, standalone project persistence, proxy forwarding, proxy failures, SMTP mocks, digest scheduling, and webhook mocks.


No real Gmail, Slack, Discord, or webhook calls are made by tests.

## Security and Production Boundaries

- Application middleware and proxy mode do not require Administrator privileges.
- Raw NIC capture still requires elevation on Windows.
- `X-Forwarded-For` is trusted and should only be trusted behind a known proxy.
- Dashboard and block actions require Basic Auth or a bearer API key.
- SMTP credentials and Gmail App Passwords must never be committed.
- Standalone JSON persistence is local-development storage only.
- Streamed response bodies are not fully modeled.
- CICIDS-trained ML features are approximations for HTTP traffic.
- External delivery needs stronger retry, backpressure, and observability for production.

## Future Plan

### Immediate hardening

1. Add notifier retry policies, bounded queues, delivery status, and failure metrics.
2. Add dashboard rate limiting, CSRF protection, trusted-proxy configuration, and configurable CORS.
3. Remove remaining test-client deprecation warnings and clean the scaler feature-name warning without suppressing useful diagnostics.
4. Add process-level smoke tests for upstream, proxy, and dashboard startup.

### Detection improvements

1. Train an application-level model using real and synthetic HTTP traffic.
2. Make rule thresholds configurable per project.
3. Add configurable rule thresholds and cross-process alert deduplication.
4. Add credential-stuffing, account-takeover, and login-failure rules.
5. Add normal API path/client baselines to reduce false positives.
6. Add feature and rule explanations to every alert.

### Dashboard improvements

1. Add project selection to the standalone dashboard UI.
2. Add pagination and filtering for large alert histories.
3. Persist request counters and top-offender telemetry.
4. Add alert acknowledgement, mute, escalation, and audit history.
5. Add project roles and moderator permissions.

### Notification improvements

1. Add dedicated Slack configuration and delivery tests.
2. Add digest previews and dry-run output.
3. Add weekly trend and top-client summaries.
4. Display notification delivery health in the dashboard.
5. Add Mailtrap/local SMTP development support.

### Framework and deployment improvements

1. Harden Django request-body and async support.
2. Add Docker Compose for app, proxy, dashboard, and persistence.
3. Add TLS termination and deployment documentation.
4. Publish a tested package to PyPI from one canonical packaging root.
5. Add CI for Windows, Linux, and macOS on Python 3.11 and 3.12.

### Optional host agent

Keep raw packet capture as a separate optional infrastructure agent. It may eventually run as a Windows service or Linux systemd service and send events to the standalone dashboard, but it should not be required by ordinary web-app users.
