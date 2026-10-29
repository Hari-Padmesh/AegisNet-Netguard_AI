# NetGuard

NetGuard is an embeddable HTTP threat monitoring SDK for Python applications. It observes requests handled by an instrumented application, combines application-layer security rules with a bundled machine-learning model, and can show alerts in an authenticated dashboard or forward them to a centralized NetGuard Cloud account.

> NetGuard monitors traffic that reaches a running, instrumented application or passes through its proxy.

## Project links

- **PyPI package:** [netguard-threat-monitor](https://pypi.org/project/netguard-threat-monitor)
- **NetGuard Cloud dashboard:** [https://netguard-dashboard-nlo8.onrender.com](https://netguard-dashboard-nlo8.onrender.com)
- **Documentation website:** [NetGuard documentation](https://aegisnet-netguard-ai.onrender.com)
- **Source documentation:** [docs/index.html](docs/index.html), [API reference](docs/reference.html), and [copy-ready coding-agent prompts](docs/prompts.html)
- **Cloud dashboard deployment and integration guide:** [centralised_dashboard/README.md](centralised_dashboard/README.md)
- **Package guide and project details:** [nids-project/README.md](nids-project/README.md)
- **License:** [MIT](LICENSE)

## What NetGuard does

- **HTTP request monitoring:** framework middleware records request metadata such as client IP, method, path, query string, status code, and approximate byte counts. Raw request bodies are not collected by default.
- **Application-layer detection:** rules look for patterns such as SQL injection, cross-site scripting, path traversal, sensitive-path probing, failed-login bursts, and request bursts. Rule cooldowns reduce repeated alerts for an ongoing match.
- **Machine-learning classification:** a bundled model scores aggregated traffic features and contributes attack labels and confidence to detection results. Detection is probabilistic; results depend on traffic, model artifacts, and thresholds.
- **Alert handling:** alerts can be written to the console/log, passed to callbacks, and sent through configured email or webhook channels. Alerts can also be forwarded to a self-hosted dashboard or NetGuard Cloud.
- **IP mitigation:** the embedded integration can reject requests from IPs explicitly blocked in the running process. Blocking is temporary and is not a replacement for a network firewall or a distributed edge protection service.
- **Dashboards:** choose an authenticated dashboard mounted in your app, a standalone dashboard service, or both. The standalone self-hosted project store uses SQLite; SQLite is part of Python's standard library.
- **Reverse proxy:** `netguard proxy` can sit in front of an HTTP upstream, inspect proxied requests, and apply NetGuard responses. It is an optional deployment mode.
- **Offline analysis and model tooling:** supported CLI commands scan PCAP files, report model information, train/evaluate models, and run live packet monitoring where the host permits packet capture.
- **Centralized multi-project monitoring:** NetGuard Cloud offers user accounts, registered FastAPI projects, per-project ingestion keys, event/telemetry storage in MongoDB Atlas, and a React/Vite dashboard.

## Install

NetGuard requires Python 3.11 or newer. The distribution name on PyPI is `netguard-threat-monitor`; Python imports and the command-line program use `netguard`.

```powershell
python -m pip install "netguard-threat-monitor[web]"
```

Install optional extras only for features you use:

```powershell
python -m pip install "netguard-threat-monitor[flask]"  # Flask extension
python -m pip install "netguard-threat-monitor[train]"  # training, evaluation, and PCAP tooling
```

The `[web]` extra includes FastAPI, Django, Uvicorn, and related web dependencies. For a source checkout, install from the repository root with `python -m pip install ".[web]"`.

## Quick start: FastAPI

Set dashboard credentials in your local shell or deployment secret manager. Do not place real credentials in source code or commit them.

```powershell
$env:NETGUARD_PROJECT_ID = "orders-api"
$env:NETGUARD_AUTH_USERNAME = "admin"
$env:NETGUARD_AUTH_PASSWORD = "replace-with-a-long-random-password"
```

Add NetGuard to the application:

```python
import os
from fastapi import FastAPI
from netguard import NetGuard
from netguard.integrations.fastapi import setup_netguard

app = FastAPI(title="Orders API")
guard = NetGuard(
    project_id=os.environ["NETGUARD_PROJECT_ID"],
    auth_username=os.environ["NETGUARD_AUTH_USERNAME"],
    auth_password=os.environ["NETGUARD_AUTH_PASSWORD"],
)
setup_netguard(app, guard)

@app.get("/")
async def home():
    return {"status": "ok"}
```

Run the app as usual, for example:

```powershell
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/netguard/` and sign in with the configured dashboard credentials. Use HTTPS and the hosting platform's secret manager in deployment. NetGuard's request middleware skips its own dashboard routes to avoid monitoring dashboard polling as application traffic.

### Configuration

You can configure NetGuard through `NetGuardConfig`, keyword arguments to `NetGuard`, or environment variables prefixed with `NETGUARD_`. Explicit Python configuration is useful when your application already has a secret manager:

```python
from netguard import NetGuard, NetGuardConfig

config = NetGuardConfig(
    project_id="orders-api",
    auth_username="admin",
    auth_password=secret_store.get("netguard-dashboard-password"),
    dashboard_mode="embedded",  # embedded | separate | both
    dashboard_path="/netguard",
    flow_window_seconds=30.0,
    min_alert_severity="LOW",
    attack_confidence_threshold=0.60,
)
guard = NetGuard(config=config)
```

Common environment settings:

| Variable | Purpose | Default / example |
|---|---|---|
| `NETGUARD_PROJECT_ID` | Name/identifier for this monitored app | `default` |
| `NETGUARD_MODEL_DIR` | Model artifact directory when supplying a custom model | bundled model if available |
| `NETGUARD_AUTH_USERNAME`, `NETGUARD_AUTH_PASSWORD` | Protect the embedded dashboard | Required as a pair, unless using API key auth |
| `NETGUARD_AUTH_API_KEY` | Alternative dashboard/API credential | unset |
| `NETGUARD_DASHBOARD_MODE` | `embedded`, `separate`, or `both` | `embedded` |
| `NETGUARD_DASHBOARD_URL` | Base URL for a self-hosted dashboard or Cloud API | `http://localhost:8787` |
| `NETGUARD_DASHBOARD_PATH` | Embedded dashboard mount path | `/netguard` |
| `NETGUARD_INGEST_KEY` | Project key for a centralized dashboard ingestion endpoint | unset |
| `NETGUARD_FLOW_WINDOW_SECONDS` | Request aggregation window | `30` |
| `NETGUARD_MIN_ALERT_SEVERITY` | Lowest severity dispatched to alert channels | `LOW` |
| `NETGUARD_ATTACK_CONFIDENCE_THRESHOLD` | ML attack confidence threshold | `0.60` |
| `NETGUARD_RULE_COOLDOWNS` | JSON object overriding per-rule cooldown seconds | built-in defaults |
| `NETGUARD_LOG_FILE` | Alert log path | `alerts.log` |
| `NETGUARD_CONSOLE_ALERTS` | Print alerts to console | `true` |

For the full environment-variable reference, see [docs/reference.html](docs/reference.html) and [nids-project/README.md](nids-project/README.md).

## Framework integrations

### FastAPI

Use `setup_netguard(app, guard)`. It adds ASGI request monitoring, mounts the authenticated dashboard by default, and starts/stops the configured weekly digest scheduler with the app lifecycle.

### Django

Install the `[web]` extra and follow the Django integration example in the [documentation](https://aegisnet-netguard-ai.onrender.com). The middleware attaches monitoring to requests handled by the Django process. Manage digest scheduling using a single external scheduler or the host application's lifecycle.

### Flask

Install the `[flask]` extra and use the separate Flask integration described in the [API reference](docs/reference.html). As with other integrations, NetGuard sees requests handled by that instrumented process.

Framework support and deployment details are documented on the [NetGuard docs site](https://aegisnet-netguard-ai.onrender.com).

## Dashboard options

### Embedded dashboard

The default `dashboard_mode="embedded"` mounts the authenticated dashboard at `/netguard/` inside the application. This is the simplest setup for monitoring one service.

### Self-hosted dashboard for multiple projects

Run a separate dashboard server with SQLite-backed project state:

```powershell
netguard serve --host 0.0.0.0 --port 8787 `
  --auth-username admin --auth-password "use-a-long-secret" `
  --storage .\netguard-projects.sqlite3
```

For each monitored app, set `NETGUARD_DASHBOARD_MODE=separate`, `NETGUARD_DASHBOARD_URL` to the dashboard server's reachable base URL, and configure matching ingestion authentication. Use `NETGUARD_AUTH_API_KEY` on both sides or the username/password credentials supported by the server. Keep the SQLite file on persistent storage in deployments; ephemeral filesystems can lose it when a service restarts. The standalone self-hosted dashboard is separate from NetGuard Cloud.

## NetGuard Cloud: connect an instrumented FastAPI app

NetGuard Cloud is a separate hosted control plane. It does not install itself into an application and cannot monitor an arbitrary URL. The application must run the NetGuard SDK, and its running process must be able to send telemetry to the Cloud API.

### Connection flow

1. Open the [NetGuard Cloud dashboard](https://netguard-dashboard-nlo8.onrender.com), create an account, and sign in.
2. Register a FastAPI app in the dashboard. Copy its project ID and one-time ingestion key when shown; store the key securely.
3. In the **FastAPI service's** deployment settings, add the project ID, ingestion key, Cloud **backend API URL**, and local embedded-dashboard credentials as server-side environment variables.
4. Install a package release that supports `NETGUARD_INGEST_KEY`, add `setup_netguard` to the FastAPI app, and redeploy it.
5. Send requests to the deployed FastAPI application. The SDK evaluates traffic and sends telemetry snapshots and detected events to the Cloud API. The browser dashboard reads the stored data using the signed-in account session.

Example environment values on the monitored FastAPI service:

```text
NETGUARD_PROJECT_ID=<project-id-from-cloud-dashboard>
NETGUARD_INGEST_KEY=<one-time-project-ingestion-key>
NETGUARD_DASHBOARD_MODE=separate
NETGUARD_DASHBOARD_URL=https://<cloud-backend-api-host>
NETGUARD_AUTH_USERNAME=<embedded-dashboard-user>
NETGUARD_AUTH_PASSWORD=<long-random-embedded-dashboard-password>
```

The dashboard URL must point to the Cloud **API backend**, not the React static frontend. The cloud frontend's `VITE_API_BASE` points to that API origin; the API's `FRONTEND_ORIGIN` must exactly match the frontend origin. The cloud backend connects to MongoDB Atlas using its own `MONGODB_URI`, `MONGODB_DATABASE`, and `SESSION_SECRET` settings. MongoDB stores cloud users, sessions, projects/key digests, event records, and telemetry snapshots. This MongoDB setup belongs to the separately deployed Cloud backend; it is not bundled into the Python SDK and does not replace the self-hosted SQLite store.

The ingestion key authenticates the app to the Cloud API. The account session authenticates a person to the Cloud website. These are separate credentials and should be kept separate. Rotate a project key in the Cloud UI if it is lost or exposed, then update the monitored service's environment and redeploy.

Cloud dashboard limitations: the current onboarding flow targets FastAPI; only requests handled by the running instrumented process are observed; the UI refreshes by polling; raw request bodies are not stored by default; and an idle application does not generate traffic or reports by itself. Review the [Cloud setup guide](centralised_dashboard/README.md) for MongoDB Atlas creation, local development, Render deployment, and troubleshooting.

## Email and other alert destinations

### SMTP / Gmail

Configure these in the **application host's secret manager**:

```text
NETGUARD_EMAIL_PROVIDER=smtp
NETGUARD_SMTP_HOST=smtp.gmail.com
NETGUARD_SMTP_PORT=587
NETGUARD_SMTP_USER=<sender-address>
NETGUARD_SMTP_PASSWORD=<gmail-app-password>
NETGUARD_SMTP_FROM=<sender-address>
NETGUARD_ALERT_EMAIL=<recipient-address>
```

For Gmail, use an App Password where Google account settings permit it; do not use your normal account password. Some serverless/free hosts block outbound SMTP. In that case, use the HTTPS provider below.

### Resend HTTPS API

```text
NETGUARD_EMAIL_PROVIDER=resend
NETGUARD_RESEND_API_KEY=<resend-api-key>
NETGUARD_RESEND_FROM=<verified-sender-address>
NETGUARD_ALERT_EMAIL=<recipient-address>
```

Weekly digest settings are `NETGUARD_WEEKLY_DIGEST_ENABLED`, `NETGUARD_WEEKLY_DIGEST_DAY` (`sun` by default), and `NETGUARD_WEEKLY_DIGEST_HOUR` (24-hour clock; default `9`). FastAPI manages the scheduler lifecycle when an email provider is configured. Run one scheduler process per application to avoid duplicate digests in multi-worker setups. Other frameworks should use a single external scheduler or their own lifecycle integration. Configure webhooks with `NETGUARD_WEBHOOK_URL` and Slack-compatible webhooks with `NETGUARD_SLACK_WEBHOOK`.

## CLI commands

Install the `[web]` extra for web-serving commands and `[train]` for model/PCAP tooling. Run `netguard --help` or `netguard COMMAND --help` to inspect the installed version's options.

| Command | Purpose |
|---|---|
| `netguard info` | Show bundled/custom model metadata and features |
| `netguard dashboard` | Launch the terminal dashboard |
| `netguard dashboard-web` | Launch a browser dashboard process |
| `netguard serve` | Run the standalone authenticated multi-project dashboard (SQLite storage) |
| `netguard proxy` | Protect an HTTP upstream through a NetGuard reverse proxy |
| `netguard scan FILE.pcap` | Analyze an offline PCAP and summarize flows/detections |
| `netguard monitor` | Capture and analyze live packets where host permissions and networking support it |
| `netguard monitor-dashboard` | Run the live monitor with its dashboard view |
| `netguard digest --send` | Send the currently configured alert-history digest immediately |
| `netguard train` | Train and compare models from supported flow CSV data |
| `netguard evaluate` | Evaluate a model and generate metrics/figures |

The NetGuard Cloud website is deployed separately and is not launched by a Python CLI command. To try offline scanning from this repository, see [PCAP generation and scanning](nids-project/README.md).

## Main Python API

The public package exports `NetGuard`, `NetGuardConfig`, `DashboardMode`, `Alert`, `Severity`, `DetectionEngine`, and `PredictionResult`.

Useful `NetGuard` methods include:

- `process_request(...)`: record an HTTP exchange and classify completed traffic flows.
- `stats()`: return current request, flow, detection, recent-event, and client statistics for dashboards.
- `recent_alerts(limit=...)`: retrieve the most recent alert objects.
- `block_ip(ip, duration_seconds=...)`, `unblock_ip(ip)`, and `is_ip_blocked(ip)`: manage process-local temporary blocking.
- `register_notifier(notifier)` and `on_alert(callback)`: attach an alert destination or callback.
- `send_weekly_digest()`: send the current alert history through the configured email provider.

Framework helpers are in `netguard.integrations.fastapi`, `netguard.integrations.django`, and `netguard.integrations.flask`. The full reference is grouped by the `[web]`, `[train]`, and `[flask]` extras in [docs/reference.html](docs/reference.html).

## Preview the documentation website locally

From the repository root:

```powershell
python -m http.server 8001 --directory docs
```

Then open [http://127.0.0.1:8001](http://127.0.0.1:8001).

## Model and dataset acknowledgement

The bundled model is associated with CICIDS2017-style flow data. The dataset itself is not included in this package. The Canadian Institute for Cybersecurity asks users of CICIDS2017 to cite the dataset paper:

Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,” ICISSP, 2018. See the [CIC-IDS2017 dataset page](https://www.unb.ca/cic/datasets/ids-2017.html).

The MIT license covers NetGuard's project files; it does not replace any separate terms that may apply to third-party material or model artifacts.
