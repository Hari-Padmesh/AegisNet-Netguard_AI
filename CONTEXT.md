# NetGuard AI Project Context

Last reviewed: 2026-10-09
Current branch: `feature/embeddable-sdk`
Latest committed baseline: `78987ce`
Current worktree: Phase 0 through embedded dashboard and standalone server changes are in progress locally.

## Project Purpose

NetGuard AI is a Python machine-learning network intrusion detection system. It has two related operating modes:

- Host/network monitoring through the existing CLI and packet-flow code. This can require elevated privileges on Windows or Linux because raw NIC capture is restricted.
- Application-aware monitoring through an embeddable SDK. Middleware observes requests and responses inside a specific web application, so it does not need administrator privileges.

The current branch is focused on the second mode while preserving the existing training, scanning, monitoring, and dashboard code.

## Repository Layout

The repository has a nested project directory:

- Root `pyproject.toml`: install/build entry point when running from `d:\nids-project`; packages are discovered under `nids-project/`.
- `nids-project/pyproject.toml`: the package-local configuration when working from `d:\nids-project\nids-project`.
- `nids-project/netguard/`: runtime package.
- `nids-project/netguard/models/`: bundled `best_model.pkl`, `scaler.pkl`, and `metadata.json` used by the SDK.
- `nids-project/netguard/integrations/`: application middleware and request analysis.
- `nids-project/netguard/notifier/`: webhook and email notification implementations.
- `nids-project/netguard/web/`: embedded Starlette dashboard and static HTML UI.
- `nids-project/examples/fastapi_demo/`: runnable protected application and traffic simulator.
- `nids-project/tests/`: unit and integration tests.
- `nids-project/data/`: datasets and captures; dataset paths are ignored by Git.
- `nids-project/models/` and `nids-project/reports/`: training outputs and evaluation artifacts outside the packaged runtime model directory.

## Current Architecture

### Detection engine

`netguard.detection.DetectionEngine` loads the trained classifier, scaler, and metadata. With no `model_dir`, it first resolves `netguard/models/` and falls back to a local `models/` directory. `predict()` accepts a feature dictionary, fills missing features with zero, scales the vector, and returns `PredictionResult`.

The bundled model metadata currently defines 20 flow features and includes the `BENIGN` class. A custom model directory remains supported for users who train their own artifacts.

### Application traffic monitor

`netguard.integrations.base.AppTrafficMonitor` aggregates per-client request statistics and converts HTTP request/response data into the model's flow feature shape. It also has explicit application-layer checks for SQL injection, XSS, path traversal, common scan paths, and high request rates.

The monitor tracks request totals, attack totals, recent events, per-client rates, attack labels, and temporary IP blocks. `block_attacks=True` enables automatic blocking for sufficiently confident detections.

### Framework integrations

- `netguard.integrations.fastapi.NetGuardMiddleware` supports FastAPI and Starlette ASGI applications.
- `netguard.integrations.fastapi.setup_netguard(app, guard)` installs middleware and mounts the authenticated dashboard by default.
- `netguard.integrations.flask.NetGuardFlask` provides Flask `before_request` and `after_request` hooks plus dashboard REST routes.
- The public package exports `NetGuard`, `NetGuardMiddleware`, `DetectionEngine`, alert types, and notifier classes from `netguard`.

### Alerting

`AlertManager` scores predictions by severity, keeps alert history, optionally writes JSON Lines logs, prints Rich console panels, invokes callbacks, and dispatches configured webhook/email notifiers. Webhook payload formatting supports generic, Discord, and Slack-style services, with cooldown throttling.

### Dashboard

`netguard.web.app.create_dashboard_app()` creates a mountable Starlette application with:

- `/` for the static dashboard UI
- `/api/stats` for aggregated telemetry
- `/api/alerts` for recent alerts
- `/api/block-ip` for manual block/unblock operations
- `/ws` for one-second telemetry updates and alert callbacks

The FastAPI/Starlette helper mounts this application at `/_netguard` by default. Dashboard HTML, REST APIs, manual IP blocking, authenticated WebSocket telemetry, and authenticated remote event ingestion are implemented. The `netguard serve` CLI provides the standalone dashboard process.

## Typical Usage

From `d:\nids-project\nids-project`, a protected FastAPI application can use:

```python
from fastapi import FastAPI
from netguard import NetGuard

app = FastAPI()
guard = NetGuard(project_id="my-app", auth_username="admin", auth_password="secret")
setup_netguard(app, guard)
```

The example is `examples/fastapi_demo/main.py`. It serves the application on port 8000 and exposes the dashboard at `http://localhost:8000/_netguard`.

Useful commands from the repository root:

```powershell
Push-Location nids-project
..\.venv\Scripts\python.exe -m pytest -q
Pop-Location
```

To run the example from `nids-project/`:

```powershell
..\.venv\Scripts\python.exe -m uvicorn examples.fastapi_demo.main:app --reload --port 8000
```

The traffic simulator is `examples/fastapi_demo/simulate_traffic.py`.

## Verification State

The complete test suite currently passes: **50 passed**. The suite covers model loading, configuration, flow aggregation, deterministic HTTP rules, FastAPI middleware, dashboard authentication, WebSocket telemetry, event ingestion, and notifier registration.

There are two known non-failing warnings:

- Starlette's `TestClient` warns that the installed HTTPX integration is deprecated.
- Scikit-learn warns when the scaler receives a NumPy array without feature names; the implementation suppresses this warning in the detection engine.

## Implemented Versus Planned

Implemented on this branch:

- Bundled model artifacts under `netguard/models/`.
- Default model discovery independent of the caller's working directory.
- FastAPI/Starlette request monitoring and optional automatic IP blocking.
- Flask request monitoring and dashboard routes.
- Webhook and email notifier modules.
- Deterministic HTTP rules for SQL injection, XSS, path traversal, failed-auth bursts, sensitive-path scans, and request bursts.
- Embedded dashboard with REST and WebSocket telemetry.
- Authenticated remote event ingestion and the standalone `netguard serve` command.
- FastAPI demo and simulated traffic script.
- Integration and model-loading tests.
- Runtime, web, and training dependency groups with bundled package-data configuration.
- Root and nested packaging configurations.
- Git ignore rules and removal of tracked Python bytecode.

Still open from the implementation plan:

- Django middleware integration.
- Non-admin reverse-proxy mode (`netguard proxy`).
- Weekly digest scheduling and a dedicated `netguard digest --send` command.
- More complete mocked HTTP/SMTP delivery tests and production retry/backpressure policies.
- Top-offender client telemetry and richer dashboard read models.
- Production hardening for dashboard authentication/authorization, trusted proxy headers, request body capture, response streaming, and WebSocket lifecycle management.

## Important Design Boundaries

- The SDK observes application HTTP traffic only. It is not a replacement for privileged host-level packet capture.
- Middleware currently uses request headers and response `Content-Length`; streamed bodies and exact payload sizes are not fully captured.
- `X-Forwarded-For` is trusted when present. Deployments behind an untrusted proxy should configure or sanitize this header before relying on IP blocking.
- Dashboard HTML, REST, block-IP, and WebSocket surfaces require Basic Auth or a bearer API key.
- Model predictions are combined with explicit signature checks. A recognized SQLi/XSS/path-traversal pattern can override or escalate the model label.

## Recent Commit History

- `78987ce` `feat: complete Phase 1 embeddable FastAPI SDK with auth and ML middleware`
- `a71dc70` `docs: add FastAPI demo and package metadata`
- `56ecdba` `feat: add embeddable NetGuard SDK`
- `f5c396c` `chore: ignore generated Python bytecode`
- `1fed7f8` prior live network detection/dashboard implementation
