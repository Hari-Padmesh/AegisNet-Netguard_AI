# NetGuard Cloud Dashboard (FastAPI MVP)

NetGuard Cloud is a separate, multi-user service for collecting telemetry from FastAPI applications instrumented with the NetGuard SDK. It does not replace the existing embedded or SQLite-backed self-hosted dashboards.

## What works in this MVP

- Email/password signup and login, with Argon2 password hashing and revocable HTTP-only sessions.
- Account-scoped FastAPI project registration, deletion, and key rotation.
- A random ingestion key per project. The API stores only a keyed SHA-256 digest; the plaintext key is returned once at creation/rotation.
- Project-scoped event and telemetry ingestion. The API resolves ownership from the key and rejects a mismatched project ID.
- MongoDB-backed recent events and telemetry snapshots.
- React/Vite UI for account access, project selection, onboarding, connection freshness, telemetry counters, and recent events.
- SDK compatibility paths `/api/events` and `/api/telemetry`, plus documented `/api/ingest/*` paths.

## Current boundaries

- The MVP supports **FastAPI** onboarding. Django and Flask are follow-on work.
- Users must instrument and deploy the Python backend with NetGuard. A public URL alone cannot be monitored.
- It receives requests handled by a running instrumented process; it does not continuously scan an idle site.
- The UI refreshes the saved snapshot every ten seconds. It is not a WebSocket/push dashboard yet.
- It stores security event and traffic metadata, not raw request bodies.
- Signup is not email-verified and has no password reset, rate limiting, audit log, or billing. Do not expose unrestricted public signup until those production controls are added.
- The SDK source in this repository now supports `NETGUARD_INGEST_KEY`; users need a package release containing this change before installing it from PyPI.

## Folder layout

```text
centralised_dashboard/
├── PLAN.md
├── README.md
├── backend/
│   ├── .env.example
│   ├── requirements.txt
│   └── app/
│       ├── config.py       # Environment configuration
│       ├── main.py         # FastAPI routes, MongoDB lifecycle and tenant checks
│       ├── schemas.py      # Validated API request models
│       └── security.py     # Password hashing, session/key creation and digests
└── frontend/
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── App.jsx         # Signup, projects, setup and event dashboard UI
        ├── main.jsx
        └── styles.css
```

## Local setup

### 1. Create the MongoDB Atlas deployment and credentials

1. Sign in to [MongoDB Atlas](https://cloud.mongodb.com/) and create a project for the cloud dashboard.
2. Create a free cluster/deployment. Wait until Atlas reports that it is ready.
3. In **Security → Database & Network Access → IP Access List**, add your current IP address for local development. Atlas accepts connections only from addresses on this list. Do not use `0.0.0.0/0` as a shortcut; that allows connections from any IP.
4. In **Security → Database & Network Access → Database Users**, create a database user. This is separate from your Atlas website login. For a quick local prototype, assign read/write access; for a deployed service, scope the role to the `netguard_cloud` database.
5. Open **Database → Clusters → Connect → Drivers**, choose Python, and copy the `mongodb+srv://...` URI. Replace its password placeholder with the database user's password. URI-reserved password characters must be percent-encoded (for example, `@` becomes `%40`).

Atlas requires both an allowed IP and a database user for a driver connection. For a deployed backend, the allow-list must include the backend host's outbound IP addresses as well as your local IP if you still want to run the API locally. Atlas's [PyMongo connection guide](https://www.mongodb.com/docs/languages/python/pymongo-driver/current/get-started/) and [IP access-list guide](https://www.mongodb.com/docs/atlas/security/ip-access-list/) show the current UI steps.

### 2. Configure and start the API

PowerShell, from this directory:

```powershell
cd D:\nids-project\centralised_dashboard\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `backend\.env` and set `MONGODB_URI`, a long random `SESSION_SECRET` (at least 32 characters), and `FRONTEND_ORIGIN`. Generate a secret in PowerShell with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Paste the generated value into `.env`; do not paste it into chat or commit it. For local development, keep `COOKIE_SECURE=false`, `COOKIE_SAMESITE=lax`, and `FRONTEND_ORIGIN=http://localhost:5173`. The database name is selected by `MONGODB_DATABASE=netguard_cloud` in `.env`.

```powershell
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Check `http://127.0.0.1:8000/api/health`. A successful response is `{"status":"ok","database":"connected"}`. The interactive API reference is at `http://127.0.0.1:8000/docs`.

### 3. Start the UI

Open another PowerShell window:

```powershell
cd D:\nids-project\centralised_dashboard\frontend
npm install
npm run dev
```

Open the Vite URL printed in the terminal (normally `http://localhost:5173`). The Vite development server forwards `/api` to `http://127.0.0.1:8000`.

Sign up with a valid email and a password of at least 12 characters. Add a project, save its one-time ingestion key, and confirm it appears in the project list. In Atlas **Database → Browse Collections**, the backend should create a `netguard_cloud` database with collections such as `users`, `sessions`, and `projects`. After events arrive, `events` and `telemetry` will appear. Project keys are stored as digests, not plaintext.

## Verify the SDK sends data

Use the repository's FastAPI demo after the cloud API and dashboard are running. In a third PowerShell window, set the project credentials from the dashboard (keep the key private):

```powershell
$env:NETGUARD_PROJECT_ID = "<project-id-from-dashboard>"
$env:NETGUARD_INGEST_KEY = "<one-time-key-from-dashboard>"
$env:NETGUARD_DASHBOARD_URL = "http://127.0.0.1:8000"
$env:NETGUARD_DASHBOARD_MODE = "separate"
$env:NETGUARD_AUTH_USERNAME = "admin"
$env:NETGUARD_AUTH_PASSWORD = "secret"

cd D:\nids-project\nids-project
..\.venv\Scripts\python.exe -m uvicorn examples.fastapi_demo.main:app --host 127.0.0.1 --port 3000
```

In a fourth PowerShell window, run the simulator against that demo:

```powershell
$env:NETGUARD_TARGET_URL = "http://127.0.0.1:3000"
cd D:\nids-project
.\.venv\Scripts\python.exe .\nids-project\examples\fastapi_demo\simulate_traffic.py
```

The simulator continues until you press `Ctrl+C`. The central dashboard should update the project's last-data time and request counters. Detected events appear as the SDK's detector produces alerts; not every simulated request necessarily produces an alert. Confirm that MongoDB's `events` and `telemetry` collections receive documents. The central dashboard currently refreshes by polling every ten seconds.

If the API reports that the MongoDB URI is missing, confirm that the file is exactly `centralised_dashboard\backend\.env` and that Uvicorn was launched from the `backend` directory. A connection timeout commonly means the current machine's IP is not in Atlas's IP access list. An authentication error commonly means the database user's credentials are wrong or reserved password characters were not encoded. The Atlas database user is not your Atlas website login.

## Connect an instrumented FastAPI application

Register an app in the dashboard and copy its project ID and one-time ingestion key. Add them to the FastAPI service's server-side environment, along with the **backend API base URL** (not the static frontend URL):

```text
NETGUARD_PROJECT_ID=<project ID shown by NetGuard>
NETGUARD_INGEST_KEY=<one-time project key>
NETGUARD_DASHBOARD_URL=https://<your-NetGuard-API-host>
NETGUARD_DASHBOARD_MODE=separate
NETGUARD_AUTH_USERNAME=<local embedded dashboard username>
NETGUARD_AUTH_PASSWORD=<long random local dashboard password>
```

Install a version of `netguard-threat-monitor[web]` that includes `NETGUARD_INGEST_KEY` support. Then instrument the FastAPI process:

```python
import os
from fastapi import FastAPI
from netguard import NetGuard
from netguard.integrations.fastapi import setup_netguard

app = FastAPI()
guard = NetGuard(
    project_id=os.environ["NETGUARD_PROJECT_ID"],
    auth_username=os.environ["NETGUARD_AUTH_USERNAME"],
    auth_password=os.environ["NETGUARD_AUTH_PASSWORD"],
    dashboard_mode="separate",
    dashboard_url=os.environ["NETGUARD_DASHBOARD_URL"],
)
setup_netguard(app, guard)
```

Restart/redeploy the FastAPI app and send requests to it. NetGuard forwards event and telemetry metadata to the central API; the dashboard marks the project online when data was received in the last two minutes, stale after that, and waiting before its first report. If a key is lost, rotate it in NetGuard and replace the app's environment value.

### Deployment note for the UI

The dashboard API and the static UI may be deployed together behind one origin or separately. If separate, set frontend build variable `VITE_API_BASE` (see `frontend/.env.example`) to the HTTPS API origin and configure the API's `FRONTEND_ORIGIN` to the exact frontend origin. Prefer frontend/API hostnames under the same parent domain. For truly cross-site frontend/API domains, set `COOKIE_SAMESITE=none` and `COOKIE_SECURE=true` (HTTPS is required, and browser third-party-cookie restrictions may still apply). Set `PUBLIC_API_URL` to the API's HTTPS origin; the setup wizard uses it for `NETGUARD_DASHBOARD_URL`. The API must be reachable from instrumented apps.

## Architecture and data ownership

```text
FastAPI service + NetGuard SDK
  ├─ POST /api/events       ─┐
  └─ POST /api/telemetry     ├─ Bearer per-project key
                             v
React/Vite UI  <── session ─ FastAPI API ── MongoDB Atlas
                              │
                              ├─ users / sessions
                              ├─ projects / key digests
                              └─ events / telemetry snapshots
```

Browser endpoints require the signed-in account's session and filter project reads by that account's MongoDB user ID. App ingestion uses a separate project key; caller-provided project IDs are checked against the project resolved from that key. Passwords and project keys are never stored as plaintext.

See [PLAN.md](PLAN.md) for phased scope, security boundaries, and later Django/Flask work.
