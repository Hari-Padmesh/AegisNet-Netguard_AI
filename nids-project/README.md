# Network Intrusion Detection System (NIDS) using Machine Learning

A multi-class ML pipeline for classifying network flow data as benign or
one of several attack families (DoS, DDoS, PortScan, Brute Force, Botnet,
Web Attack, Infiltration), trained on CICIDS2017-style flow features.

## Project structure

```
nids-project/
├── data/
│   ├── raw/                  # put downloaded CICIDS2017 CSVs here
│   └── processed/            # generated test set (created by train.py)
├── src/
│   ├── preprocessing.py      # cleaning, label encoding
│   ├── features.py           # train/test split, scaling, feature selection
│   ├── train.py              # CLI training script
│   └── evaluate.py           # per-class metrics, FPR, confusion matrix, ROC
├── app/
│   └── streamlit_app.py      # interactive demo
├── models/                   # saved model/scaler/metadata (created by train.py)
├── reports/
│   └── figures/               # saved evaluation plots
└── requirements.txt
```

## Setup

```bash
python -m venv nids-env
source nids-env/bin/activate      # Windows: nids-env\Scripts\activate
pip install -r requirements.txt
```

Run the commands below from the inner project folder, `nids-project/`, where
`src/` lives. For your workspace, that means:

```bash
cd nids-project
```

## 1. Get the data

Download CICIDS2017 (the "MachineLearningCSV" version — 8 daily CSVs) from
the Canadian Institute for Cybersecurity:
https://www.unb.ca/cic/datasets/ids-2017.html

Registration is required. Place all 8 CSVs into `data/raw/`.

> Want to test the pipeline before downloading the full ~225MB dataset?
> Any CSV with a `Label` column and numeric feature columns will work —
> the code only assumes a `Label` column exists, nothing CICIDS-specific
> beyond the optional attack-family collapsing map in `preprocessing.py`.

## 2. Train

```bash
python -m src.train --data_dir data/raw/ --top_n_features 20 --cv_folds 5
```

If you see `ModuleNotFoundError: No module named 'src'`, you are running the
command from the outer folder. Change into `nids-project/` first, then rerun
the command.

This will:
1. Load and clean all CSVs in `data_dir` (handles whitespace in columns,
   Inf/NaN rows, duplicate rows, zero-variance columns — all known
   CICIDS2017 quirks)
2. Collapse fine-grained attack labels into families (configurable)
3. Stratified train/test split
4. Select top-N features by Random Forest importance
5. Scale features (fit on train only — no leakage)
6. Run 5-fold stratified CV comparing Logistic Regression, Random Forest,
   and XGBoost, scored on **macro-F1** (not accuracy — accuracy is
   misleading here because BENIGN dominates the class distribution)
7. Fit the best model on the full training set
8. Save `models/best_model.joblib`, `models/scaler.joblib`,
   `models/metadata.json`, and `data/processed/test_set.csv`

## 3. Evaluate

```bash
python -m src.evaluate
```

Produces:
- Per-class precision/recall/F1 (the metric that actually matters for rare
  attack types like Infiltration)
- **False Positive Rate per class** — the metric that determines whether
  an IDS is usable in practice (high FPR = alert fatigue)
- Confusion matrix (`reports/figures/confusion_matrix.png`)
- One-vs-rest ROC curves (`reports/figures/roc_curves.png`)
- `reports/evaluation_summary.json` for your writeup

## 4. Run the demo

```bash
streamlit run app/streamlit_app.py
```

Two modes:
- **Upload CSV**: batch-score a file of flow records, see prediction
  distribution, download results
- **Manual input**: adjust feature values with number inputs, get a live
  single-flow prediction with class probabilities

The demo loads the exact same model/scaler/feature-list artifacts that
`train.py` produced, so there's no train/serve skew.

## 5. Embeddable SDK (FastAPI)

Install with web integration extras:

```bash
python -m pip install ".[web]"
```

Run this install command from the repository root (the directory containing
the top-level `pyproject.toml`). For development, use
`python -m pip install -e ".[web]"` from that same directory. Once published,
users will install the release with `python -m pip install "netguard[web]"`.

Set authentication (required for NetGuard API routes):

```bash
export NETGUARD_AUTH_USERNAME=admin
export NETGUARD_AUTH_PASSWORD=secret
export NETGUARD_PROJECT_ID=my-app
```

Optional Gmail instant alerts:

```bash
export NETGUARD_ALERT_EMAIL=owner@gmail.com
export NETGUARD_SMTP_HOST=smtp.gmail.com
export NETGUARD_SMTP_PORT=587
export NETGUARD_SMTP_USER=you@gmail.com
export NETGUARD_SMTP_PASSWORD=<google-app-password>
export NETGUARD_SMTP_FROM=you@gmail.com
```

Minimal FastAPI integration:

```python
from fastapi import FastAPI
from netguard import NetGuard
from netguard.integrations.fastapi import setup_netguard

app = FastAPI()
guard = NetGuard(
    project_id="my-app",
    auth_username="admin",
    auth_password="secret",
    model_dir="models",
)
setup_netguard(app, guard)
```

The default setup mounts an authenticated dashboard at `/netguard/` with
health, statistics, alert, IP-blocking, and WebSocket telemetry endpoints.
Use Basic Auth or a bearer API key configured through `NETGUARD_AUTH_*`.
The middleware observes only the host application and does not require admin
privileges. The existing raw packet monitor remains a separate admin-required
mode on Windows.

Run the included demo (from this directory):

```bash
uvicorn examples.fastapi_demo.main:app --reload --port 8000
curl -u admin:secret http://localhost:8000/netguard/health
```

The model combines deterministic HTTP rules with approximate ML features
derived from request/response sizes. The bundled model was trained on
CICIDS-style network flows, so application-specific rules are the authoritative
first layer for web attacks.

Standalone multi-project dashboard:

```bash
netguard serve --port 8787 --auth-username admin --auth-password secret
```

The server stores bounded project alert history in `netguard-projects.sqlite3`
using SQLite WAL mode. Existing `netguard-projects.json` data is imported when
the default database is first created; passing a legacy JSON file through
`--storage` migrates it in place. Applications configured with
`dashboard_mode="separate"` or `"both"` send
authenticated alert events to `NETGUARD_DASHBOARD_URL`. Use `/api/projects`,
`/api/stats?project_id=...`, and `/api/alerts?project_id=...` to inspect
isolated projects. They also publish a throttled request/client snapshot so
the dashboard can show request totals, recent events, and client IP activity.

To connect the FastAPI demo to the standalone dashboard, start the dashboard
server, then configure these variables in the PowerShell window that starts
the demo app:

```powershell
$env:NETGUARD_DASHBOARD_MODE = "separate"
$env:NETGUARD_DASHBOARD_URL = "http://127.0.0.1:8787"
$env:NETGUARD_PROJECT_ID = "demo-app"
$env:NETGUARD_AUTH_USERNAME = "admin"
$env:NETGUARD_AUTH_PASSWORD = "secret"
```

The standalone dashboard selects the first reporting project automatically;
use its project selector to switch when several apps are reporting.

HTTP rule alerts have per-client, per-rule cooldowns. Defaults range from
30 to 60 seconds; repeated detections remain visible in recent events but are
marked `alert_suppressed` and do not dispatch duplicate alerts during the
cooldown. Override individual durations with a JSON object, for example:

```powershell
$env:NETGUARD_RULE_COOLDOWNS = '{"http.sqli": 5, "http.request_burst": 10}'
```

Optional Django integration:

```python
MIDDLEWARE = [
    "netguard.integrations.django.NetGuardDjangoMiddleware",
    # ...
]
```

The middleware reads the same `NETGUARD_*` configuration as the FastAPI
integration. Install Django support with `pip install "netguard[web]"`.
The Flask extension is a separate, older API; install its dependency with
`pip install "netguard[flask]"` and import `NetGuardFlask` from
`netguard.integrations.flask`.

Unprivileged reverse proxy mode:

```bash
netguard proxy --target http://127.0.0.1:3000 --port 8080 \
  --project-id my-app --auth-username admin --auth-password secret
```

This proxies HTTP traffic through NetGuard without raw packet capture or
administrator privileges.

Weekly email digest:

```bash
netguard digest --send
```

In FastAPI, the integration starts the weekly scheduler at application startup
and stops it at shutdown when SMTP is configured and
`weekly_digest_enabled=True`. Provide configuration in Python if you do not
want to set shell environment variables:

```python
from netguard import NetGuard, NetGuardConfig
from netguard.integrations.fastapi import setup_netguard

# `secrets` below represents the secret manager provided by your host.
config = NetGuardConfig(
    project_id="my-app",
    auth_username="admin",
    auth_password=secrets.get("netguard-dashboard-password"),
    alert_email="ops@example.com",
    smtp_host="smtp.example.com",
    smtp_port=587,
    smtp_user=secrets.get("smtp-username"),
    smtp_password=secrets.get("smtp-password"),
    smtp_from="netguard@example.com",
    weekly_digest_enabled=True,
    weekly_digest_day="sun",
    weekly_digest_hour=9,
)
guard = NetGuard(config=config)
setup_netguard(app, guard)
```

Here `secrets.get(...)` stands for your deployment platform's secret manager;
do not commit credentials to source control. The schedule uses the host's local
time. Run the scheduler in only one application process because every worker
has its own scheduler thread. For Django or another host, start and stop it
from that framework's process lifecycle, or run one external scheduled
process. `netguard digest --send` remains available for a one-off send.

## Design notes / known limitations (worth stating explicitly in any writeup)

- **NSL-KDD vs CICIDS2017**: this pipeline is built for CICIDS2017-style
  flow features (78 columns). NSL-KDD has a different, older feature set
  and known dataset artifacts (duplicate records, synthetic generation
  quirks) — fine for quick prototyping, not for a final result.
- **Macro-F1 over accuracy**: with BENIGN as the majority class, a model
  that just predicts BENIGN often gets >80% accuracy while detecting
  nothing. Macro-F1 and per-class recall are what matter.
- **Temporal leakage**: CICIDS2017 has a day-by-day structure. The default
  split here is a random stratified split. For a more rigorous test of
  generalization, consider splitting by day instead (train on days 1-6,
  test on days 7-8) — this is closer to how the model would actually be
  evaluated in deployment, and the code in `features.py` is structured so
  this is a small change to `split_data`.
- **Feature selection** uses Random Forest importance as a fast heuristic.
  For a more rigorous final explanation of the chosen model, layer in SHAP.
- **Generalization gap**: a model trained and tested on the same dataset's
  traffic generator tends to overstate real-world performance. If you want
  to push this further, training on CICIDS2017 and testing on CICIDS2018
  or UNSW-NB15 is a known, meaningful stress test in the IDS literature.

## Next steps (optional extensions)

- SHAP analysis on the final model for explainability
- SMOTE vs class-weighting comparison (imbalanced-learn is already in
  requirements.txt)
- Hyperparameter tuning with Optuna on the winning model from CV
- Cross-dataset generalization test (train on CICIDS2017, test on
  CICIDS2018/UNSW-NB15)
- Live `.pcap` capture → CICFlowMeter → model inference, for a true
  live-traffic demo
