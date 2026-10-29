# NetGuard

NetGuard is an embeddable HTTP threat monitoring SDK for Python applications.
It records request metadata, applies application-layer detection rules and a
bundled ML model, and provides an authenticated live dashboard.

Published package in PyPi: [netguard-threat-monitor](https://pypi.org/project/netguard-threat-monitor)
Cloud dashboard(can only connect applications that already have basic netguard package installed and configured): [NetGuard Cloud dashboard](https://netguard-dashboard-nlo8.onrender.com) - follow the steps in the webite to connect and mmonitor

Package documentation: [Netgurad docs](https://aegisnet-netguard-ai.onrender.com)

## Documentation

Browse the [NetGuard documentation site](docs/index.html), the [API reference by install extra](docs/reference.html), and [copy-ready coding-agent prompts](docs/prompts.html) for installation,
framework integrations, dashboard setup, configuration, email alerts, CLI
commands, and deployment guidance. Preview it locally with:

    python -m http.server 8001 --directory docs

## NetGuard Cloud Dashboard

Open the [NetGuard Cloud dashboard](https://netguard-dashboard-nlo8.onrender.com) to create an account, register instrumented FastAPI applications, and review their latest telemetry and security events in one workspace. Each app must run the NetGuard SDK and be configured with its project ID, ingestion key, and the cloud API URL; a public website URL by itself is not monitored. See the [cloud dashboard setup guide](centralised_dashboard/README.md) for deployment and integration details. The cloud dashboard currently supports FastAPI onboarding.

## Install

From a source checkout, run this command from the repository root:

```powershell
python -m pip install ".[web]"
```

After a release is published to PyPI, install the web integration with:

```powershell
python -m pip install "netguard-threat-monitor[web]"
```

## FastAPI integration

```python
from fastapi import FastAPI
from netguard import NetGuard, NetGuardConfig
from netguard.integrations.fastapi import setup_netguard

app = FastAPI()
# `secrets` below represents the secret manager provided by your host.
config = NetGuardConfig(
    project_id="my-app",
    auth_username="admin",
    auth_password=secrets.get("netguard-dashboard-password"),
)
guard = NetGuard(config=config)
setup_netguard(app, guard)
```

The authenticated dashboard is mounted at `/netguard/`. For a single
application, the embedded dashboard is the simplest option. To aggregate
several applications, run `netguard serve` as a separate dashboard service and
configure each application with `dashboard_mode="separate"` and its
`dashboard_url`.

Keep dashboard and email provider credentials in your deployment platform's
secret manager. Do not commit credentials to source control. Configure NetGuard
directly with `NetGuardConfig` or use the `NETGUARD_*` settings described in
the [full project guide](nids-project/README.md).

Email can be delivered through SMTP or the Resend HTTPS API. For hosts that
block SMTP, select the Resend provider with `NETGUARD_EMAIL_PROVIDER=resend`,
`NETGUARD_RESEND_API_KEY`, `NETGUARD_RESEND_FROM`, and `NETGUARD_ALERT_EMAIL`.
FastAPI starts and stops the weekly digest scheduler with the app lifecycle
when the selected provider is configured. Run one scheduler process per app to
avoid duplicate digests in multi-worker deployments. Other frameworks should
manage it from their own lifecycle or use one external scheduler.

## Optional integrations

- `netguard-threat-monitor[web]`: FastAPI, Django, and ASGI server dependencies.
- `netguard-threat-monitor[flask]`: dependency for the separate legacy Flask extension.
- `netguard-threat-monitor[train]`: model training and offline-analysis dependencies.

NetGuard is distributed under the MIT License; see [LICENSE](LICENSE).

## Model and dataset acknowledgement

The bundled model is associated with CICIDS2017-style flow data. The dataset
itself is not included in this package. The Canadian Institute for
Cybersecurity asks users of CICIDS2017 to cite the dataset paper:

Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, “Toward
Generating a New Intrusion Detection Dataset and Intrusion Traffic
Characterization,” ICISSP, 2018. See the [CIC-IDS2017 dataset page](https://www.unb.ca/cic/datasets/ids-2017.html).

The MIT license covers NetGuard's project files; it does not replace any
separate terms that may apply to third-party material or model artifacts.
