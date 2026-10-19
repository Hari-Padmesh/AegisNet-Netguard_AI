## Plan: Finish Phase 1 and Build Phase 2

The Cursor plan is directionally correct, and the current branch has implemented much of the Phase 1 foundation. Phase 1 is not complete by its own acceptance criteria yet: the full suite is 33 passed / 8 failed, the old and new integration APIs coexist inconsistently, `mount_dashboard` is a no-op, and the new core does not wire webhook/Slack channels or rule-based web attack detection. Complete stabilization first, then build the dashboard/event-delivery layer on top of the new `NetGuard` core.

**Steps**

### Phase 0: Stabilize the current branch
1. Make the new API canonical: `NetGuard(config/kwargs)` plus `setup_netguard(app, guard)`. Update `tests/test_integrations.py` to use the Phase 1 API and add compatibility coverage only if the old `NetGuard(app, ...)` form is intentionally retained. Do not silently support two incompatible meanings of `NetGuard`.
2. Fix the legacy `AppTrafficMonitor` and `NetGuardFlask` call sites to use the current `AlertManager(console_alerts=...)` contract, or mark those modules deprecated until they are migrated to the shared core. Remove duplicate behavior where possible.
3. Add focused tests for the current Phase 1 contract: model fallback when launched from the outer repository root, Basic Auth and bearer API-key health access, middleware request/response accounting, idle-flow flush, shutdown flush, alert threshold behavior, and notifier registration.
4. Commit the already identified bundled-model fallback separately as a small bug fix, then commit the test/API migration separately. The Phase 0 exit criterion is a clean full suite with no known legacy API failures.

### Phase 1 completion: make the SDK behavior honest and deterministic
5. Define the lifecycle contract for flow scoring. Keep the 30-second idle window configurable, but add a deterministic flush mechanism for tests and local demos. Expose enough telemetry to distinguish requests received, flows active, flows scored, predictions, alerts, and attacks. Ensure `attack_count` semantics are documented as alerted attacks rather than all predicted attacks, or rename the field.
6. Add an application-layer rules boundary, separate from the CICIDS feature model. Start with deterministic rules for request-rate bursts, repeated failed authentication, suspicious paths, and payload signatures. Emit the same `PredictionResult`/`Alert` shape as ML detections, with a source/rule identifier in the alert details. Keep the existing XGBoost model explicitly documented as an approximate HTTP-flow classifier, not a validated web-attack model.
7. Wire all configured notification channels through the current `AlertNotifier.notify()` protocol. Adapt the existing webhook notifier instead of maintaining a second `send()` protocol, add a Slack-specific or service-selectable notifier, and add mocked delivery tests for severity filtering, cooldowns, failure isolation, and payloads. Do not send real email/webhook traffic in tests.
8. Add `.env.example`, ignore `.env.local` and local alert logs, and update documentation so credentials are never committed and `.env.local` is not assumed to be auto-loaded by Python. Keep Gmail app-password instructions but state that SMTP configuration is optional.

### Phase 2: embedded dashboard and real-time events
9. Refactor `netguard/web/app.py` around the new `NetGuard` core rather than the legacy `AppTrafficMonitor`. Define a small dashboard read model/event bus that exposes stats, recent alerts, top clients, attack breakdown, and manual block actions without coupling the web layer to the old monitor.
10. Implement authenticated embedded routes under the configured `dashboard_path`: dashboard HTML, `/api/health`, `/api/stats`, `/api/alerts`, and protected block/unblock actions. Apply the same Basic Auth/API-key dependency to every API route and make the WebSocket authentication behavior explicit rather than leaving the socket open.
11. Implement the WebSocket alert/telemetry stream with connection cleanup, bounded subscriber handling, and tests for telemetry messages, alert broadcasts, disconnects, and unauthorized access. Keep the browser dashboard as a lightweight static client and ensure its paths match the final route names.
12. Add deterministic demo endpoints or a standalone test harness for benign traffic, failed-login bursts, suspicious paths, and high request rate. The acceptance check must show a request moving from received -> scored -> alert -> dashboard event without waiting on an uncontrolled timer.

### Phase 3: separate dashboard server and production-facing delivery
13. Implement `DashboardMode` behavior instead of only storing the enum. In `embedded` mode mount routes in the host app; in `separate`/`both` mode start or connect to a standalone server with an authenticated event-ingestion endpoint. Define the event schema and project isolation rules before coding transport details.
14. Add the `netguard serve` CLI command with host/port/project/auth options, health/stats/alerts/event-ingest routes, and a local development warning. Test the server with an in-process client; do not require a second real process in unit tests.
15. Add webhook, Slack, instant Gmail email, and a manually triggerable weekly digest. Keep delivery asynchronous or bounded so notifier failures cannot delay application responses. Add `netguard digest --send` only after the digest data model and scheduler-independent send path are tested.

### Phase 4: packaging and release readiness
16. Consolidate the root and inner `pyproject.toml` files or clearly designate one supported install root. Align package version, README path, package discovery, package data, runtime dependencies, `[web]`, `[train]`, and `[dev]` extras. Runtime installation should not pull SHAP, Optuna, plotting, Streamlit, or training-only dependencies.
17. Resolve model artifact packaging and path behavior in a clean temporary virtual environment from the supported install root. Add a packaging smoke test that imports `netguard`, loads the bundled model from an arbitrary working directory, and starts the FastAPI integration.
18. Stop treating generated `netguard.egg-info` as hand-maintained source metadata. Either remove it from version control and ignore it, or regenerate it consistently from the one canonical project configuration. Add an explicit version source so CLI and package versions cannot diverge.
19. Update README and `CONTEXT.md` only after behavior is implemented. Document FastAPI quickstart, authentication, embedded/separate dashboard modes, no-admin scope, raw-capture admin limitation, model mismatch caveat, alert configuration, tests, and known production hardening requirements.

**Relevant files**
- `nids-project/netguard/core.py` — canonical SDK lifecycle, model fallback, scoring, stats, shutdown.
- `nids-project/netguard/config.py` — configuration schema, dashboard modes, auth, SMTP and thresholds.
- `nids-project/netguard/aggregator.py` — HTTP-to-flow aggregation and flush semantics.
- `nids-project/netguard/integrations/fastapi.py` — ASGI middleware and setup helper; currently only registers authenticated health and leaves dashboard mounting as a no-op.
- `nids-project/netguard/integrations/base.py` and `nids-project/netguard/integrations/flask.py` — legacy duplicate monitor paths that currently use the stale `console_output` AlertManager argument.
- `nids-project/netguard/alerts.py` — current notifier protocol, severity filtering, callbacks, history, and alert statistics.
- `nids-project/netguard/notifier/base.py`, `email.py`, `webhook.py`, `email_notifier.py` — consolidate notifier interfaces and remove duplicate delivery implementations.
- `nids-project/netguard/web/app.py` and `web/static/dashboard.html` — refactor from the legacy monitor contract to the new core and protect all dashboard surfaces.
- `nids-project/netguard/auth.py` — Basic/Bearer dependency and WebSocket authorization policy.
- `nids-project/netguard/cli.py` — add `serve`/digest only after the server and delivery contracts exist; also align version and model-path handling.
- `nids-project/tests/test_integrations.py` — migrate stale pre-Phase-1 tests and add embedded API/WebSocket coverage.
- `nids-project/tests/test_aggregator.py`, `test_config.py`, plus new core/alert/notifier/dashboard tests — preserve current passing coverage and add lifecycle/security cases.
- `nids-project/pyproject.toml` and root `pyproject.toml` — consolidate installation metadata and optional dependency groups.
- `.gitignore`, `.env.example`, `nids-project/README.md`, and `CONTEXT.md` — credentials, generated files, setup instructions, and current-stage documentation.

**Verification**
1. Phase 0: run the full suite from the canonical project root with the repository virtual environment; exit criterion is zero failures, including migrated integration tests.
2. Run a model-loading smoke test from both `D:\nids-project` and an unrelated temporary working directory; `DetectionEngine().load()` and `NetGuard(...).engine.is_loaded` must succeed.
3. Use `TestClient` to verify unauthenticated health/stats/alerts/block routes return `401`, Basic Auth and bearer API key succeed, and middleware does not count dashboard requests as protected app traffic.
4. Send deterministic benign and attack-like requests, flush the guard, and assert request/flow/prediction/alert counts plus alert payloads without real network delivery.
5. Test WebSocket telemetry and alert broadcasts, client disconnect cleanup, and bounded subscriber behavior.
6. Test notifier adapters with mocked HTTP/SMTP transports, including severity thresholds, cooldowns, and exceptions.
7. Run the FastAPI demo manually: start app, call authenticated health, send the simulator/rule fixtures, observe dashboard updates, then stop cleanly and confirm final flush.
8. Build/install from the canonical root into a clean virtual environment and verify import, bundled model loading, CLI help, and `netguard serve` help.
9. Run `git diff --check`, inspect `git status`, and confirm no `.env.local`, credentials, alert logs, caches, or generated egg-info changes are included in commits.

**Decisions**
- FastAPI is the first supported application integration; Flask/Django are not Phase 2 blockers.
- The new `NetGuard` core plus `setup_netguard` is the canonical public API.
- Dashboard target is both embedded and standalone, but embedded authenticated routes should be completed before the separate transport.
- ML remains the primary classifier, with deterministic application rules added as a complementary layer because CICIDS packet-flow features are only approximations for HTTP traffic.
- Gmail is the selected local email provider; credentials use environment variables/app passwords and are never hardcoded.
- Raw NIC capture remains an optional admin-required mode, not part of the no-admin SDK path.
- No PyPI publication or multi-tenant SaaS work is included until packaging and dashboard contracts are stable.

**Further Considerations**
1. Decide whether to preserve the older `AppTrafficMonitor`/legacy dashboard API for backwards compatibility. Recommendation: migrate tests and mark it deprecated unless existing external users depend on it; maintaining two state models will keep causing drift.
2. Decide whether dashboard authentication should use Basic Auth, bearer API keys, or both. Recommendation: support both for local development, require an explicit production setting, and never leave manual block operations unauthenticated.
3. Decide the separate-dashboard transport before implementation: local authenticated HTTP event ingestion is the simplest MVP; an in-process event bus is sufficient for embedded mode, while cross-process persistence can wait for a later release.
