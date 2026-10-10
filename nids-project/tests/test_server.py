"""Tests for standalone dashboard project isolation and persistence."""

from starlette.testclient import TestClient

from netguard.web.server import DashboardProjectStore, create_dashboard_server_app


def test_project_store_persists_and_isolates_alerts(tmp_path):
    path = str(tmp_path / "projects.json")
    first = DashboardProjectStore(path)
    first.ingest("alpha", {"label": "PortScan", "severity": "MEDIUM"})
    first.ingest("beta", {"label": "DoS", "severity": "CRITICAL"})

    second = DashboardProjectStore(path)
    assert second.projects() == ["alpha", "beta"]
    assert second.stats("alpha")["attacks"] == 1
    assert second.stats("beta")["attacks"] == 1
    assert second.alerts("alpha")[0]["label"] == "PortScan"
    assert second.alerts("alpha")[0]["label"] != second.alerts("beta")[0]["label"]


def test_server_event_ingestion_is_project_scoped(tmp_path):
    app = create_dashboard_server_app(
        "admin",
        "secret",
        storage_path=str(tmp_path / "projects.json"),
    )
    client = TestClient(app)

    response = client.post(
        "/api/events",
        auth=("admin", "secret"),
        json={"project_id": "alpha", "label": "XSS", "severity": "HIGH"},
    )
    alpha = client.get("/api/stats?project_id=alpha", auth=("admin", "secret"))
    beta = client.get("/api/stats?project_id=beta", auth=("admin", "secret"))

    assert response.status_code == 200
    assert alpha.json()["attacks"] == 1
    assert beta.json()["attacks"] == 0