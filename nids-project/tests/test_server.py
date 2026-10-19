"""Tests for standalone dashboard project isolation and persistence."""

import json
from concurrent.futures import ThreadPoolExecutor

from starlette.testclient import TestClient

from netguard.web.server import DashboardProjectStore, create_dashboard_server_app


def test_project_store_persists_and_isolates_alerts(tmp_path):
    path = str(tmp_path / "projects.sqlite3")
    first = DashboardProjectStore(path)
    first.ingest("alpha", {"label": "PortScan", "severity": "MEDIUM"})
    first.ingest("beta", {"label": "DoS", "severity": "CRITICAL"})

    second = DashboardProjectStore(path)
    assert second.projects() == ["alpha", "beta"]
    assert second.stats("alpha")["attacks"] == 1
    assert second.stats("beta")["attacks"] == 1
    assert second.alerts("alpha")[0]["label"] == "PortScan"
    assert second.alerts("alpha")[0]["label"] != second.alerts("beta")[0]["label"]
    with open(path, "rb") as database:
        assert database.read(16) == b"SQLite format 3\x00"


def test_project_store_migrates_existing_json_file(tmp_path):
    path = tmp_path / "projects.json"
    path.write_text(json.dumps({
        "alpha": {
            "requests": 12,
            "attacks": 3,
            "alerts": [{"label": "PortScan", "severity": "MEDIUM"}],
        }
    }), encoding="utf-8")

    store = DashboardProjectStore(str(path))

    assert store.stats("alpha")["requests"] == 12
    assert store.stats("alpha")["attacks"] == 3
    assert store.alerts("alpha")[0]["label"] == "PortScan"
    assert path.read_bytes().startswith(b"SQLite format 3\x00")


def test_default_store_imports_legacy_json_without_replacing_it(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    legacy_path = tmp_path / "netguard-projects.json"
    legacy_path.write_text(json.dumps({
        "old-app": {
            "requests": 4,
            "attacks": 1,
            "alerts": [{"label": "XSS", "severity": "HIGH"}],
        }
    }), encoding="utf-8")
    app = create_dashboard_server_app("admin", "secret")

    with TestClient(app) as client:
        response = client.get("/api/stats?project_id=old-app", auth=("admin", "secret"))

    assert response.json()["requests"] == 4
    assert response.json()["attacks"] == 1
    assert json.loads(legacy_path.read_text(encoding="utf-8"))["old-app"]["attacks"] == 1
    assert (tmp_path / "netguard-projects.sqlite3").read_bytes().startswith(b"SQLite format 3\x00")


def test_project_store_handles_concurrent_writers(tmp_path):
    store = DashboardProjectStore(str(tmp_path / "projects.sqlite3"))
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(
            lambda index: store.ingest("alpha", {"label": f"event-{index}"}),
            range(40),
        ))

    assert store.stats("alpha")["attacks"] == 40
    assert len(store.alerts("alpha")) == 40


def test_server_event_ingestion_is_project_scoped(tmp_path):
    app = create_dashboard_server_app(
        "admin",
        "secret",
        storage_path=str(tmp_path / "projects.sqlite3"),
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


def test_server_telemetry_ingestion_populates_client_activity(tmp_path):
    app = create_dashboard_server_app(
        "admin",
        "secret",
        storage_path=str(tmp_path / "projects.sqlite3"),
    )
    client = TestClient(app)
    response = client.post(
        "/api/telemetry",
        auth=("admin", "secret"),
        json={
            "project_id": "alpha",
            "stats": {
                "total_requests": 18,
                "total_attacks": 2,
                "blocked_ips_count": 1,
                "threat_level": "ELEVATED",
                "top_clients": [{"ip": "198.51.100.8", "requests": 18, "attacks": 2}],
                "recent_events": [{"client_ip": "198.51.100.8", "path": "/login", "label": "BruteForce"}],
            },
        },
    )

    stats = client.get("/api/stats?project_id=alpha", auth=("admin", "secret")).json()

    assert response.status_code == 200
    assert stats["total_requests"] == 18
    assert stats["top_clients"][0]["ip"] == "198.51.100.8"
    assert stats["recent_events"][0]["client_ip"] == "198.51.100.8"
    assert stats["blocked_ips_count"] == 1
