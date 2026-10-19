"""
tests/test_packaging_smoke.py
------------------------------
Packaging and release smoke test:
Validates that netguard can be imported, loads the bundled model from an arbitrary
working directory, initializes the canonical NetGuard core, and starts the FastAPI integration.
"""

import os
import tempfile
import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

import netguard
from netguard import NetGuard
from netguard.detection import DetectionEngine
from netguard.integrations.fastapi import setup_netguard


def test_package_metadata():
    """Package should expose canonical __version__ and __all__."""
    assert hasattr(netguard, "__version__")
    assert netguard.__version__ == "0.2.0"
    assert "NetGuard" in netguard.__all__
    assert "DetectionEngine" in netguard.__all__


def test_bundled_model_loading_from_arbitrary_cwd():
    """
    DetectionEngine should locate and load its bundled model artifacts even when
    the current working directory is an unrelated temporary directory.
    """
    original_cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as tmp_dir:
        try:
            os.chdir(tmp_dir)
            engine = DetectionEngine().load()
            assert engine.is_loaded
            assert len(engine.features) == 20
            assert "BENIGN" in engine.classes
        finally:
            os.chdir(original_cwd)


def test_fastapi_integration_smoke():
    """
    Smoke test: initialize NetGuard, attach to FastAPI app, and verify authenticated
    endpoints and middleware flow.
    """
    app = FastAPI()
    guard = NetGuard(
        project_id="smoke-app",
        auth_username="admin",
        auth_password="secret-password",
    )
    setup_netguard(app, guard)

    client = TestClient(app)

    # 1. Unauthenticated health check should fail with 401
    unauth_resp = client.get("/netguard/health")
    assert unauth_resp.status_code == 401

    # 2. Authenticated health check should succeed with 200
    auth_resp = client.get("/netguard/health", auth=("admin", "secret-password"))
    assert auth_resp.status_code == 200
    data = auth_resp.json()
    assert data["status"] == "ok"
    assert data["project_id"] == "smoke-app"
    assert data["threat_level"] == "NOMINAL"
    assert guard.engine.is_loaded is True


