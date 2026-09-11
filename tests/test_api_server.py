from __future__ import annotations

from pathlib import Path
from fastapi.testclient import TestClient

from api.server import app

client = TestClient(app)


def test_health_check() -> None:
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["service"] == "CertGuard Enterprise SaaS API"


def test_evaluate_cert_endpoint() -> None:
    cert_pem = Path("tests/certificates/valid_cert.pem").read_text(encoding="utf-8")
    response = client.post("/api/v1/evaluate-cert", json={"cert_pem": cert_pem})
    assert response.status_code == 200
    data = response.json()
    assert "compliant" in data
    assert "report" in data


def test_scan_endpoint_api() -> None:
    response = client.post("/api/v1/scan-endpoint", json={"endpoint": "example.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["agent"] == "api_tls_posture_agent"
    assert "success" in data


def test_publish_redline_api() -> None:
    response = client.post(
        "/api/v1/publish-redline",
        json={
            "policy_title": "Test Policy",
            "new_policy_text": "Validity: 200 days",
            "old_policy_text": "Validity: 398 days",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "artifacts" in data
