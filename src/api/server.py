from __future__ import annotations

from pathlib import Path
import tempfile
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from certguard.agents.api_tls_posture import ApiTlsPostureAgent
from certguard.doc_publisher import EnterpriseDocPublisher, generate_redline_diff
from certguard.engine import ComplianceGateEngine


app = FastAPI(
    title="CertGuard Enterprise SaaS API",
    description="REST API for Automated PKI Compliance, Active TLS Posture Scanning, & Policy Redlining",
    version="1.0.0",
)


class EvaluateCertRequest(BaseModel):
    cert_pem: str = Field(..., description="X.509 Certificate in PEM format")
    policy_path: str = Field(default="policies/cabf_policy.yaml", description="Path to policy YAML file")


class ScanEndpointRequest(BaseModel):
    endpoint: str = Field(..., description="Target domain or URL (e.g. example.com or https://api.bank.com)")


class PublishRedlineRequest(BaseModel):
    policy_title: str = Field(default="CA/Browser Forum Baseline Requirements", description="Document title")
    new_policy_text: str = Field(..., description="Current/Updated policy text or markdown")
    old_policy_text: str | None = Field(default=None, description="Previous policy text for redline diff generation")


@app.get("/")
def health_check() -> dict[str, str]:
    return {
        "status": "online",
        "service": "CertGuard Enterprise SaaS API",
        "version": "1.0.0",
    }


@app.post("/api/v1/evaluate-cert")
def evaluate_cert(payload: EvaluateCertRequest) -> dict[str, Any]:
    """Evaluate an X.509 certificate PEM string against policy rules."""
    if not payload.cert_pem.strip():
        raise HTTPException(status_code=400, detail="Certificate PEM content cannot be empty.")

    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as tmp:
        tmp.write(payload.cert_pem)
        tmp_path = Path(tmp.name)

    try:
        report_path = tmp_path.parent / f"{tmp_path.stem}_report.json"
        evidence_dir = tmp_path.parent / f"{tmp_path.stem}_evidence"
        engine = ComplianceGateEngine(policy_path=Path(payload.policy_path))
        compliant, report = engine.evaluate(
            cert_path=tmp_path,
            report_path=report_path,
            evidence_dir=evidence_dir,
        )
        return {
            "compliant": compliant,
            "report": report.to_dict(),
        }
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


@app.post("/api/v1/scan-endpoint")
def scan_endpoint(payload: ScanEndpointRequest) -> dict[str, Any]:
    """Scan active domain TLS posture & return compliance findings."""
    if not payload.endpoint.strip():
        raise HTTPException(status_code=400, detail="Endpoint domain or URL cannot be empty.")

    agent = ApiTlsPostureAgent()
    result = agent.run({"endpoint": payload.endpoint})
    return {
        "agent": result.agent,
        "success": result.success,
        "endpoint": result.data.get("endpoint"),
        "tls_version": result.data.get("tls_version"),
        "cipher_suite": result.data.get("cipher_suite"),
        "risk_level": result.data.get("risk_level"),
        "checks": [check.to_dict() for check in result.checks],
    }


@app.post("/api/v1/publish-redline")
def publish_redline(payload: PublishRedlineRequest) -> dict[str, Any]:
    """Generate redline document diff and publish multi-format compliance package."""
    publisher = EnterpriseDocPublisher()
    result = publisher.publish_package(
        policy_title=payload.policy_title,
        markdown_content=payload.new_policy_text,
        old_markdown_content=payload.old_policy_text,
    )
    return result
