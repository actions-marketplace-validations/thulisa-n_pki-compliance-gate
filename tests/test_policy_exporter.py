from __future__ import annotations

from pathlib import Path
from certguard.policy_exporter import export_policy_to_markdown


def test_export_policy_to_markdown(tmp_path: Path) -> None:
    policy_file = Path("policies/cabf_policy.yaml")
    out_file = tmp_path / "CPS_SECTION_7.md"
    
    content = export_policy_to_markdown(policy_file, out_file)
    
    assert out_file.exists()
    assert "# Certificate Policy Specification (CP/CPS Section 7)" in content
    assert "CABF-BR-6.3.2" in content
    assert "Validity Period" in content
    assert "200 days" in content
