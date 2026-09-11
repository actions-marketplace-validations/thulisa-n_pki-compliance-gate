from __future__ import annotations

from pathlib import Path
from certguard.doc_publisher import EnterpriseDocPublisher, generate_redline_diff


def test_generate_redline_diff() -> None:
    old_text = "Rule 1: RSA key size must be 2048 bits.\nRule 2: Max validity 398 days."
    new_text = "Rule 1: RSA key size must be 2048 bits.\nRule 2: Max validity 200 days."

    diff = generate_redline_diff(old_text, new_text)

    assert "# Policy-as-Code Redlined Compliance Diff Report" in diff
    assert "-Rule 2: Max validity 398 days." in diff
    assert "+Rule 2: Max validity 200 days." in diff


def test_enterprise_doc_publisher(tmp_path: Path) -> None:
    publisher = EnterpriseDocPublisher(output_dir=tmp_path)
    old_doc = "Max validity 398 days."
    new_doc = "Max validity 200 days."

    res = publisher.publish_package(
        policy_title="CA/Browser Forum BR v2.0",
        markdown_content=new_doc,
        old_markdown_content=old_doc,
    )

    assert res["status"] == "success"
    assert Path(res["artifacts"]["markdown"]).exists()
    assert Path(res["artifacts"]["html"]).exists()
    assert Path(res["artifacts"]["redline_diff"]).exists()
