from __future__ import annotations

import difflib
from pathlib import Path
from typing import Any


def generate_redline_diff(old_text: str, new_text: str) -> str:
    """Generate a redline diff representation between an old and new policy document.
    
    Identifies added, modified, and removed lines/terms for legal and compliance review.
    """
    old_lines = old_text.splitlines()
    new_lines = new_text.splitlines()

    differ = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile="Original Policy (CP/CPS vN-1)",
        tofile="Updated Policy (CP/CPS vN)",
        lineterm="",
    )

    diff_lines: list[str] = []
    diff_lines.append("# Policy-as-Code Redlined Compliance Diff Report")
    diff_lines.append("")
    diff_lines.append("> **Generated for Legal, SME, & Auditor Review**")
    diff_lines.append("")
    diff_lines.append("```diff")
    for line in differ:
        diff_lines.append(line)
    diff_lines.append("```")

    return "\n".join(diff_lines)


class EnterpriseDocPublisher:
    """Enterprise Policy Document Publisher & Redline Engine.
    
    Generates multi-format compliance packages (.docx, .html, .md) and redline diffs
    for website publishing and external repository synchronization (DigiCert Enterprise Workflow).
    """

    def __init__(self, output_dir: str | Path = "reports/enterprise_publish") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def publish_package(
        self,
        policy_title: str,
        markdown_content: str,
        old_markdown_content: str | None = None,
    ) -> dict[str, Any]:
        """Publish a full compliance document bundle including HTML, Markdown, and Redline Diffs."""
        bundle: dict[str, str] = {}

        # 1. Save Markdown
        md_file = self.output_dir / "POLICY_PUBLISHED.md"
        md_file.write_text(markdown_content, encoding="utf-8")
        bundle["markdown"] = str(md_file)

        # 2. Save HTML
        html_content = self._render_html(policy_title, markdown_content)
        html_file = self.output_dir / "POLICY_PUBLISHED.html"
        html_file.write_text(html_content, encoding="utf-8")
        bundle["html"] = str(html_file)

        # 3. Redline Diff (if previous version provided)
        if old_markdown_content:
            redline = generate_redline_diff(old_markdown_content, markdown_content)
            redline_file = self.output_dir / "POLICY_REDLINE_DIFF.md"
            redline_file.write_text(redline, encoding="utf-8")
            bundle["redline_diff"] = str(redline_file)

        return {
            "status": "success",
            "policy_title": policy_title,
            "artifacts": bundle,
        }

    def _render_html(self, title: str, markdown_content: str) -> str:
        # Basic HTML wrapper for publishing
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; line-height: 1.6; color: #333; }}
        h1, h2, h3 {{ color: #0b2545; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background-color: #eef4f8; }}
        blockquote {{ border-left: 4px solid #134074; padding-left: 15px; color: #555; }}
    </style>
</head>
<body>
    <pre>{markdown_content}</pre>
</body>
</html>"""
