from __future__ import annotations

from pathlib import Path
import yaml


def export_policy_to_markdown(policy_path: str | Path, output_path: str | Path | None = None) -> str:
    """Compile a Policy-as-Code YAML file into human-readable CP/CPS Section 7 Markdown documentation.
    
    Acts as the Single Source of Truth generator ensuring CP/CPS prose documentation
    never drifts from the automated enforcement rules in CI/CD.
    """
    path = Path(policy_path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    metadata = data.get("metadata", {})
    terms = data.get("terms", [])
    cert_cfg = data.get("certificate", {})
    key_cfg = data.get("key", {})
    sig_cfg = data.get("signature", {})
    domain_cfg = data.get("domains", {})

    lines: list[str] = []
    lines.append(f"# Certificate Policy Specification (CP/CPS Section 7)")
    lines.append("")
    lines.append(f"> **Standard**: {metadata.get('standard', 'CA/Browser Forum Baseline Requirements')}")
    lines.append(f"> **Policy Version**: {metadata.get('version', '1.0.0')}")
    lines.append(f"> **Last Updated**: {metadata.get('last_updated', 'N/A')}")
    lines.append(f"> **Source Profile**: `{path.name}`")
    lines.append("")
    lines.append("## 7.1 Certificate Profiles & Technical Controls")
    lines.append("")
    lines.append("This document represents the authoritative single source of truth for technical certificate profiles.")
    lines.append("Pre-issuance linting and CI/CD compliance gates evaluate certificates directly against these requirements.")
    lines.append("")
    lines.append("### 7.1.1 Enforced Normative Terms")
    lines.append("")
    lines.append("| Rule ID | Title | Summary / Governance Description |")
    lines.append("| :--- | :--- | :--- |")

    for term in terms:
        t_id = term.get("id", "N/A")
        title = term.get("title", "Untitled Term")
        summary = term.get("summary", "")
        lines.append(f"| **{t_id}** | {title} | {summary} |")

    lines.append("")
    lines.append("### 7.1.2 Technical Parameter Constraints")
    lines.append("")
    lines.append("| Parameter Category | Policy Requirement | Enforced Value |")
    lines.append("| :--- | :--- | :--- |")
    lines.append(f"| **Validity Period** | Max Allowed Lifetime | `{cert_cfg.get('max_validity_days', 'N/A')} days` |")
    lines.append(f"| **Subject Alt Name** | SAN Extension Required | `{cert_cfg.get('require_san', True)}` |")
    lines.append(f"| **Key Size** | Minimum RSA Key Size | `{key_cfg.get('minimum_rsa_bits', 2048)} bits` |")
    
    prohibited_algs = ", ".join(sig_cfg.get("prohibited_algorithms", ["sha1", "md5"])).upper()
    lines.append(f"| **Signature Algorithm** | Prohibited Hash Algorithms | `{prohibited_algs}` |")

    blocked_suffixes = ", ".join(domain_cfg.get("blocked_suffixes", [".local", ".internal"]))
    lines.append(f"| **Domain Names** | Forbid Internal Names | `{domain_cfg.get('forbid_internal_names', True)}` (Blocked: `{blocked_suffixes}`) |")

    lines.append("")
    lines.append("---")
    lines.append("*Generated automatically by CertGuard Engine Policy Exporter.*")

    markdown_content = "\n".join(lines)

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(markdown_content, encoding="utf-8")

    return markdown_content
