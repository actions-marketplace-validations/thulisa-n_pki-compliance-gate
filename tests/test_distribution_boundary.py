"""Static guardrails for the public package and trusted publisher."""

import tomllib
from pathlib import Path


def test_public_distribution_only_discovers_core_namespace() -> None:
    with Path("pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)

    assert project["project"]["name"] == "pki-compliance-gate"
    assert project["tool"]["setuptools"]["packages"]["find"]["include"] == [
        "certguard",
        "certguard.*",
    ]


def test_pypi_job_is_pinned_to_public_repository() -> None:
    workflow = Path(".github/workflows/publish.yml").read_text(encoding="utf-8")

    assert "github.repository == 'thulisa-n/pki-compliance-gate'" in workflow
