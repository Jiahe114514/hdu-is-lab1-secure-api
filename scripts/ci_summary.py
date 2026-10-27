"""Render a short Markdown summary of the SAST/SCA reports for GitHub Actions."""

from __future__ import annotations

import json
import pathlib


def main() -> None:
    report_dir = pathlib.Path("reports")

    bandit_file = report_dir / "bandit.json"
    if bandit_file.exists():
        totals = json.loads(bandit_file.read_text())["metrics"]["_totals"]
        print(
            "- **SAST (bandit)**: "
            f"{totals.get('SEVERITY.HIGH', 0)} high, "
            f"{totals.get('SEVERITY.MEDIUM', 0)} medium, "
            f"{totals.get('SEVERITY.LOW', 0)} low severity findings "
            f"across {totals.get('loc', 0)} lines of code"
        )
    else:
        print("- **SAST (bandit)**: report missing")

    audit_file = report_dir / "pip-audit.json"
    if audit_file.exists():
        dependencies = json.loads(audit_file.read_text()).get("dependencies", [])
        vulnerable = [dep for dep in dependencies if dep.get("vulns")]
        print(
            f"- **SCA (pip-audit)**: {len(vulnerable)} vulnerable of "
            f"{len(dependencies)} dependencies"
        )
        for dep in vulnerable:
            ids = ", ".join(vuln.get("id", "?") for vuln in dep["vulns"])
            print(f"  - {dep['name']} {dep['version']}: {ids}")
    else:
        print("- **SCA (pip-audit)**: report missing")


if __name__ == "__main__":
    main()
