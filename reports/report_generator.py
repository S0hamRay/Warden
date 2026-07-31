"""Generate JSON, HTML, and colored CLI summaries from findings."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from colorama import Fore, Style, init as colorama_init
from jinja2 import Environment, FileSystemLoader, select_autoescape

from scanner.findings import Finding, Severity, count_by_severity

colorama_init(autoreset=True)

SEVERITY_COLOR = {
    Severity.CRITICAL: Fore.RED + Style.BRIGHT,
    Severity.HIGH: Fore.YELLOW + Style.BRIGHT,
    Severity.MEDIUM: Fore.CYAN,
    Severity.LOW: Fore.GREEN + Style.DIM,
}


def generate_reports(
    findings: list[Finding],
    output_dir: str | Path = "reports",
    print_cli: bool = True,
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    summary = count_by_severity(findings)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }

    json_path = output / "report.json"
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    html_path = output / "report.html"
    html_path.write_text(_render_html(payload), encoding="utf-8")

    if print_cli:
        print_cli_summary(findings, summary)

    return payload


def _render_html(payload: dict[str, Any]) -> str:
    template_dir = Path(__file__).resolve().parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html.j2")
    return template.render(
        generated_at=payload["generated_at"],
        summary=payload["summary"],
        finding_count=payload["finding_count"],
        findings=payload["findings"],
    )


def print_cli_summary(
    findings: list[Finding],
    summary: dict[str, int] | None = None,
) -> None:
    summary = summary or count_by_severity(findings)
    print()
    print(Style.BRIGHT + "Warden Scan Summary" + Style.RESET_ALL)
    print("-" * 40)
    for sev in Severity:
        color = SEVERITY_COLOR[sev]
        print(f"{color}{sev.value:8}{Style.RESET_ALL} {summary.get(sev.value, 0)}")
    print("-" * 40)
    print(f"Total: {len(findings)}")
    print()

    if not findings:
        print(Fore.GREEN + "No findings." + Style.RESET_ALL)
        return

    print(Style.BRIGHT + "Findings" + Style.RESET_ALL)
    for finding in findings:
        color = SEVERITY_COLOR[finding.severity]
        print(
            f"{color}[{finding.severity.value}]{Style.RESET_ALL} "
            f"{finding.id} | {finding.module} | {finding.resource}"
        )
        print(f"  {finding.title}")
        print(f"  {finding.description}")
        print()
