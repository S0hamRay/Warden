"""Generate JSON, HTML, CLI, attack-path, and Graphviz outputs."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from colorama import Fore, Style, init as colorama_init
from jinja2 import Environment, FileSystemLoader, select_autoescape

from scanner.attack_graph.attack_path import AttackPath
from scanner.attack_graph.engine import AttackGraphEngine, render_dot_png
from scanner.attack_graph.graph import AssetGraph
from scanner.findings import Finding, Severity, count_by_severity

colorama_init(autoreset=True)
logger = logging.getLogger("warden.reports")

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
    attack_paths: list[AttackPath] | None = None,
    graph: AssetGraph | None = None,
    run_attack_graph: bool = True,
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    if run_attack_graph and (attack_paths is None or graph is None):
        engine = AttackGraphEngine()
        graph, attack_paths = engine.analyze(findings)
    attack_paths = attack_paths or []
    graph = graph or AssetGraph()

    summary = count_by_severity(findings)
    path_summary = _path_severity_counts(attack_paths)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
        "attack_path_summary": path_summary,
        "attack_path_count": len(attack_paths),
        "attack_paths": [p.to_dict() for p in attack_paths],
    }

    json_path = output / "report.json"
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    attack_paths_path = output / "attack_paths.json"
    attack_paths_path.write_text(
        json.dumps(
            {
                "generated_at": payload["generated_at"],
                "summary": path_summary,
                "count": len(attack_paths),
                "paths": payload["attack_paths"],
                "graph": graph.to_dict(),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    html_path = output / "report.html"
    html_path.write_text(_render_html(payload), encoding="utf-8")

    _write_graphviz(graph, attack_paths, output)

    if print_cli:
        print_cli_summary(findings, summary)
        print_attack_paths_cli(attack_paths)

    return payload


def _path_severity_counts(paths: list[AttackPath]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for path in paths:
        counts[path.severity.value] += 1
    return counts


def _write_graphviz(
    graph: AssetGraph,
    attack_paths: list[AttackPath],
    output: Path,
) -> None:
    highlight = [p.node_ids for p in attack_paths[:10]]
    dot_source = graph.to_dot(highlight_paths=highlight)
    dot_path = output / "attack_graph.dot"
    png_path = output / "attack_graph.png"
    rendered = render_dot_png(dot_source, str(dot_path), str(png_path))
    if rendered:
        logger.info("Wrote %s and %s", dot_path, png_path)
    else:
        logger.info("Wrote %s (PNG render requires Graphviz `dot`)", dot_path)


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
        attack_paths=payload.get("attack_paths", []),
        attack_path_summary=payload.get("attack_path_summary", {}),
        attack_path_count=payload.get("attack_path_count", 0),
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


def print_attack_paths_cli(paths: list[AttackPath]) -> None:
    print(Style.BRIGHT + "Attack Paths" + Style.RESET_ALL)
    print("=" * 40)
    if not paths:
        print(Fore.GREEN + "No attack paths correlated." + Style.RESET_ALL)
        print()
        return

    critical = sum(1 for p in paths if p.severity == Severity.CRITICAL)
    print(f"Critical Attack Paths: {critical}")
    print(f"Total Attack Paths: {len(paths)}")
    print("-" * 40)

    for idx, path in enumerate(paths[:15], start=1):
        color = SEVERITY_COLOR[path.severity]
        print()
        print(f"{color}Attack Path #{idx} [{path.severity.value}]{Style.RESET_ALL}")
        for i, name in enumerate(path.chain_labels()):
            print(name)
            if i < len(path.chain_labels()) - 1:
                print("↓")
        print(f"Risk Score: {path.score}")
        print(f"Business Impact: {path.business_impact}")
        if path.recommendations:
            print("Recommendations")
            for rec in path.recommendations:
                print(f"• {rec}")
    print()
