#!/usr/bin/env python3
"""
Turn an OWASP ZAP JSON report into a deduplicated, severity-sorted findings
table in Markdown, with per-finding evidence blocks ready to paste into the
assessment report.

Consumes the "traditional-json" report produced by zap-baseline.py -J,
zap-full-scan.py -J or an Automation Framework report job with
template: traditional-json. Alert instances of the same rule on the same
parameter are merged into one finding with an instance count, so a scanner
that fires 40 times on one parameter does not read as 40 findings.

Usage:
  python zap_alerts_report.py --report zap-report.json
  python zap_alerts_report.py --report zap-report.json --output findings.md
  python zap_alerts_report.py --report zap-report.json --min-risk Medium
"""

import argparse
import json
import re
import sys

RISK_ORDER = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}
MIN_RISK_VALUE = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}
CONFIDENCE_NAMES = {
    "0": "False Positive",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "User Confirmed",
}

def clean(text):
    """Strip HTML tags ZAP embeds in alert descriptions and collapse whitespace."""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text or "")).strip()


def md_inline(text):
    """Make a value safe inside single-backtick Markdown code spans."""
    return (text or "").replace("`", "'").replace("|", "\\|")


def load_alerts(report_path):
    """Return the flat alert list from a ZAP traditional-json report."""
    with open(report_path, encoding="utf-8") as handle:
        data = json.load(handle)
    alerts = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            alerts.append(alert)
    return alerts


def merge_alerts(alerts):
    """Merge alert instances of the same rule + parameter into one finding."""
    merged = {}
    for alert in alerts:
        instances = alert.get("instances") or [{}]
        for instance in instances:
            key = (
                alert.get("pluginid", ""),
                instance.get("param") or "",
            )
            finding = merged.setdefault(
                key,
                {
                    "pluginid": alert.get("pluginid", ""),
                    "alertRef": alert.get("alertRef", ""),
                    "name": alert.get("name", ""),
                    "riskcode": int(alert.get("riskcode", "0") or 0),
                    "risk": alert.get("riskdesc", "").split(" ", 1)[0],
                    "confidence": CONFIDENCE_NAMES.get(
                        alert.get("confidence", ""), alert.get("confidence", "")
                    ),
                    "cweid": alert.get("cweid", ""),
                    "desc": clean(alert.get("desc", "")),
                    "solution": clean(alert.get("solution", "")),
                    "reference": clean(alert.get("reference", "")),
                    "instances": [],
                },
            )
            finding["instances"].append(
                {
                    "uri": instance.get("uri", ""),
                    "param": instance.get("param") or "",
                    "attack": instance.get("attack") or "",
                    "evidence": instance.get("evidence") or "",
                    "method": instance.get("method") or "",
                }
            )
            # Keep the worst risk seen for this rule/param pair.
            code = int(alert.get("riskcode", "0") or 0)
            if code > finding["riskcode"]:
                finding["riskcode"] = code
                finding["risk"] = alert.get("riskdesc", "").split(" ", 1)[0]
    return list(merged.values())


def render(findings, min_risk):
    lines = [
        "# ZAP findings (deduplicated)",
        "",
        "| # | Risk | Confidence | Finding | Plugin | CWE | Param | Instances |",
        "|---|------|------------|---------|--------|-----|-------|-----------|",
    ]
    filtered = [
        f for f in findings if RISK_ORDER.get(f["risk"], 0) >= MIN_RISK_VALUE[min_risk]
    ]
    filtered.sort(key=lambda f: (-f["riskcode"], f["name"]))
    for number, finding in enumerate(filtered, start=1):
        params = sorted({i["param"] for i in finding["instances"] if i["param"]})
        lines.append(
            "| {number} | {risk} | {confidence} | {name} | {pluginid} | {cweid} | {params} | {count} |".format(
                number=number,
                risk=finding["risk"],
                confidence=finding["confidence"],
                name=finding["name"].replace("|", "\\|"),
                pluginid=finding["pluginid"],
                cweid=finding["cweid"] or "-",
                params=", ".join(params) or "-",
                count=len(finding["instances"]),
            )
        )
    lines.append("")
    for number, finding in enumerate(filtered, start=1):
        lines.append(f"## {number}. {finding['name']} ({finding['risk']})")
        lines.append("")
        lines.append(f"- Plugin ID: {finding['pluginid']} (alertRef {finding['alertRef']})")
        lines.append(f"- CWE: {finding['cweid'] or '-'}")
        lines.append(f"- Confidence: {finding['confidence']}")
        lines.append("")
        lines.append("**Evidence (verify each before reporting):**")
        lines.append("")
        for instance in finding["instances"][:5]:
            lines.append(f"- `{md_inline(instance['method'])}` `{md_inline(instance['uri'])}`")
            if instance["param"]:
                lines.append(f"  - Param: `{md_inline(instance['param'])}`")
            if instance["attack"]:
                lines.append(f"  - Attack: `{md_inline(instance['attack'])}`")
            if instance["evidence"]:
                lines.append(f"  - Evidence: `{md_inline(instance['evidence'])}`")
        if len(finding["instances"]) > 5:
            lines.append(f"- ... and {len(finding['instances']) - 5} more instances")
        lines.append("")
        if finding["desc"]:
            lines.append(f"**Description:** {finding['desc']}")
        if finding["solution"]:
            lines.append(f"**Suggested fix:** {finding['solution']}")
        lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--report", required=True, help="ZAP traditional-json report file")
    parser.add_argument("--output", help="Markdown output file (default: stdout)")
    parser.add_argument(
        "--min-risk",
        choices=MIN_RISK_VALUE,
        default="Low",
        help="drop findings below this risk level (default: Low)",
    )
    args = parser.parse_args()

    alerts = load_alerts(args.report)
    if not alerts:
        print("No alerts in report.", file=sys.stderr)
        sys.exit(1)
    findings = merge_alerts(alerts)
    markdown = render(findings, args.min_risk)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(markdown)
        print(f"Wrote {args.output}: {len(findings)} deduplicated findings.")
    else:
        print(markdown)


if __name__ == "__main__":
    main()
