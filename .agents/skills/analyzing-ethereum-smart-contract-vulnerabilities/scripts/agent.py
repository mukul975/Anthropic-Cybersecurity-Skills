#!/usr/bin/env python3
"""Smart Contract Security Agent - runs Slither and Mythril analysis on Solidity contracts."""

import json
import argparse
import logging
import subprocess
import os
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SWC_REGISTRY = {
    "SWC-101": "Integer Overflow and Underflow",
    "SWC-104": "Unchecked Call Return Value",
    "SWC-106": "Unprotected SELFDESTRUCT",
    "SWC-107": "Reentrancy",
    "SWC-110": "Assert Violation",
    "SWC-112": "Delegatecall to Untrusted Callee",
    "SWC-113": "DoS with Failed Call",
    "SWC-115": "Authorization through tx.origin",
    "SWC-116": "Block values as a proxy for time",
    "SWC-120": "Weak Sources of Randomness",
}


def run_slither(contract_path):
    """Run Slither static analysis on Solidity contract."""
    cmd = ["slither", contract_path, "--json", "-"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    try:
        return json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        logger.error("Slither JSON parse failed")
        return {}


def run_mythril(contract_path, timeout=300):
    """Run Mythril symbolic execution analysis."""
    cmd = ["myth", "analyze", contract_path, "--execution-timeout", str(timeout), "-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60)
    try:
        return json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        logger.error("Mythril JSON parse failed")
        return {}


def analyze_slither_results(slither_output):
    """Parse and categorize Slither detector findings."""
    findings = []
    by_severity = defaultdict(int)
    by_detector = defaultdict(int)
    for detector in slither_output.get("results", {}).get("detectors", []):
        severity = detector.get("impact", "informational").lower()
        by_severity[severity] += 1
        det_name = detector.get("check", "unknown")
        by_detector[det_name] += 1
        elements = detector.get("elements", [])
        location = ""
        if elements:
            elem = elements[0]
            location = f"{elem.get('source_mapping', {}).get('filename_short', '')}:" \
                       f"L{elem.get('source_mapping', {}).get('lines', [0])[0] if elem.get('source_mapping', {}).get('lines') else 0}"
        findings.append({
            "detector": det_name,
            "severity": severity,
            "description": detector.get("description", "")[:200],
            "location": location,
            "confidence": detector.get("confidence", ""),
        })
    return {
        "total": len(findings),
        "by_severity": dict(by_severity),
        "by_detector": dict(sorted(by_detector.items(), key=lambda x: x[1], reverse=True)[:15]),
        "findings": sorted(findings, key=lambda x: {"high": 0, "medium": 1, "low": 2, "informational": 3}.get(x["severity"], 4)),
    }


def analyze_mythril_results(mythril_output):
    """Parse Mythril symbolic execution findings."""
    findings = []
    by_swc = defaultdict(int)
    for issue in mythril_output.get("issues", []):
        swc_id = issue.get("swc-id", "")
        swc_key = f"SWC-{swc_id}" if swc_id else "unknown"
        by_swc[swc_key] += 1
        severity = issue.get("severity", "Medium").lower()
        findings.append({
            "swc_id": swc_key,
            "swc_title": SWC_REGISTRY.get(swc_key, issue.get("title", "")),
            "severity": severity,
            "description": issue.get("description", "")[:200],
            "contract": issue.get("contract", ""),
            "function": issue.get("function", ""),
            "line_number": issue.get("lineno", 0),
        })
    return {
        "total": len(findings),
        "by_swc": dict(by_swc),
        "findings": findings,
    }


def deduplicate_findings(slither_findings, mythril_findings):
    """Merge and deduplicate findings from both tools."""
    combined = []
    seen = set()
    for f in slither_findings.get("findings", []):
        key = (f.get("location", ""), f.get("detector", ""))
        if key not in seen:
            seen.add(key)
            combined.append({**f, "source": "slither"})
    for f in mythril_findings.get("findings", []):
        key = (f.get("contract", "") + str(f.get("line_number", 0)), f.get("swc_id", ""))
        if key not in seen:
            seen.add(key)
            combined.append({**f, "source": "mythril"})
    return combined


def generate_report(contract_path, slither_analysis, mythril_analysis, combined):
    critical_high = sum(1 for f in combined if f.get("severity") in ("high", "critical"))
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "contract": contract_path,
        "slither_analysis": {
            "total_findings": slither_analysis["total"],
            "by_severity": slither_analysis["by_severity"],
            "top_detectors": slither_analysis["by_detector"],
        },
        "mythril_analysis": {
            "total_findings": mythril_analysis["total"],
            "by_swc": mythril_analysis["by_swc"],
        },
        "combined_findings": len(combined),
        "critical_high_findings": critical_high,
        "audit_result": "FAIL" if critical_high > 0 else "PASS",
        "findings": combined[:30],
    }


def main():
    parser = argparse.ArgumentParser(description="Solidity Smart Contract Security Analysis Agent")
    parser.add_argument("--contract", required=True, help="Path to Solidity contract or project directory")
    parser.add_argument("--mythril-timeout", type=int, default=300, help="Mythril execution timeout (seconds)")
    parser.add_argument("--skip-mythril", action="store_true", help="Skip Mythril (slow symbolic execution)")
    parser.add_argument("--output", default="smart_contract_audit_report.json")
    args = parser.parse_args()

    slither_output = run_slither(args.contract)
    slither_analysis = analyze_slither_results(slither_output)
    mythril_analysis = {"total": 0, "by_swc": {}, "findings": []}
    if not args.skip_mythril:
        mythril_output = run_mythril(args.contract, args.mythril_timeout)
        mythril_analysis = analyze_mythril_results(mythril_output)
    combined = deduplicate_findings(slither_analysis, mythril_analysis)
    report = generate_report(args.contract, slither_analysis, mythril_analysis, combined)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Smart contract audit: %d findings (%d critical/high), result: %s",
                report["combined_findings"], report["critical_high_findings"], report["audit_result"])
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
