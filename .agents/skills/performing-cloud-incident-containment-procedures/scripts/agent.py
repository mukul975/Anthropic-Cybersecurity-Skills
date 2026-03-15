#!/usr/bin/env python3
"""Cloud incident containment agent."""
import argparse, json, sys
from datetime import datetime, timezone
try:
    import requests
except ImportError:
    requests = None

def run_scan(target, token=None):
    findings = []
    if not requests: return [{"error": "requests required"}]
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        resp = requests.get(f"{target}", headers=headers, timeout=15)
        if resp.status_code == 200:
            findings.append({"check": "Target Accessible", "status": "OK", "severity": "INFO"})
        else:
            findings.append({"check": "Target Access", "status": f"HTTP {resp.status_code}", "severity": "MEDIUM"})
    except requests.RequestException as e:
        findings.append({"error": str(e)})
    return findings

def analyze_results(target, token=None):
    findings = []
    if not requests: return []
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        resp = requests.get(f"{target}/api/v1/results", headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("findings", data.get("results", [])):
                severity = item.get("severity", item.get("risk", "MEDIUM"))
                findings.append({"check": item.get("name", item.get("title", "unknown")),
                                 "severity": severity.upper() if isinstance(severity, str) else "MEDIUM"})
    except requests.RequestException:
        pass
    return findings

def main():
    p = argparse.ArgumentParser(description="Cloud incident containment agent")
    p.add_argument("--target", required=True, help="Target URL or IP")
    p.add_argument("--token", help="API token")
    p.add_argument("--output", "-o", help="Output JSON report")
    p.add_argument("--verbose", "-v", action="store_true")
    a = p.parse_args()
    print("[*] Cloud incident containment agent")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "target": a.target, "findings": []}
    report["findings"].extend(run_scan(a.target, a.token))
    report["findings"].extend(analyze_results(a.target, a.token))
    high = sum(1 for f in report["findings"] if f.get("severity") in ("HIGH", "CRITICAL"))
    report["risk_level"] = "CRITICAL" if high > 2 else "HIGH" if high else "MEDIUM" if report["findings"] else "LOW"
    print(f"[*] {len(report['findings'])} findings, risk: {report['risk_level']}")
    if a.output:
        with open(a.output, "w") as f: json.dump(report, f, indent=2)
    else:
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
