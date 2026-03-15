#!/usr/bin/env python3
"""Pass-the-Hash Detection - Analyzes authentication logs for NTLM-based lateral movement patterns."""

import json, csv, argparse, datetime, re
from collections import defaultdict
from pathlib import Path

SYSTEM_ACCOUNTS = {"system", "anonymous logon", "anonymous", "local service", "network service"}

def parse_logs(path):
    p = Path(path)
    if p.suffix == ".json":
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else data.get("events", [])
    elif p.suffix == ".csv":
        with open(p, encoding="utf-8-sig") as f:
            return [dict(r) for r in csv.DictReader(f)]
    return []

def detect_pth(event):
    eid = str(event.get("EventCode", event.get("EventID", "")))
    if eid != "4624": return None
    logon_type = str(event.get("Logon_Type", event.get("LogonType", "")))
    if logon_type != "3": return None
    auth_pkg = event.get("Authentication_Package", event.get("AuthenticationPackageName", "")).lower()
    if "ntlm" not in auth_pkg: return None
    account = event.get("Account_Name", event.get("TargetUserName", "")).lower()
    if account in SYSTEM_ACCOUNTS or account.endswith("$"): return None
    src_ip = event.get("Source_Network_Address", event.get("IpAddress", ""))
    if not src_ip or src_ip in ("-", "::1", "127.0.0.1"): return None
    return {
        "technique": "T1550.002",
        "account": event.get("Account_Name", event.get("TargetUserName", "")),
        "source_ip": src_ip,
        "dest_host": event.get("Computer", event.get("hostname", "")),
        "auth_package": auth_pkg,
        "logon_process": event.get("Logon_Process", event.get("LogonProcessName", "")),
        "timestamp": event.get("_time", event.get("timestamp", "")),
        "risk_score": 45,
        "risk_level": "MEDIUM",
        "indicators": ["Type 3 NTLM logon - potential Pass-the-Hash"],
    }

def analyze_velocity(findings, threshold=3):
    account_dests = defaultdict(set)
    for f in findings:
        account_dests[f["account"]].add(f["dest_host"])
    alerts = []
    for acct, dests in account_dests.items():
        if len(dests) >= threshold:
            alerts.append({
                "technique": "T1550.002", "account": acct,
                "unique_targets": len(dests), "targets": list(dests),
                "risk_score": 80, "risk_level": "CRITICAL",
                "indicators": [f"NTLM auth to {len(dests)} hosts - PtH spray pattern"],
            })
    return alerts

def run_hunt(input_path, output_dir):
    print(f"[*] Pass-the-Hash Hunt - {datetime.datetime.now().isoformat()}")
    events = parse_logs(input_path)
    findings = [f for f in (detect_pth(e) for e in events) if f]
    velocity = analyze_velocity(findings)
    all_findings = findings + velocity
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    with open(Path(output_dir) / "pth_findings.json", "w", encoding="utf-8") as f:
        json.dump({"hunt_id": f"TH-PTH-{datetime.date.today()}", "findings": all_findings}, f, indent=2)
    print(f"[+] {len(all_findings)} findings ({len(velocity)} velocity alerts)")

def main():
    p = argparse.ArgumentParser(description="Pass-the-Hash Detection")
    sp = p.add_subparsers(dest="cmd")
    h = sp.add_parser("hunt"); h.add_argument("--input", "-i", required=True); h.add_argument("--output", "-o", default="./pth_output")
    sp.add_parser("queries")
    args = p.parse_args()
    if args.cmd == "hunt": run_hunt(args.input, args.output)
    elif args.cmd == "queries":
        print("=== Splunk PtH Query ===")
        print('''index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
| stats count dc(Computer) as targets by Account_Name Source_Network_Address
| where targets > 3 | sort -targets''')
    else: p.print_help()

if __name__ == "__main__": main()
