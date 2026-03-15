#!/usr/bin/env python3
"""SIEM detection use case management agent with ATT&CK coverage mapping."""

import json
import sys
import argparse
from datetime import datetime
from collections import Counter

try:
    from attackcti import attack_client
except ImportError:
    print("Install attackcti: pip install attackcti")
    sys.exit(1)

try:
    import splunklib.client as splunk_client
    import splunklib.results as splunk_results
    HAS_SPLUNK = True
except ImportError:
    HAS_SPLUNK = False


USE_CASE_TEMPLATES = {
    "brute_force_login": {
        "name": "Brute Force Authentication Attempt",
        "technique": "T1110",
        "tactic": "credential-access",
        "data_sources": ["Windows Security 4625", "Linux auth.log", "VPN logs"],
        "splunk_query": ('index=wineventlog EventCode=4625 '
                         '| stats count by src_ip, TargetUserName '
                         '| where count > 10'),
        "threshold": 10,
        "severity": "high",
        "sla_response": "15 minutes",
    },
    "lateral_movement_psexec": {
        "name": "Lateral Movement via PsExec",
        "technique": "T1021.002",
        "tactic": "lateral-movement",
        "data_sources": ["Windows Security 7045", "Sysmon EventID 1"],
        "splunk_query": ('index=wineventlog EventCode=7045 '
                         'ServiceFileName="*PSEXESVC*" '
                         '| stats count by ComputerName, ServiceName'),
        "threshold": 1,
        "severity": "critical",
        "sla_response": "5 minutes",
    },
    "suspicious_powershell": {
        "name": "Suspicious PowerShell Execution",
        "technique": "T1059.001",
        "tactic": "execution",
        "data_sources": ["Sysmon EventID 1", "PowerShell 4104"],
        "splunk_query": ('index=sysmon EventCode=1 Image="*powershell.exe" '
                         '(CommandLine="*-enc*" OR CommandLine="*invoke-expression*" '
                         'OR CommandLine="*downloadstring*")'),
        "threshold": 1,
        "severity": "high",
        "sla_response": "10 minutes",
    },
    "data_exfiltration_dns": {
        "name": "DNS-Based Data Exfiltration",
        "technique": "T1048.003",
        "tactic": "exfiltration",
        "data_sources": ["DNS query logs", "Zeek dns.log"],
        "splunk_query": ('index=dns query_length>50 '
                         '| stats count dc(query) as unique_queries by src_ip '
                         '| where unique_queries > 100'),
        "threshold": 100,
        "severity": "high",
        "sla_response": "15 minutes",
    },
    "privilege_escalation_new_admin": {
        "name": "Privilege Escalation - New Admin Account",
        "technique": "T1098",
        "tactic": "persistence",
        "data_sources": ["Windows Security 4728", "Windows Security 4732"],
        "splunk_query": ('index=wineventlog (EventCode=4728 OR EventCode=4732) '
                         'TargetGroup="Administrators" '
                         '| stats count by SubjectUserName, MemberName, TargetGroup'),
        "threshold": 1,
        "severity": "critical",
        "sla_response": "5 minutes",
    },
    "credential_dumping_lsass": {
        "name": "Credential Dumping - LSASS Access",
        "technique": "T1003.001",
        "tactic": "credential-access",
        "data_sources": ["Sysmon EventID 10"],
        "splunk_query": ('index=sysmon EventCode=10 TargetImage="*lsass.exe" '
                         'NOT SourceImage IN ("*\\csrss.exe","*\\services.exe") '
                         '| stats count by SourceImage, SourceUser'),
        "threshold": 1,
        "severity": "critical",
        "sla_response": "5 minutes",
    },
    "ransomware_file_encryption": {
        "name": "Ransomware File Encryption Activity",
        "technique": "T1486",
        "tactic": "impact",
        "data_sources": ["Sysmon EventID 11", "Windows Security 4663"],
        "splunk_query": ('index=sysmon EventCode=11 '
                         '| stats dc(TargetFilename) as file_count by Image '
                         '| where file_count > 100'),
        "threshold": 100,
        "severity": "critical",
        "sla_response": "immediate",
    },
}


def get_attack_coverage(techniques_covered):
    """Calculate ATT&CK coverage percentage."""
    client = attack_client()
    all_techniques = client.get_techniques()
    enterprise = [t for t in all_techniques
                  if any("enterprise-attack" in ref.get("url", "")
                         for ref in t.get("external_references", []))]
    total = len(enterprise)
    covered = len(set(techniques_covered))
    return {"total_techniques": total, "covered": covered,
            "coverage_pct": round(covered / max(total, 1) * 100, 1)}


def map_use_cases_to_attack():
    """Map all use case templates to ATT&CK techniques and tactics."""
    tactic_coverage = Counter()
    technique_list = []
    for uc_id, uc in USE_CASE_TEMPLATES.items():
        tactic_coverage[uc["tactic"]] += 1
        technique_list.append(uc["technique"])
    return {"tactics": dict(tactic_coverage), "techniques": technique_list,
            "total_use_cases": len(USE_CASE_TEMPLATES)}


def validate_use_case_data_sources(use_case_id):
    """Validate that required data sources are available for a use case."""
    uc = USE_CASE_TEMPLATES.get(use_case_id)
    if not uc:
        return {"error": f"Use case {use_case_id} not found"}
    return {
        "use_case": uc["name"],
        "required_data_sources": uc["data_sources"],
        "validation_note": "Verify these log sources are ingested into SIEM with correct parsing",
    }


def generate_sigma_rule(use_case_id):
    """Generate a Sigma detection rule for a use case."""
    uc = USE_CASE_TEMPLATES.get(use_case_id)
    if not uc:
        return None
    return {
        "title": uc["name"],
        "id": f"sigma-{use_case_id}",
        "status": "experimental",
        "description": f"Detects {uc['name']} mapped to ATT&CK {uc['technique']}",
        "references": [f"https://attack.mitre.org/techniques/{uc['technique'].replace('.', '/')}/"],
        "tags": [f"attack.{uc['tactic']}", f"attack.{uc['technique'].lower()}"],
        "logsource": {"product": "windows", "service": "security"},
        "detection": {"condition": "selection"},
        "level": uc["severity"],
        "falsepositives": ["Legitimate administrative activity"],
    }


def run_detection_coverage_report():
    """Generate SIEM detection coverage report."""
    print(f"\n{'='*60}")
    print(f"  SIEM DETECTION USE CASE REPORT")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    mapping = map_use_cases_to_attack()
    print(f"--- USE CASE LIBRARY ({mapping['total_use_cases']} rules) ---")
    for uc_id, uc in USE_CASE_TEMPLATES.items():
        print(f"  [{uc['severity'].upper():>8}] {uc['name']}")
        print(f"           ATT&CK: {uc['technique']} ({uc['tactic']}) | SLA: {uc['sla_response']}")

    print(f"\n--- TACTIC COVERAGE ---")
    for tactic, count in sorted(mapping["tactics"].items(), key=lambda x: -x[1]):
        bar = "#" * count
        print(f"  {tactic:<25} {bar} ({count})")

    print(f"\n--- ATT&CK COVERAGE ---")
    try:
        coverage = get_attack_coverage(mapping["techniques"])
        print(f"  Total Enterprise Techniques: {coverage['total_techniques']}")
        print(f"  Covered by Use Cases:        {coverage['covered']}")
        print(f"  Coverage Percentage:         {coverage['coverage_pct']}%")
    except Exception as e:
        print(f"  Could not calculate coverage: {e}")

    print(f"\n--- DATA SOURCE REQUIREMENTS ---")
    all_sources = set()
    for uc in USE_CASE_TEMPLATES.values():
        all_sources.update(uc["data_sources"])
    for src in sorted(all_sources):
        print(f"  - {src}")

    print(f"\n{'='*60}\n")
    return {"use_cases": mapping, "data_sources": list(all_sources)}


def main():
    parser = argparse.ArgumentParser(description="SIEM Use Case Detection Agent")
    parser.add_argument("--report", action="store_true", help="Generate detection coverage report")
    parser.add_argument("--sigma", help="Generate Sigma rule for use case ID")
    parser.add_argument("--validate", help="Validate data sources for use case ID")
    parser.add_argument("--output", help="Save report to JSON")
    args = parser.parse_args()

    if args.report:
        report = run_detection_coverage_report()
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
    elif args.sigma:
        rule = generate_sigma_rule(args.sigma)
        print(json.dumps(rule, indent=2) if rule else f"Use case '{args.sigma}' not found")
    elif args.validate:
        result = validate_use_case_data_sources(args.validate)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
