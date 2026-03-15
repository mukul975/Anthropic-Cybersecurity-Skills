#!/usr/bin/env python3
"""DCSync attack detection agent for Active Directory environments.

Parses Windows Security Event ID 4662 logs to detect non-domain-controller
accounts requesting directory replication (DCSync technique T1003.006).
"""

import argparse
import json
import re
import sys
from datetime import datetime

try:
    import Evtx.Evtx as evtx
except ImportError:
    evtx = None

REPLICATION_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}

KNOWN_REPLICATION_ACCOUNTS = set()


def load_dc_accounts(filepath):
    if not filepath:
        return set()
    accounts = set()
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                accounts.add(line.upper())
    return accounts


def parse_4662_events(filepath, dc_accounts):
    if evtx is None:
        return {"error": "python-evtx not installed: pip install python-evtx"}
    findings = []
    total_4662 = 0

    with evtx.Evtx(filepath) as log:
        for record in log.records():
            xml = record.xml()
            if "<EventID>4662</EventID>" not in xml:
                continue
            total_4662 += 1

            props = re.search(r'<Data Name="Properties">([^<]+)', xml)
            if not props:
                continue
            prop_text = props.group(1).lower()

            matched_rights = []
            for guid, name in REPLICATION_GUIDS.items():
                if guid in prop_text:
                    matched_rights.append(name)
            if not matched_rights:
                continue

            subject = re.search(r'<Data Name="SubjectUserName">([^<]+)', xml)
            domain = re.search(r'<Data Name="SubjectDomainName">([^<]+)', xml)
            logon_id = re.search(r'<Data Name="SubjectLogonId">([^<]+)', xml)
            object_name = re.search(r'<Data Name="ObjectName">([^<]+)', xml)
            time_created = re.search(r'SystemTime="([^"]+)"', xml)
            computer = re.search(r'<Computer>([^<]+)', xml)

            subject_name = subject.group(1) if subject else ""
            domain_name = domain.group(1) if domain else ""
            full_account = f"{domain_name}\\{subject_name}".upper()

            if subject_name.endswith("$"):
                if subject_name.upper().rstrip("$") in dc_accounts or \
                   full_account.rstrip("$") in dc_accounts:
                    continue

            if subject_name.upper() in dc_accounts or full_account in dc_accounts:
                continue

            is_machine = subject_name.endswith("$")
            severity = "HIGH" if is_machine else "CRITICAL"

            findings.append({
                "event_id": 4662,
                "timestamp": time_created.group(1) if time_created else "",
                "subject_user": subject_name,
                "subject_domain": domain_name,
                "logon_id": logon_id.group(1) if logon_id else "",
                "computer": computer.group(1) if computer else "",
                "object_name": object_name.group(1) if object_name else "",
                "replication_rights": matched_rights,
                "is_machine_account": is_machine,
                "severity": severity,
                "mitre": "T1003.006",
                "description": "Non-DC account requesting directory replication",
            })

    return {"total_4662_events": total_4662, "dcsync_detections": findings}


def check_replication_permissions_powershell():
    query = """
Import-Module ActiveDirectory
$domain = (Get-ADDomain).DistinguishedName
$acl = Get-Acl "AD:\\$domain"
$repl_rights = @(
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
)
$acl.Access | Where-Object {
    $_.ObjectType -in $repl_rights -and
    $_.AccessControlType -eq 'Allow'
} | Select-Object IdentityReference, ObjectType, AccessControlType |
  ConvertTo-Json
"""
    return {"powershell_query": query.strip(),
            "note": "Run on a domain controller with RSAT tools"}


def generate_sigma_rule():
    return {
        "title": "DCSync Activity - Non-DC Replication Request",
        "status": "stable",
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection": {
                "EventID": 4662,
                "Properties|contains": [
                    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
                    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
                ]
            },
            "filter_dc": {"SubjectUserName|endswith": "$"},
            "condition": "selection and not filter_dc"
        },
        "level": "critical",
        "tags": ["attack.credential_access", "attack.t1003.006"],
    }


def main():
    parser = argparse.ArgumentParser(description="DCSync Attack Detector")
    parser.add_argument("--security-log", help="Windows Security EVTX file")
    parser.add_argument("--dc-accounts", help="File with known DC account names (one per line)")
    parser.add_argument("--generate-sigma", action="store_true", help="Output Sigma detection rule")
    parser.add_argument("--check-perms", action="store_true",
                        help="Show PowerShell query for replication permissions")
    args = parser.parse_args()

    results = {"timestamp": datetime.utcnow().isoformat() + "Z"}

    dc_accounts = load_dc_accounts(args.dc_accounts)
    dc_accounts.update(KNOWN_REPLICATION_ACCOUNTS)

    if args.security_log:
        parsed = parse_4662_events(args.security_log, dc_accounts)
        if isinstance(parsed, dict) and "error" in parsed:
            results["error"] = parsed["error"]
        else:
            results.update(parsed)
            results["total_detections"] = len(parsed.get("dcsync_detections", []))

    if args.generate_sigma:
        results["sigma_rule"] = generate_sigma_rule()

    if args.check_perms:
        results["permission_check"] = check_replication_permissions_powershell()

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
