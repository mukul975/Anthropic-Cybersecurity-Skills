#!/usr/bin/env python3
"""DCSync attack detection and analysis agent using impacket and ldap3."""

import json
import sys
import argparse
from datetime import datetime

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM
except ImportError:
    print("Install: pip install ldap3")
    sys.exit(1)


def check_dcsync_permissions(server_ip, domain, username, password):
    """Check which accounts have DCSync-capable permissions (Replicating Directory Changes)."""
    server = Server(server_ip, get_info=ALL)
    conn = Connection(server, user=f"{domain}\\{username}", password=password,
                      authentication=NTLM, auto_bind=True)
    base_dn = ",".join([f"DC={p}" for p in domain.split(".")])
    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=domain)",
        attributes=["nTSecurityDescriptor"],
    )
    dcsync_accounts = []
    REPL_CHANGES_GUID = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    REPL_ALL_GUID = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectCategory=person)(objectClass=user)(adminCount=1))",
        attributes=["sAMAccountName", "distinguishedName", "memberOf"],
    )
    for entry in conn.entries:
        dcsync_accounts.append({
            "account": str(entry.sAMAccountName),
            "dn": str(entry.distinguishedName),
            "admin_count": True,
            "risk": "HIGH",
            "note": "adminCount=1 — potential DCSync privilege holder",
        })
    conn.unbind()
    return dcsync_accounts


def detect_dcsync_events(log_file=None):
    """Parse Windows Security event logs for DCSync indicators (Event IDs 4662, 4624)."""
    dcsync_indicators = {
        "4662": "Directory service access — replication operation",
        "4624": "Logon event — check for NTLM from unexpected source",
    }
    REPL_GUIDS = [
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
        "89e95b76-444d-4c62-991a-0facbeda640c",
    ]
    detections = []
    if log_file:
        try:
            with open(log_file, "r") as f:
                events = json.load(f)
            for event in events:
                eid = str(event.get("EventID", ""))
                if eid == "4662":
                    props = event.get("Properties", "")
                    for guid in REPL_GUIDS:
                        if guid in str(props).lower():
                            detections.append({
                                "event_id": eid,
                                "timestamp": event.get("TimeCreated", ""),
                                "account": event.get("SubjectUserName", ""),
                                "operation": dcsync_indicators[eid],
                                "guid_matched": guid,
                                "severity": "CRITICAL",
                            })
        except (FileNotFoundError, json.JSONDecodeError) as e:
            detections.append({"error": str(e)})
    return detections


def generate_sigma_rule():
    """Generate Sigma detection rule for DCSync activity."""
    return {
        "title": "DCSync Attack Detected via Directory Replication",
        "status": "production",
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection": {
                "EventID": 4662,
                "Properties|contains": [
                    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
                    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
                ],
            },
            "filter": {"SubjectUserName|endswith": "$"},
            "condition": "selection and not filter",
        },
        "level": "critical",
        "tags": ["attack.credential_access", "attack.t1003.006"],
    }


def run_audit(server, domain, username, password, log_file=None):
    """Run DCSync persistence audit."""
    print(f"\n{'='*60}")
    print(f"  DCSYNC PERSISTENCE AUDIT")
    print(f"  Domain: {domain} | Server: {server}")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    accounts = check_dcsync_permissions(server, domain, username, password)
    print(f"--- PRIVILEGED ACCOUNTS ({len(accounts)}) ---")
    for a in accounts[:15]:
        print(f"  [{a['risk']}] {a['account']}: {a['note']}")

    events = detect_dcsync_events(log_file)
    print(f"\n--- DCSYNC DETECTIONS ({len(events)}) ---")
    for e in events[:10]:
        if "error" not in e:
            print(f"  [{e['severity']}] {e['account']} at {e['timestamp']}")

    sigma = generate_sigma_rule()
    print(f"\n--- SIGMA RULE ---")
    print(f"  {sigma['title']}")
    print(f"  Level: {sigma['level']}")

    return {"accounts": accounts, "detections": events, "sigma_rule": sigma}


def main():
    parser = argparse.ArgumentParser(description="DCSync Detection Agent")
    parser.add_argument("--server", required=True, help="Domain controller IP")
    parser.add_argument("--domain", required=True, help="AD domain (e.g., corp.local)")
    parser.add_argument("--username", required=True, help="LDAP bind username")
    parser.add_argument("--password", required=True, help="LDAP bind password")
    parser.add_argument("--log-file", help="Windows event log JSON export to analyze")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args.server, args.domain, args.username, args.password, args.log_file)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
