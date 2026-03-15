#!/usr/bin/env python3
"""Agent for hunting MITRE ATT&CK T1098 account manipulation.

Detects shadow admin creation, SID history injection, privileged
group membership changes, and credential modifications by parsing
Windows Security Event Logs for key event IDs.
"""
# For authorized threat hunting and blue team use only

import argparse
import json
import os
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

try:
    import Evtx.Evtx as evtx
except ImportError:
    evtx = None

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

T1098_EVENT_IDS = {
    "4738": "User account changed",
    "4728": "Member added to global security group",
    "4732": "Member added to local security group",
    "4756": "Member added to universal security group",
    "4729": "Member removed from global security group",
    "4733": "Member removed from local security group",
    "4670": "Permissions on object changed",
    "5136": "Directory service object modified",
    "4724": "Password reset attempted",
    "4723": "Password change attempted",
    "4781": "Account name changed",
}

PRIVILEGED_GROUPS = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "backup operators", "server operators",
    "account operators", "print operators", "dns admins",
    "group policy creator owners", "remote desktop users",
}

SENSITIVE_ATTRIBUTES = {
    "sidhistory", "serviceprincipalname", "msds-allowedtodelegateto",
    "msds-allowedtoactonbehalfofotheridentity", "admincount",
    "useraccountcontrol", "primarygroupid",
}


def _parse_event(xml_str):
    """Extract event ID, timestamp, and data fields from event XML."""
    root = ET.fromstring(xml_str)
    sys_node = root.find(f"{NS}System")
    event_id = sys_node.find(f"{NS}EventID").text if sys_node is not None else None
    tc = sys_node.find(f"{NS}TimeCreated") if sys_node is not None else None
    timestamp = tc.get("SystemTime", "") if tc is not None else ""
    data = {}
    for d in root.iter(f"{NS}Data"):
        name = d.get("Name", "")
        data[name] = d.text or ""
    return event_id, timestamp, data


class T1098HuntingAgent:
    """Hunts for T1098 account manipulation in Windows Event Logs."""

    def __init__(self, evtx_path, output_dir="./t1098_hunt"):
        self.evtx_path = evtx_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.events = []
        self.findings = []

    def parse_events(self):
        """Parse EVTX for T1098-relevant event IDs."""
        if evtx is None:
            raise RuntimeError("python-evtx required: pip install python-evtx")
        with evtx.Evtx(self.evtx_path) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                except Exception:
                    continue
                event_id, ts, data = _parse_event(xml_str)
                if event_id in T1098_EVENT_IDS:
                    self.events.append({
                        "event_id": event_id,
                        "description": T1098_EVENT_IDS[event_id],
                        "timestamp": ts,
                        "subject_user": data.get("SubjectUserName", ""),
                        "subject_domain": data.get("SubjectDomainName", ""),
                        "target_user": data.get("TargetUserName", data.get("MemberName", "")),
                        "target_domain": data.get("TargetDomainName", ""),
                        "group_name": data.get("TargetUserName", ""),
                        "member_sid": data.get("MemberSid", ""),
                        "attribute_name": data.get("AttributeLDAPDisplayName", ""),
                        "attribute_value": data.get("AttributeValue", "")[:200],
                    })

    def detect_privileged_group_changes(self):
        """Detect additions to privileged security groups."""
        group_add_ids = {"4728", "4732", "4756"}
        alerts = []
        for event in self.events:
            if event["event_id"] in group_add_ids:
                group = event["group_name"].lower()
                if any(pg in group for pg in PRIVILEGED_GROUPS):
                    alerts.append(event)
                    self.findings.append({
                        "severity": "critical",
                        "type": "Privileged Group Addition",
                        "detail": f"{event['subject_user']} added {event['target_user']} "
                                  f"to '{event['group_name']}' at {event['timestamp']}",
                        "mitre": "T1098.001",
                    })
        return alerts

    def detect_sid_history_injection(self):
        """Detect SID History modifications via directory service changes."""
        alerts = []
        for event in self.events:
            if event["event_id"] == "5136":
                attr = event["attribute_name"].lower()
                if attr == "sidhistory":
                    alerts.append(event)
                    self.findings.append({
                        "severity": "critical",
                        "type": "SID History Injection",
                        "detail": f"SID History modified on {event['target_user']} "
                                  f"by {event['subject_user']} at {event['timestamp']}",
                        "mitre": "T1134.005",
                    })
        return alerts

    def detect_sensitive_attribute_changes(self):
        """Detect changes to sensitive AD attributes."""
        alerts = []
        for event in self.events:
            if event["event_id"] == "5136":
                attr = event["attribute_name"].lower()
                if attr in SENSITIVE_ATTRIBUTES:
                    alerts.append(event)
                    self.findings.append({
                        "severity": "high",
                        "type": "Sensitive Attribute Modified",
                        "detail": f"Attribute '{event['attribute_name']}' changed on "
                                  f"{event['target_user']} by {event['subject_user']}",
                        "mitre": "T1098",
                    })
        return alerts

    def detect_shadow_admin(self):
        """Detect potential shadow admin creation patterns."""
        alerts = []
        admin_adds = [e for e in self.events
                      if e["event_id"] in ("4728", "4732", "4756") and
                      any(pg in e["group_name"].lower() for pg in PRIVILEGED_GROUPS)]
        account_changes = [e for e in self.events if e["event_id"] == "4738"]

        changed_accounts = {e["target_user"].lower() for e in account_changes}
        for add_event in admin_adds:
            target = add_event["target_user"].lower()
            if target in changed_accounts:
                alerts.append(add_event)
                self.findings.append({
                    "severity": "critical",
                    "type": "Shadow Admin Indicator",
                    "detail": f"Account '{add_event['target_user']}' modified and then "
                              f"added to '{add_event['group_name']}'",
                    "mitre": "T1098",
                })
        return alerts

    def generate_report(self):
        self.parse_events()
        priv_group = self.detect_privileged_group_changes()
        sid_history = self.detect_sid_history_injection()
        sensitive = self.detect_sensitive_attribute_changes()
        shadow = self.detect_shadow_admin()

        event_summary = Counter(e["event_id"] for e in self.events)
        actor_summary = Counter(e["subject_user"] for e in self.events if e["subject_user"])

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "evtx_file": str(self.evtx_path),
            "mitre_technique": "T1098 - Account Manipulation",
            "total_t1098_events": len(self.events),
            "event_id_summary": dict(event_summary),
            "top_actors": actor_summary.most_common(10),
            "privileged_group_changes": len(priv_group),
            "sid_history_injections": len(sid_history),
            "sensitive_attr_changes": len(sensitive),
            "shadow_admin_indicators": len(shadow),
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "t1098_hunt_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    parser = argparse.ArgumentParser(
        description="Hunt for MITRE T1098 account manipulation in Windows Event Logs"
    )
    parser.add_argument("evtx_file", help="Path to Security.evtx log file")
    parser.add_argument("--output-dir", default="./t1098_hunt",
                        help="Output directory for hunt report")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    agent = T1098HuntingAgent(args.evtx_file, output_dir=args.output_dir)
    agent.generate_report()


if __name__ == "__main__":
    main()
