"""
Active Directory Compromise Investigation Script
Analyzes Windows Security event logs for indicators of AD compromise
including DCSync, Golden Ticket, Kerberoasting, and lateral movement.
"""

import json
import csv
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path


class ADCompromiseInvestigator:
    """Investigates Active Directory compromise through event log analysis."""

    # Critical Event IDs for AD investigation
    EVENT_IDS = {
        4624: "Successful Logon",
        4625: "Failed Logon",
        4648: "Explicit Credential Logon",
        4662: "AD Object Operation",
        4768: "Kerberos TGT Request (AS-REQ)",
        4769: "Kerberos Service Ticket Request (TGS-REQ)",
        4771: "Kerberos Pre-Auth Failed",
        4776: "NTLM Credential Validation",
        5136: "Directory Object Modified",
        5137: "Directory Object Created",
        4706: "Trust Created",
        4707: "Trust Removed",
        4728: "Member Added to Security-Enabled Global Group",
        4732: "Member Added to Security-Enabled Local Group",
        4756: "Member Added to Security-Enabled Universal Group",
        4742: "Computer Account Changed",
        8222: "Shadow Copy Created",
    }

    PRIVILEGED_GROUPS = [
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Account Operators",
        "Backup Operators",
        "DnsAdmins",
        "Group Policy Creator Owners",
        "Server Operators",
        "Print Operators",
        "Protected Users",
    ]

    DCSYNC_GUIDS = [
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
        "89e95b76-444d-4c62-991a-0facbeda640c",  # DS-Replication-Get-Changes-In-Filtered-Set
    ]

    def __init__(self, output_dir="ad_investigation_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []
        self.compromised_accounts = set()
        self.lateral_movement_chain = []
        self.kerberos_anomalies = []
        self.privilege_escalations = []

    def parse_evtx_xml(self, xml_file):
        """Parse exported Windows event log XML file."""
        events = []
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

            for event_elem in root.findall(".//ns:Event", ns):
                event = self._extract_event_data(event_elem, ns)
                if event:
                    events.append(event)
        except ET.ParseError as e:
            print(f"[ERROR] XML parse error in {xml_file}: {e}")
        return events

    def _extract_event_data(self, event_elem, ns):
        """Extract structured data from an event XML element."""
        system = event_elem.find("ns:System", ns)
        if system is None:
            return None

        event_id_elem = system.find("ns:EventID", ns)
        time_elem = system.find("ns:TimeCreated", ns)
        computer_elem = system.find("ns:Computer", ns)

        event = {
            "event_id": int(event_id_elem.text) if event_id_elem is not None else 0,
            "timestamp": time_elem.get("SystemTime", "") if time_elem is not None else "",
            "computer": computer_elem.text if computer_elem is not None else "",
            "data": {},
        }

        event_data = event_elem.find("ns:EventData", ns)
        if event_data is not None:
            for data in event_data.findall("ns:Data", ns):
                name = data.get("Name", "")
                value = data.text or ""
                event[" data"][name] = value

        return event

    def analyze_dcsync_activity(self, events):
        """Detect DCSync attacks by analyzing replication permission usage."""
        print("[*] Analyzing for DCSync activity...")
        dcsync_events = []

        for event in events:
            if event["event_id"] != 4662:
                continue
            properties = event["data"].get("Properties", "")
            for guid in self.DCSYNC_GUIDS:
                if guid.lower() in properties.lower():
                    subject = event["data"].get("SubjectUserName", "Unknown")
                    dcsync_events.append({
                        "timestamp": event["timestamp"],
                        "account": subject,
                        "computer": event["computer"],
                        "guid": guid,
                        "severity": "CRITICAL",
                        "description": f"DCSync replication rights used by {subject}",
                    })
                    self.compromised_accounts.add(subject)

        if dcsync_events:
            finding = {
                "category": "DCSync Attack",
                "severity": "CRITICAL",
                "count": len(dcsync_events),
                "details": dcsync_events,
                "recommendation": "Immediately revoke replication rights from non-DC accounts. "
                                  "Double-rotate krbtgt password. Reset all domain passwords.",
            }
            self.findings.append(finding)
            print(f"  [!] CRITICAL: {len(dcsync_events)} DCSync events detected!")
        else:
            print("  [+] No DCSync activity detected.")

        return dcsync_events

    def analyze_golden_ticket_indicators(self, events):
        """Detect Golden Ticket usage through Kerberos anomalies."""
        print("[*] Analyzing for Golden Ticket indicators...")
        golden_ticket_indicators = []

        tgt_requests = {}
        service_tickets = []

        for event in events:
            if event["event_id"] == 4768:
                account = event["data"].get("TargetUserName", "")
                tgt_requests[account] = event
            elif event["event_id"] == 4769:
                service_tickets.append(event)

        for ticket in service_tickets:
            account = ticket["data"].get("TargetUserName", "")
            encryption = ticket["data"].get("TicketEncryptionType", "")
            # RC4 encryption (0x17) when AES should be used indicates forged ticket
            if encryption == "0x17":
                golden_ticket_indicators.append({
                    "timestamp": ticket["timestamp"],
                    "account": account,
                    "indicator": "RC4 encryption on service ticket (should be AES)",
                    "encryption_type": encryption,
                    "severity": "HIGH",
                })
            # Service ticket without corresponding TGT request
            if account and account not in tgt_requests:
                golden_ticket_indicators.append({
                    "timestamp": ticket["timestamp"],
                    "account": account,
                    "indicator": "Service ticket without matching TGT request",
                    "severity": "CRITICAL",
                })

        if golden_ticket_indicators:
            finding = {
                "category": "Golden Ticket Indicators",
                "severity": "CRITICAL",
                "count": len(golden_ticket_indicators),
                "details": golden_ticket_indicators,
                "recommendation": "Double-rotate krbtgt password immediately. "
                                  "Wait for full replication between rotations.",
            }
            self.findings.append(finding)
            print(f"  [!] CRITICAL: {len(golden_ticket_indicators)} Golden Ticket indicators!")
        else:
            print("  [+] No Golden Ticket indicators detected.")

        return golden_ticket_indicators

    def analyze_kerberoasting(self, events):
        """Detect Kerberoasting by analyzing bulk service ticket requests."""
        print("[*] Analyzing for Kerberoasting activity...")
        tgs_requests_by_source = defaultdict(list)

        for event in events:
            if event["event_id"] != 4769:
                continue
            source_ip = event["data"].get("IpAddress", "")
            service_name = event["data"].get("ServiceName", "")
            encryption = event["data"].get("TicketEncryptionType", "")
            account = event["data"].get("TargetUserName", "")

            if service_name and not service_name.endswith("$"):
                tgs_requests_by_source[source_ip].append({
                    "timestamp": event["timestamp"],
                    "service": service_name,
                    "account": account,
                    "encryption": encryption,
                })

        kerberoasting_sources = []
        for source_ip, requests in tgs_requests_by_source.items():
            # Threshold: more than 5 unique service tickets in short timeframe
            unique_services = set(r["service"] for r in requests)
            if len(unique_services) >= 5:
                kerberoasting_sources.append({
                    "source_ip": source_ip,
                    "unique_services_requested": len(unique_services),
                    "total_requests": len(requests),
                    "services": list(unique_services)[:20],
                    "severity": "HIGH",
                })

        if kerberoasting_sources:
            finding = {
                "category": "Kerberoasting Activity",
                "severity": "HIGH",
                "count": len(kerberoasting_sources),
                "details": kerberoasting_sources,
                "recommendation": "Reset passwords of targeted service accounts. "
                                  "Use Group Managed Service Accounts (gMSA) where possible. "
                                  "Enforce long, complex passwords on service accounts.",
            }
            self.findings.append(finding)
            print(f"  [!] HIGH: {len(kerberoasting_sources)} sources performing Kerberoasting!")
        else:
            print("  [+] No Kerberoasting activity detected.")

        return kerberoasting_sources

    def analyze_pass_the_hash(self, events):
        """Detect Pass-the-Hash through NTLM logon analysis."""
        print("[*] Analyzing for Pass-the-Hash indicators...")
        pth_indicators = []

        for event in events:
            if event["event_id"] != 4624:
                continue
            logon_type = event["data"].get("LogonType", "")
            auth_package = event["data"].get("AuthenticationPackageName", "")
            logon_process = event["data"].get("LogonProcessName", "")

            # Type 3 (Network) + NTLM + NtLmSsp = potential PtH
            if logon_type == "3" and "NTLM" in auth_package and "NtLmSsp" in logon_process:
                account = event["data"].get("TargetUserName", "")
                source_ip = event["data"].get("IpAddress", "")
                workstation = event["data"].get("WorkstationName", "")

                pth_indicators.append({
                    "timestamp": event["timestamp"],
                    "account": account,
                    "source_ip": source_ip,
                    "workstation": workstation,
                    "severity": "HIGH",
                    "description": f"NTLM network logon from {source_ip} as {account}",
                })

        if pth_indicators:
            finding = {
                "category": "Pass-the-Hash Indicators",
                "severity": "HIGH",
                "count": len(pth_indicators),
                "details": pth_indicators[:50],
                "recommendation": "Enable Credential Guard. Enforce NTLMv2 only. "
                                  "Add privileged accounts to Protected Users group. "
                                  "Implement tiered administration.",
            }
            self.findings.append(finding)
            print(f"  [!] HIGH: {len(pth_indicators)} Pass-the-Hash indicators detected!")
        else:
            print("  [+] No Pass-the-Hash indicators detected.")

        return pth_indicators

    def analyze_privilege_escalation(self, events):
        """Detect unauthorized additions to privileged groups."""
        print("[*] Analyzing for privilege escalation via group membership...")
        escalations = []

        group_change_events = [4728, 4732, 4756]

        for event in events:
            if event["event_id"] not in group_change_events:
                continue
            group_name = event["data"].get("TargetUserName", "")
            member_added = event["data"].get("MemberName", "")
            changed_by = event["data"].get("SubjectUserName", "")

            for priv_group in self.PRIVILEGED_GROUPS:
                if priv_group.lower() in group_name.lower():
                    escalations.append({
                        "timestamp": event["timestamp"],
                        "group": group_name,
                        "member_added": member_added,
                        "changed_by": changed_by,
                        "computer": event["computer"],
                        "severity": "CRITICAL",
                    })

        self.privilege_escalations = escalations

        if escalations:
            finding = {
                "category": "Privileged Group Modification",
                "severity": "CRITICAL",
                "count": len(escalations),
                "details": escalations,
                "recommendation": "Review all privileged group membership changes. "
                                  "Remove unauthorized members. Audit AdminSDHolder.",
            }
            self.findings.append(finding)
            print(f"  [!] CRITICAL: {len(escalations)} privileged group modifications!")
        else:
            print("  [+] No suspicious privileged group modifications detected.")

        return escalations

    def analyze_lateral_movement(self, events):
        """Map lateral movement chains through authentication patterns."""
        print("[*] Analyzing lateral movement patterns...")
        auth_chain = defaultdict(lambda: defaultdict(set))

        for event in events:
            if event["event_id"] != 4624:
                continue
            logon_type = event["data"].get("LogonType", "")
            if logon_type not in ("3", "10"):
                continue
            account = event["data"].get("TargetUserName", "")
            source_ip = event["data"].get("IpAddress", "")
            target = event["computer"]

            if source_ip and account and not account.endswith("$"):
                auth_chain[account][source_ip].add(target)

        movement_paths = []
        for account, sources in auth_chain.items():
            for source_ip, targets in sources.items():
                if len(targets) >= 3:
                    movement_paths.append({
                        "account": account,
                        "source_ip": source_ip,
                        "targets_accessed": list(targets),
                        "target_count": len(targets),
                        "severity": "HIGH" if len(targets) >= 5 else "MEDIUM",
                    })

        if movement_paths:
            finding = {
                "category": "Lateral Movement Patterns",
                "severity": "HIGH",
                "count": len(movement_paths),
                "details": sorted(movement_paths, key=lambda x: x["target_count"], reverse=True)[:20],
                "recommendation": "Investigate accounts with wide lateral movement. "
                                  "Implement network segmentation. Enable credential guard.",
            }
            self.findings.append(finding)
            print(f"  [!] HIGH: {len(movement_paths)} lateral movement patterns detected!")
        else:
            print("  [+] No significant lateral movement patterns detected.")

        return movement_paths

    def analyze_gpo_modifications(self, events):
        """Detect suspicious Group Policy Object modifications."""
        print("[*] Analyzing GPO modifications...")
        gpo_changes = []

        for event in events:
            if event["event_id"] != 5136:
                continue
            object_class = event["data"].get("ObjectClass", "")
            if "grouppolicycontainer" in object_class.lower():
                changed_by = event["data"].get("SubjectUserName", "")
                attribute = event["data"].get("AttributeLDAPDisplayName", "")
                value = event["data"].get("AttributeValue", "")

                gpo_changes.append({
                    "timestamp": event["timestamp"],
                    "changed_by": changed_by,
                    "attribute": attribute,
                    "value": value[:200],
                    "computer": event["computer"],
                    "severity": "HIGH",
                })

        if gpo_changes:
            finding = {
                "category": "GPO Modifications",
                "severity": "HIGH",
                "count": len(gpo_changes),
                "details": gpo_changes,
                "recommendation": "Review all GPO changes for unauthorized modifications. "
                                  "Check for malicious scheduled tasks, login scripts, "
                                  "or software installation policies.",
            }
            self.findings.append(finding)
            print(f"  [!] HIGH: {len(gpo_changes)} GPO modifications detected!")
        else:
            print("  [+] No GPO modifications detected.")

        return gpo_changes

    def generate_report(self):
        """Generate comprehensive investigation report."""
        report = {
            "investigation_report": "Active Directory Compromise Investigation",
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_findings": len(self.findings),
                "critical_findings": sum(1 for f in self.findings if f["severity"] == "CRITICAL"),
                "high_findings": sum(1 for f in self.findings if f["severity"] == "HIGH"),
                "compromised_accounts": list(self.compromised_accounts),
            },
            "findings": self.findings,
            "recommendations": self._generate_recommendations(),
        }

        report_path = self.output_dir / "ad_investigation_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"\n[+] Report saved to {report_path}")
        self._print_summary(report)
        return report

    def _generate_recommendations(self):
        """Generate prioritized remediation recommendations."""
        recommendations = []
        has_critical = any(f["severity"] == "CRITICAL" for f in self.findings)

        if has_critical:
            recommendations.append({
                "priority": 1,
                "action": "Double-rotate krbtgt password",
                "detail": "Reset krbtgt twice with full AD replication between rotations. "
                          "This invalidates all Kerberos tickets including Golden Tickets.",
            })
            recommendations.append({
                "priority": 2,
                "action": "Reset all privileged account passwords",
                "detail": "Reset passwords for Domain Admins, Enterprise Admins, "
                          "and all service accounts with SPNs.",
            })

        if self.compromised_accounts:
            recommendations.append({
                "priority": 3,
                "action": "Disable and investigate compromised accounts",
                "detail": f"Accounts to investigate: {', '.join(self.compromised_accounts)}",
            })

        recommendations.extend([
            {
                "priority": 4,
                "action": "Implement tiered administration model",
                "detail": "Separate Tier 0 (AD), Tier 1 (servers), Tier 2 (workstations) "
                          "with no credential reuse across tiers.",
            },
            {
                "priority": 5,
                "action": "Deploy advanced monitoring",
                "detail": "Enable Microsoft Defender for Identity or equivalent. "
                          "Configure advanced audit policies on all DCs.",
            },
        ])

        return recommendations

    def _print_summary(self, report):
        """Print investigation summary to console."""
        summary = report["summary"]
        print("\n" + "=" * 60)
        print("AD COMPROMISE INVESTIGATION SUMMARY")
        print("=" * 60)
        print(f"Total Findings: {summary['total_findings']}")
        print(f"Critical: {summary['critical_findings']}")
        print(f"High: {summary['high_findings']}")
        print(f"Compromised Accounts: {len(summary['compromised_accounts'])}")
        if summary["compromised_accounts"]:
            for account in summary["compromised_accounts"]:
                print(f"  - {account}")
        print("=" * 60)

    def run_full_investigation(self, event_log_files):
        """Run complete AD compromise investigation."""
        print("[*] Starting Active Directory Compromise Investigation")
        print(f"[*] Processing {len(event_log_files)} event log files...")

        all_events = []
        for log_file in event_log_files:
            events = self.parse_evtx_xml(log_file)
            all_events.extend(events)
            print(f"  Parsed {len(events)} events from {log_file}")

        print(f"[*] Total events to analyze: {len(all_events)}")

        self.analyze_dcsync_activity(all_events)
        self.analyze_golden_ticket_indicators(all_events)
        self.analyze_kerberoasting(all_events)
        self.analyze_pass_the_hash(all_events)
        self.analyze_privilege_escalation(all_events)
        self.analyze_lateral_movement(all_events)
        self.analyze_gpo_modifications(all_events)

        return self.generate_report()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Active Directory Compromise Investigation Tool"
    )
    parser.add_argument(
        "log_files",
        nargs="+",
        help="Windows Security event log XML files to analyze",
    )
    parser.add_argument(
        "-o", "--output",
        default="ad_investigation_results",
        help="Output directory for investigation results",
    )

    args = parser.parse_args()

    investigator = ADCompromiseInvestigator(output_dir=args.output)
    report = investigator.run_full_investigation(args.log_files)

    if report["summary"]["critical_findings"] > 0:
        print("\n[!!!] CRITICAL FINDINGS DETECTED - IMMEDIATE ACTION REQUIRED")
        exit(1)


if __name__ == "__main__":
    main()
