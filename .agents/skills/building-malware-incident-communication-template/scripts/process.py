"""
Malware Incident Communication Template Generator
Generates severity-appropriate communication templates for malware incidents.
"""

import json
from datetime import datetime, timezone
from pathlib import Path


class IncidentCommunicationGenerator:
    """Generates incident communication templates based on severity and type."""

    SEVERITY_LEVELS = {
        "P1": {"name": "Critical", "notify_minutes": 15, "update_hours": 2},
        "P2": {"name": "High", "notify_minutes": 60, "update_hours": 4},
        "P3": {"name": "Medium", "notify_minutes": 240, "update_hours": 8},
        "P4": {"name": "Low", "notify_minutes": 1440, "update_hours": 24},
    }

    STAKEHOLDER_MATRIX = {
        "P1": ["incident_commander", "ciso", "ceo", "legal", "board", "external_ir", "law_enforcement"],
        "P2": ["incident_commander", "ciso", "it_director", "legal"],
        "P3": ["security_manager", "it_director"],
        "P4": ["security_team_lead"],
    }

    def __init__(self, org_name="Organization", output_dir="communication_output"):
        self.org_name = org_name
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_initial_notification(self, case_id, severity, malware_type,
                                       affected_systems, impact_description):
        """Generate initial incident notification."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        sev_info = self.SEVERITY_LEVELS.get(severity, self.SEVERITY_LEVELS["P2"])

        notification = f"""SUBJECT: [{severity} - {sev_info['name']}] Malware Incident - Initial Notification - {now}

CLASSIFICATION: CONFIDENTIAL - IR TEAM ONLY

INCIDENT ID: {case_id}
DETECTION TIME: {now}
NOTIFICATION TIME: {now}
SEVERITY: {severity} - {sev_info['name']}

SUMMARY:
A malware incident has been detected affecting {len(affected_systems)} system(s).
The malware has been identified as {malware_type}.

CURRENT IMPACT:
- Systems affected: {', '.join(affected_systems)}
- Business impact: {impact_description}
- Current spread status: Under investigation

IMMEDIATE ACTIONS TAKEN:
1. Affected endpoints have been isolated from the network
2. EDR containment policies have been activated
3. Security operations team has been mobilized
4. Forensic evidence preservation has been initiated

NEXT STEPS:
1. Complete scope assessment within the next 2 hours
2. Deploy IOC-based hunting across enterprise
3. Engage external IR support if needed

INCIDENT COMMANDER: [Assigned IC Name]
CONTACT: [Secure Communication Channel]

NEXT UPDATE: {sev_info['update_hours']} hours or sooner if situation changes

---
Do not forward this notification outside the IR team.
"""
        output_file = self.output_dir / f"{case_id}_initial_notification.txt"
        with open(output_file, "w") as f:
            f.write(notification)

        print(f"[+] Initial notification generated: {output_file}")
        return notification

    def generate_executive_briefing(self, case_id, severity, incident_summary,
                                     business_impact, status, decisions_needed):
        """Generate executive briefing document."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        briefing = f"""SUBJECT: Executive Briefing - Malware Incident {case_id}

FOR: CISO / CEO / CIO
FROM: Incident Commander
DATE: {now}

SITUATION SUMMARY:
{incident_summary}

BUSINESS IMPACT:
{business_impact}

CURRENT STATUS: {status}

KEY DECISIONS NEEDED:
"""
        for i, decision in enumerate(decisions_needed, 1):
            briefing += f"{i}. {decision}\n"

        briefing += f"""
EXTERNAL COMMUNICATION STATUS:
- Regulatory notification: Under assessment by Legal
- Customer notification: Under assessment
- Law enforcement: Under assessment

NEXT UPDATE: As determined by severity level
"""
        output_file = self.output_dir / f"{case_id}_executive_briefing.txt"
        with open(output_file, "w") as f:
            f.write(briefing)

        print(f"[+] Executive briefing generated: {output_file}")
        return briefing

    def generate_technical_advisory(self, case_id, malware_name, description,
                                     iocs, affected_systems, required_actions):
        """Generate technical advisory for IT teams."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        advisory = f"""SUBJECT: TECHNICAL ADVISORY - {malware_name} - Immediate Action Required

SEVERITY: CRITICAL
DATE: {now}
ADVISORY ID: TA-{case_id}

THREAT DESCRIPTION:
{description}

AFFECTED SYSTEMS:
"""
        for system in affected_systems:
            advisory += f"- {system}\n"

        advisory += "\nINDICATORS OF COMPROMISE (IOCs):\n"

        if "hashes" in iocs:
            advisory += "\nFile Hashes:\n"
            for h in iocs["hashes"]:
                advisory += f"  {h['type']}: {h['value']}\n"

        if "domains" in iocs:
            advisory += "\nC2 Domains:\n"
            for d in iocs["domains"]:
                advisory += f"  {d}\n"

        if "ips" in iocs:
            advisory += "\nC2 IP Addresses:\n"
            for ip in iocs["ips"]:
                advisory += f"  {ip}\n"

        if "filenames" in iocs:
            advisory += "\nFile Names:\n"
            for fn in iocs["filenames"]:
                advisory += f"  {fn}\n"

        advisory += "\nREQUIRED ACTIONS:\n"
        for i, action in enumerate(required_actions, 1):
            advisory += f"{i}. [{action.get('priority', 'MEDIUM')}] {action['description']}\n"

        output_file = self.output_dir / f"{case_id}_technical_advisory.txt"
        with open(output_file, "w") as f:
            f.write(advisory)

        print(f"[+] Technical advisory generated: {output_file}")
        return advisory

    def generate_regulatory_notification(self, case_id, regulation, data_types,
                                          affected_count, timeline_events):
        """Generate regulatory breach notification."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        notification = f"""[ORGANIZATION LETTERHEAD]

Date: {now}
RE: Data Security Incident Notification - {case_id}

Pursuant to {regulation}, {self.org_name} is providing notification
of a data security incident.

INCIDENT SUMMARY:
On {timeline_events.get('detected', now)}, {self.org_name} detected a malware incident
affecting systems containing {', '.join(data_types)}.

DATA POTENTIALLY AFFECTED:
- Types of data: {', '.join(data_types)}
- Number of individuals: {affected_count}

TIMELINE:
- Incident occurred (estimated): {timeline_events.get('occurred', 'Under investigation')}
- Incident detected: {timeline_events.get('detected', now)}
- Containment achieved: {timeline_events.get('contained', 'In progress')}
- This notification: {now}

MEASURES TAKEN:
1. Immediate containment of affected systems
2. Engagement of external forensic investigators
3. Enhanced monitoring and security controls
4. Comprehensive review of security posture

CONTACT INFORMATION:
[Data Protection Officer / Privacy Officer]
{self.org_name}
[Contact Details]
"""
        output_file = self.output_dir / f"{case_id}_regulatory_notification.txt"
        with open(output_file, "w") as f:
            f.write(notification)

        print(f"[+] Regulatory notification generated: {output_file}")
        return notification

    def generate_full_communication_pack(self, case_id, severity, malware_type,
                                          malware_name, affected_systems, impact,
                                          iocs=None):
        """Generate complete communication pack for an incident."""
        print(f"[*] Generating full communication pack for {case_id}")

        self.generate_initial_notification(
            case_id, severity, malware_type, affected_systems, impact
        )

        self.generate_executive_briefing(
            case_id, severity,
            f"A {malware_type} incident has been detected affecting {len(affected_systems)} systems.",
            impact, "CONTAINMENT IN PROGRESS",
            ["Approve engagement of external IR firm",
             "Approve customer notification if data exposure confirmed"]
        )

        self.generate_technical_advisory(
            case_id, malware_name or malware_type,
            f"{malware_type} detected on enterprise systems",
            iocs or {},
            affected_systems,
            [
                {"priority": "CRITICAL", "description": "Block all IOCs at perimeter"},
                {"priority": "HIGH", "description": "Scan all endpoints for indicators"},
                {"priority": "MEDIUM", "description": "Verify backup integrity"},
            ]
        )

        manifest = {
            "case_id": case_id,
            "severity": severity,
            "generated": datetime.now(timezone.utc).isoformat(),
            "documents": [
                f"{case_id}_initial_notification.txt",
                f"{case_id}_executive_briefing.txt",
                f"{case_id}_technical_advisory.txt",
            ],
            "stakeholders": self.STAKEHOLDER_MATRIX.get(severity, []),
        }

        manifest_file = self.output_dir / f"{case_id}_communication_manifest.json"
        with open(manifest_file, "w") as f:
            json.dump(manifest, f, indent=2)

        print(f"[+] Full communication pack generated in {self.output_dir}/")
        return manifest


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Malware Incident Communication Generator")
    parser.add_argument("--case-id", default="IR-2025-001")
    parser.add_argument("--severity", choices=["P1", "P2", "P3", "P4"], default="P1")
    parser.add_argument("--malware-type", default="ransomware")
    parser.add_argument("--malware-name", default="Unknown")
    parser.add_argument("--affected", nargs="+", default=["SRV-01", "WKS-042"])
    parser.add_argument("--impact", default="Business operations partially disrupted")
    parser.add_argument("--org", default="Organization")
    parser.add_argument("-o", "--output", default="communication_output")

    args = parser.parse_args()

    generator = IncidentCommunicationGenerator(org_name=args.org, output_dir=args.output)
    generator.generate_full_communication_pack(
        args.case_id, args.severity, args.malware_type,
        args.malware_name, args.affected, args.impact
    )


if __name__ == "__main__":
    main()
