#!/usr/bin/env python3
"""CISA ransomware playbook builder and compliance checker agent.

Generates a structured ransomware incident response playbook aligned with the
CISA StopRansomware Guide. Assesses organizational readiness against CISA
checklist items and produces gap analysis reports.
"""

import json
import sys
from datetime import datetime

CISA_PREPARATION_CHECKLIST = {
    "PREP-01": {
        "control": "Offline encrypted backups",
        "description": "Maintain offline, encrypted backups of critical data tested quarterly",
        "cisa_ref": "StopRansomware Guide Part 1, Section 1",
        "priority": "Critical",
    },
    "PREP-02": {
        "control": "Incident response plan",
        "description": "Create, maintain, and exercise a cyber incident response plan with ransomware annex",
        "cisa_ref": "StopRansomware Guide Part 1, Section 2",
        "priority": "Critical",
    },
    "PREP-03": {
        "control": "Network segmentation",
        "description": "Implement network segmentation between IT, OT, and critical asset zones",
        "cisa_ref": "StopRansomware Guide Part 1, Section 3",
        "priority": "High",
    },
    "PREP-04": {
        "control": "Multi-factor authentication",
        "description": "Enable MFA on all remote access, privileged accounts, and email",
        "cisa_ref": "StopRansomware Guide Part 1, Section 4",
        "priority": "Critical",
    },
    "PREP-05": {
        "control": "Endpoint detection and response",
        "description": "Deploy EDR on all endpoints with automated response capabilities",
        "cisa_ref": "StopRansomware Guide Part 1, Section 5",
        "priority": "High",
    },
    "PREP-06": {
        "control": "RDP restrictions",
        "description": "Disable or restrict RDP; require VPN with MFA for remote access",
        "cisa_ref": "StopRansomware Guide Part 1, Section 6",
        "priority": "Critical",
    },
    "PREP-07": {
        "control": "Patch management",
        "description": "Apply patches within 48 hours for internet-facing systems, 30 days for internal",
        "cisa_ref": "StopRansomware Guide Part 1, Section 7",
        "priority": "High",
    },
    "PREP-08": {
        "control": "Email security",
        "description": "Configure email filtering, disable macros by default, implement DMARC/DKIM/SPF",
        "cisa_ref": "StopRansomware Guide Part 1, Section 8",
        "priority": "High",
    },
    "PREP-09": {
        "control": "Application allowlisting",
        "description": "Implement AppLocker or WDAC to restrict unauthorized executables",
        "cisa_ref": "StopRansomware Guide Part 1, Section 9",
        "priority": "Medium",
    },
    "PREP-10": {
        "control": "Security awareness training",
        "description": "Conduct regular phishing simulation and security awareness training",
        "cisa_ref": "StopRansomware Guide Part 1, Section 10",
        "priority": "Medium",
    },
}

RESPONSE_PHASES = {
    "detection": {
        "name": "Detection and Analysis",
        "steps": [
            "Identify initial indicators (mass file renames, ransom notes, EDR alerts)",
            "Take system images and memory captures of affected devices",
            "Identify patient zero and initial access vector",
            "Determine ransomware family using ID Ransomware or sample analysis",
            "Assess encryption scope: systems, shares, data classification impacted",
            "Check for data exfiltration indicators (double extortion)",
            "Notify incident response team and escalate per IRP",
        ],
        "time_target": "0-2 hours",
    },
    "containment": {
        "name": "Containment",
        "steps": [
            "Isolate affected systems (disable NIC, VLAN quarantine, firewall block)",
            "If unable to disconnect, power down affected systems immediately",
            "Disable shared drives and mapped network shares",
            "Reset credentials for compromised and service accounts",
            "Block known IOCs at firewall and proxy (C2 domains, IPs, hashes)",
            "Preserve forensic evidence (do not wipe or rebuild yet)",
            "Engage legal counsel for breach notification assessment",
            "Activate out-of-band communication channel for response team",
        ],
        "time_target": "1-4 hours",
    },
    "eradication": {
        "name": "Eradication and Recovery",
        "steps": [
            "Rebuild affected systems from known-clean images",
            "Restore data from verified offline backups",
            "Reset ALL domain passwords including krbtgt (twice, 12h apart)",
            "Scan restored systems with updated AV and EDR before reconnection",
            "Re-enable services in priority order (DC/DNS first, then business apps)",
            "Monitor restored systems for 72 hours for reinfection signals",
            "Validate data integrity of restored files against known checksums",
        ],
        "time_target": "1-7 days",
    },
    "post_incident": {
        "name": "Post-Incident Activity",
        "steps": [
            "Conduct root cause analysis with full incident timeline",
            "Document lessons learned with all response team stakeholders",
            "Update incident response playbook based on findings",
            "Implement new controls to address identified gaps",
            "File regulatory notifications within required timeframes",
            "Report to CISA at report.cisa.gov and FBI at ic3.gov",
            "Schedule follow-up review in 30, 60, and 90 days",
        ],
        "time_target": "1-4 weeks",
    },
}


def assess_readiness(current_controls):
    """Assess ransomware readiness against CISA checklist."""
    results = {"total_controls": len(CISA_PREPARATION_CHECKLIST), "implemented": 0,
               "gaps": [], "score": 0.0, "details": []}

    for ctrl_id, ctrl in CISA_PREPARATION_CHECKLIST.items():
        status = current_controls.get(ctrl_id, "not_implemented")
        is_implemented = status in ("implemented", "partial")
        if is_implemented:
            results["implemented"] += 1
        else:
            results["gaps"].append({
                "id": ctrl_id,
                "control": ctrl["control"],
                "priority": ctrl["priority"],
                "cisa_ref": ctrl["cisa_ref"],
            })
        results["details"].append({
            "id": ctrl_id,
            "control": ctrl["control"],
            "status": status,
            "priority": ctrl["priority"],
        })

    results["score"] = round(
        (results["implemented"] / results["total_controls"]) * 100, 1
    )
    return results


def generate_playbook(org_name="Organization"):
    """Generate a full ransomware response playbook."""
    playbook = {
        "title": f"Ransomware Incident Response Playbook - {org_name}",
        "framework": "CISA StopRansomware Guide + NIST CSF",
        "version": "1.0",
        "generated": datetime.now().isoformat(),
        "preparation": CISA_PREPARATION_CHECKLIST,
        "response_phases": RESPONSE_PHASES,
        "escalation_matrix": {
            "severity_1_critical": {
                "criteria": "Encryption active, spreading across network, critical systems affected",
                "notify": ["CISO", "CEO", "Legal Counsel", "External IR Firm", "CISA", "FBI"],
                "response_time": "Immediate",
            },
            "severity_2_high": {
                "criteria": "Encryption contained to single segment, no critical systems affected",
                "notify": ["CISO", "IT Director", "Legal Counsel"],
                "response_time": "Within 1 hour",
            },
            "severity_3_medium": {
                "criteria": "Ransomware detected but not yet executed (pre-encryption)",
                "notify": ["SOC Manager", "IT Director"],
                "response_time": "Within 4 hours",
            },
        },
        "communication_plan": {
            "internal": "Use out-of-band channel (Signal, phone tree) - assume email compromised",
            "external_stakeholders": "Prepared holding statement; legal review before public disclosure",
            "regulatory": "GDPR 72h, HIPAA 60d, SEC 4 business days, state-specific breach laws",
            "cisa_reporting": "Report to report.cisa.gov within 24 hours",
        },
    }
    return playbook


def generate_markdown_playbook(playbook):
    """Render playbook as Markdown document."""
    lines = [f"# {playbook['title']}", "", f"**Framework:** {playbook['framework']}",
             f"**Version:** {playbook['version']}", f"**Generated:** {playbook['generated']}", ""]

    lines.append("## Preparation Checklist (CISA Part 1)")
    lines.append("")
    for ctrl_id, ctrl in playbook["preparation"].items():
        lines.append(f"- [ ] **{ctrl_id}**: {ctrl['control']} - {ctrl['description']} "
                      f"[{ctrl['priority']}]")
    lines.append("")

    lines.append("## Response Phases (CISA Part 2)")
    lines.append("")
    for phase_id, phase in playbook["response_phases"].items():
        lines.append(f"### {phase['name']} (Target: {phase['time_target']})")
        lines.append("")
        for i, step in enumerate(phase["steps"], 1):
            lines.append(f"{i}. {step}")
        lines.append("")

    lines.append("## Escalation Matrix")
    lines.append("")
    for sev, details in playbook["escalation_matrix"].items():
        lines.append(f"### {sev.replace('_', ' ').title()}")
        lines.append(f"- **Criteria:** {details['criteria']}")
        lines.append(f"- **Notify:** {', '.join(details['notify'])}")
        lines.append(f"- **Response Time:** {details['response_time']}")
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    print("=" * 60)
    print("CISA Ransomware Playbook Builder Agent")
    print("Playbook generation and readiness assessment")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python agent.py generate [org_name]     Generate playbook")
        print("  python agent.py assess <controls.json>  Assess readiness")
        print("  python agent.py checklist               Print CISA checklist")
        sys.exit(0)

    command = sys.argv[1]

    if command == "generate":
        org = sys.argv[2] if len(sys.argv) > 2 else "Organization"
        playbook = generate_playbook(org)
        md = generate_markdown_playbook(playbook)
        output_file = f"ransomware_playbook_{org.lower().replace(' ', '_')}.md"
        with open(output_file, "w") as f:
            f.write(md)
        print(f"\n[+] Playbook generated: {output_file}")
        print(f"[+] Contains {len(CISA_PREPARATION_CHECKLIST)} preparation controls")
        print(f"[+] Contains {len(RESPONSE_PHASES)} response phases")
        print(f"\n{md[:500]}...")

    elif command == "assess":
        if len(sys.argv) < 3:
            print("[!] Provide a JSON file with current control statuses")
            print('    Format: {"PREP-01": "implemented", "PREP-02": "not_implemented", ...}')
            sys.exit(1)
        with open(sys.argv[2]) as f:
            controls = json.load(f)
        results = assess_readiness(controls)
        print("\n--- Ransomware Readiness Assessment ---")
        print(f"  Score: {results['score']}% ({results['implemented']}/{results['total_controls']})")
        if results["gaps"]:
            print("\n  Critical Gaps:")
            for gap in results["gaps"]:
                print(f"    [{gap['priority']}] {gap['id']}: {gap['control']}")
        print(f"\n{json.dumps(results, indent=2)}")

    elif command == "checklist":
        print("\n--- CISA Ransomware Preparation Checklist ---")
        for ctrl_id, ctrl in CISA_PREPARATION_CHECKLIST.items():
            print(f"  [{ctrl['priority']:8s}] {ctrl_id}: {ctrl['control']}")
            print(f"             {ctrl['description']}")
    else:
        print(f"[!] Unknown command: {command}")
