#!/usr/bin/env python3
"""Cyber Kill Chain analysis agent for mapping incidents to Lockheed Martin kill chain phases."""

import json
import os
import sys
import datetime


KILL_CHAIN_PHASES = {
    1: {
        "name": "Reconnaissance",
        "description": "Adversary gathers target information",
        "indicators": [
            "DNS queries from adversary IP",
            "LinkedIn/social media scraping",
            "Shodan/Censys scans of infrastructure",
            "Job posting analysis for technology stack",
            "WHOIS lookups on organization domains",
        ],
        "mitre_tactics": ["TA0043 - Reconnaissance"],
        "coas": {
            "detect": "Monitor for anomalous DNS lookups and port scans from single sources",
            "deny": "Limit public-facing information, restrict DNS zone transfers",
            "disrupt": "Block scanning IPs at perimeter firewall",
            "degrade": "Return honeypot responses to recon probes",
            "deceive": "Deploy decoy infrastructure and fake employee profiles",
        },
    },
    2: {
        "name": "Weaponization",
        "description": "Adversary creates attack tool (malware + exploit)",
        "indicators": [
            "Malware compilation timestamps",
            "Exploit document metadata",
            "Builder tool artifacts in samples",
            "Reused infrastructure from previous campaigns",
        ],
        "mitre_tactics": ["TA0042 - Resource Development"],
        "coas": {
            "detect": "Threat intelligence on adversary tooling and TTPs",
            "deny": "Patch vulnerabilities targeted by known exploit kits",
            "disrupt": "N/A (occurs outside defender visibility)",
            "degrade": "Application hardening reduces exploit reliability",
            "deceive": "Share deceptive vulnerability information",
        },
    },
    3: {
        "name": "Delivery",
        "description": "Adversary transmits weapon to target",
        "indicators": [
            "Phishing emails with malicious attachments",
            "Drive-by download URLs",
            "USB device insertion events",
            "Supply chain compromise artifacts",
            "Watering hole website modifications",
        ],
        "mitre_tactics": ["TA0001 - Initial Access"],
        "coas": {
            "detect": "Email security gateway alerts, proxy URL filtering alerts",
            "deny": "Block malicious attachments, URL filtering, USB device control",
            "disrupt": "Quarantine suspicious emails before delivery",
            "degrade": "Sandbox detonation of attachments delays delivery",
            "deceive": "Canary documents in email attachments",
        },
    },
    4: {
        "name": "Exploitation",
        "description": "Adversary exploits vulnerability to execute code",
        "indicators": [
            "CVE exploitation in application logs",
            "Memory corruption crash dumps",
            "Shellcode execution artifacts",
            "Exploit kit landing page access",
        ],
        "mitre_tactics": ["TA0002 - Execution"],
        "coas": {
            "detect": "EDR behavioral detection, exploit guard alerts",
            "deny": "Patch management, application whitelisting",
            "disrupt": "ASLR, DEP, CFG memory protections",
            "degrade": "Sandboxed application execution (Protected View)",
            "deceive": "Honeypot applications with fake vulnerabilities",
        },
    },
    5: {
        "name": "Installation",
        "description": "Adversary establishes persistence on target",
        "indicators": [
            "New scheduled tasks or services",
            "Registry Run key modifications",
            "Web shell deployment",
            "Startup folder additions",
            "DLL search-order hijacking",
        ],
        "mitre_tactics": ["TA0003 - Persistence", "TA0004 - Privilege Escalation"],
        "coas": {
            "detect": "Sysmon EventID 11/12/13, EDR persistence monitoring",
            "deny": "Application whitelisting, UAC enforcement",
            "disrupt": "Real-time file integrity monitoring alerts",
            "degrade": "Restrict write access to system directories",
            "deceive": "Canary registry keys and file system canaries",
        },
    },
    6: {
        "name": "Command & Control",
        "description": "Adversary communicates with compromised system",
        "indicators": [
            "Beaconing traffic at regular intervals",
            "DNS tunneling (high entropy subdomain queries)",
            "HTTPS to newly registered domains",
            "Known C2 framework signatures",
        ],
        "mitre_tactics": ["TA0011 - Command and Control"],
        "coas": {
            "detect": "Network beacon analysis, JA3 fingerprinting, DNS monitoring",
            "deny": "DNS sinkholing, firewall egress filtering",
            "disrupt": "TLS inspection to identify C2 in encrypted traffic",
            "degrade": "Rate-limit suspicious outbound connections",
            "deceive": "C2 interception and response manipulation",
        },
    },
    7: {
        "name": "Actions on Objectives",
        "description": "Adversary achieves mission goals",
        "indicators": [
            "Data staging and exfiltration",
            "Lateral movement to additional systems",
            "Ransomware encryption activity",
            "Destructive operations (wiper malware)",
            "Credential dumping (LSASS access)",
        ],
        "mitre_tactics": ["TA0010 - Exfiltration", "TA0040 - Impact"],
        "coas": {
            "detect": "DLP alerts, anomalous data transfers, UEBA",
            "deny": "Network segmentation, data classification controls",
            "disrupt": "Isolate compromised systems, kill C2 connections",
            "degrade": "Encrypt sensitive data at rest (attacker gets ciphertext)",
            "deceive": "Canary files and honeytoken credentials",
        },
    },
}


def map_event_to_phase(event_description):
    """Map an incident event description to the most likely kill chain phase."""
    event_lower = event_description.lower()
    keyword_phase_map = {
        1: ["recon", "scan", "enumerat", "shodan", "whois", "dns lookup"],
        2: ["weaponiz", "builder", "compile", "payload creat"],
        3: ["phish", "email", "deliver", "download", "usb", "attachment", "watering hole"],
        4: ["exploit", "cve-", "buffer overflow", "shellcode", "rce"],
        5: ["persist", "scheduled task", "registry", "run key", "service install",
            "web shell", "backdoor", "startup"],
        6: ["beacon", "c2", "c&c", "command and control", "callback", "dns tunnel"],
        7: ["exfiltrat", "lateral", "ransomware", "encrypt", "data stag", "credential dump",
            "mimikatz", "wiper"],
    }
    scores = {phase: 0 for phase in range(1, 8)}
    for phase, keywords in keyword_phase_map.items():
        for kw in keywords:
            if kw in event_lower:
                scores[phase] += 1
    best_phase = max(scores, key=scores.get)
    if scores[best_phase] == 0:
        return None
    return best_phase


def analyze_incident(events):
    """Analyze a list of incident events and map to kill chain phases."""
    analysis = {phase: {"events": [], "detected": False, "completed": False}
                for phase in range(1, 8)}
    for event in events:
        phase = map_event_to_phase(event.get("description", ""))
        if phase:
            analysis[phase]["events"].append(event)
            analysis[phase]["completed"] = True
            if event.get("detected", False):
                analysis[phase]["detected"] = True
    return analysis


def generate_report(analysis):
    """Generate a kill chain analysis report."""
    report_lines = [
        "CYBER KILL CHAIN ANALYSIS REPORT",
        "=" * 50,
        f"Generated: {datetime.datetime.utcnow().isoformat()}Z",
        "",
    ]
    deepest_phase = 0
    detection_phase = None
    for phase_num in range(1, 8):
        phase_data = analysis[phase_num]
        phase_info = KILL_CHAIN_PHASES[phase_num]
        if phase_data["completed"]:
            deepest_phase = phase_num
        if phase_data["detected"] and detection_phase is None:
            detection_phase = phase_num
        status = "COMPLETED" if phase_data["completed"] else "NOT REACHED"
        if phase_data["detected"]:
            status += " (DETECTED)"
        report_lines.append(f"Phase {phase_num}: {phase_info['name']} -> {status}")
        for evt in phase_data["events"]:
            report_lines.append(f"  - {evt.get('description', 'N/A')}")
    report_lines.extend([
        "",
        f"Deepest phase reached: {deepest_phase} ({KILL_CHAIN_PHASES.get(deepest_phase, {}).get('name', 'N/A')})",
        f"First detection at phase: {detection_phase or 'None'}",
        "",
        "RECOMMENDED COURSES OF ACTION:",
    ])
    for phase_num in range(1, deepest_phase + 1):
        phase_info = KILL_CHAIN_PHASES[phase_num]
        report_lines.append(f"\n  Phase {phase_num} - {phase_info['name']}:")
        for coa_type, coa_desc in phase_info["coas"].items():
            report_lines.append(f"    {coa_type.upper()}: {coa_desc}")
    return "\n".join(report_lines)


if __name__ == "__main__":
    print("=" * 60)
    print("Cyber Kill Chain Analysis Agent")
    print("Lockheed Martin framework mapping with MITRE ATT&CK integration")
    print("=" * 60)

    # Demo incident events
    demo_events = [
        {"description": "Shodan scans detected from 203.0.113.50 targeting web servers",
         "timestamp": "2025-09-10T08:00:00Z", "detected": False},
        {"description": "Phishing email with malicious .docm attachment delivered to 5 users",
         "timestamp": "2025-09-11T09:15:00Z", "detected": False},
        {"description": "CVE-2023-23397 exploitation detected in Outlook process crash",
         "timestamp": "2025-09-11T09:20:00Z", "detected": False},
        {"description": "Scheduled task created for persistence by malware dropper",
         "timestamp": "2025-09-11T09:25:00Z", "detected": True},
        {"description": "C2 beacon detected to 185.220.101.42 on port 443",
         "timestamp": "2025-09-11T09:30:00Z", "detected": True},
    ]

    print("\n[*] Analyzing demo incident events...")
    analysis = analyze_incident(demo_events)
    report = generate_report(analysis)
    print(f"\n{report}")
