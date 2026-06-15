---
name: building-ransomware-playbook-with-cisa-framework
description: 'Builds a structured ransomware incident response playbook aligned with
  the CISA StopRansomware Guide and NIST Cybersecurity Framework. Covers preparation,
  detection, containment, eradication, recovery, and post-incident phases with actionable
  checklists. Activates for requests involving ransomware response planning, CISA
  compliance, incident response playbook creation, or ransomware preparedness assessment.

  '
domain: cybersecurity
subdomain: ransomware-defense
tags:
- ransomware
- incident-response
- CISA
- playbook
- compliance
- NIST
version: 1.0.0
author: mahipal
license: Apache-2.0
nist_csf:
- PR.DS-11
- RS.MA-01
- RC.RP-01
- PR.IR-01
mitre_attack:
- T1486
- T1490
- T1489
- T1078
- T1021.002
---

# Building Ransomware Playbook with CISA Framework

## When to Use

- An organization needs to create or update its ransomware incident response playbook following CISA guidelines
- A security team is conducting a ransomware readiness assessment against the CISA StopRansomware framework
- Compliance requires documenting ransomware response procedures aligned with NIST CSF and CISA recommendations
- During tabletop exercises to validate that the organization's ransomware response steps match industry best practices
- After a ransomware incident to update the playbook with lessons learned and close identified gaps

**Do not use** as a substitute for legal counsel regarding ransom payment decisions, breach notification timelines, or regulatory obligations specific to your jurisdiction.

## Prerequisites

- Familiarity with the CISA StopRansomware Guide (cisa.gov/stopransomware/ransomware-guide)
- NIST Cybersecurity Framework (CSF) understanding (Identify, Protect, Detect, Respond, Recover)
- Inventory of critical assets, backup infrastructure, and communication channels
- Defined roles and responsibilities for incident response team members
- Python 3.8+ for playbook generation and compliance checking automation
- Access to organization's asset inventory and backup configuration documentation

## Workflow

### Step 1: Preparation Phase (CISA Part 1 - Prevention)

Establish ransomware-specific defenses before an incident:

```
CISA Preparation Checklist:
━━━━━━━━━━━━━━━━━━━━━━━━━━
[ ] Maintain offline, encrypted backups tested for restoration
[ ] Create and exercise a cyber incident response plan (IRP)
[ ] Implement network segmentation between IT and OT networks
[ ] Enable MFA on all remote access and privileged accounts
[ ] Deploy endpoint detection and response (EDR) on all endpoints
[ ] Disable or restrict RDP; require VPN for remote access
[ ] Maintain a software/hardware asset inventory
[ ] Apply patches within 48 hours for internet-facing systems
[ ] Configure email filtering and disable macro execution by default
[ ] Conduct regular phishing awareness training
[ ] Implement application allowlisting (AppLocker/WDAC)
[ ] Test backup restoration quarterly and document RTO/RPO
```

### Step 2: Detection and Analysis Phase

Identify ransomware indicators and assess scope:

```
Detection Indicators:
━━━━━━━━━━━━━━━━━━━━
- Mass file rename operations with new extensions (.locked, .encrypted)
- Ransom notes appearing in directories (README.txt, DECRYPT.html)
- Volume Shadow Copy deletion (vssadmin delete shadows)
- Abnormal CPU usage from encryption processes
- EDR/AV alerts for known ransomware signatures
- Network connections to known C2 infrastructure
- Unusual lateral movement via SMB or PsExec
- Sysmon Event ID 11 (file creation) spikes

Initial Analysis Steps (CISA):
  1. Take system images and memory captures of affected devices
  2. Identify patient zero and initial access vector
  3. Determine the ransomware family (ID Ransomware, ransom note analysis)
  4. Assess encryption scope: which systems, shares, and data are affected
  5. Check if data exfiltration occurred (double extortion indicator)
```

### Step 3: Containment Phase

Stop the spread and preserve evidence:

```
Immediate Containment (First 1-4 hours):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Isolate affected systems from the network (disable NICs, VLAN quarantine)
2. If unable to disconnect, power down affected systems
3. Disable shared drives to prevent encryption spread
4. Reset credentials for compromised accounts (especially admin/service accounts)
5. Block known ransomware IOCs at firewall/proxy (C2 domains, IPs)
6. Preserve forensic evidence (memory dumps, disk images, logs)
7. Engage legal counsel and prepare breach notification if data exfiltrated

Extended Containment:
  - Identify and patch the initial access vector (phishing, RDP, VPN vuln)
  - Audit all Active Directory accounts for persistence (scheduled tasks, services)
  - Check for backdoors or additional malware beyond the ransomware payload
```

### Step 4: Eradication and Recovery Phase

Remove the threat and restore operations:

```
CISA Recovery Steps:
━━━━━━━━━━━━━━━━━━━
1. Rebuild affected systems from known-clean images (do NOT decrypt in place)
2. Restore data from offline backups (verify backup integrity first)
3. Reset ALL passwords including service accounts, krbtgt (twice, 12h apart)
4. Scan restored systems with updated AV/EDR before reconnecting to network
5. Re-enable services in priority order based on business criticality
6. Monitor restored systems intensively for 72 hours for reinfection

Recovery Priority Matrix:
  P1 (0-4h):  Domain controllers, DNS, authentication infrastructure
  P2 (4-24h): Email, critical business applications, databases
  P3 (1-3d):  File servers, departmental applications
  P4 (3-7d):  Non-critical systems, development environments
```

### Step 5: Post-Incident Activity

Document lessons learned and improve defenses:

```
Post-Incident Report Template:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Executive summary: What happened, impact, resolution
2. Timeline: Detection to full recovery with timestamps
3. Root cause analysis: Initial access vector and propagation path
4. Scope: Number of systems, data volumes, business impact in hours/dollars
5. Response effectiveness: What worked, what failed, what was missing
6. Recommendations: Specific technical and procedural improvements
7. Compliance actions: Notification timeline, regulatory obligations met
8. Updated playbook: Revisions based on lessons learned
```

## Verification

- Validate playbook completeness against CISA StopRansomware checklist items
- Conduct tabletop exercise using the playbook with all stakeholders
- Verify backup restoration procedures work within documented RTO targets
- Test communication plans including out-of-band channels
- Confirm legal and regulatory notification procedures are current
- Review and update the playbook at least annually or after any incident

## Key Concepts

| Term | Definition |
|------|------------|
| **CISA StopRansomware Guide** | Joint CISA/MS-ISAC/NSA/FBI guide providing ransomware prevention best practices and response checklists |
| **RTO/RPO** | Recovery Time Objective (max downtime) and Recovery Point Objective (max data loss); critical metrics for backup planning |
| **Double Extortion** | Ransomware tactic where attackers both encrypt data and threaten to publish stolen data unless paid |
| **Patient Zero** | The first system compromised in an incident; identifying it reveals the initial access vector |
| **Tabletop Exercise** | Simulated incident scenario walked through by the response team to validate the playbook without live systems |

## Tools & Systems

- **CISA StopRansomware Guide**: Primary framework for ransomware response planning and prevention
- **NIST CSF**: Cybersecurity Framework providing the Identify/Protect/Detect/Respond/Recover structure
- **ID Ransomware**: Service for identifying ransomware families from encrypted files and ransom notes
- **MITRE ATT&CK**: Technique framework for mapping ransomware TTPs to detection opportunities
- **Velociraptor**: Endpoint visibility tool for rapid triage and forensic artifact collection during incidents
