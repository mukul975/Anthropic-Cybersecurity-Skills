---
name: executing-red-team-exercise
description: >
  Executes comprehensive red team exercises that simulate real-world adversary operations
  against an organization's people, processes, and technology. The red team operates with
  stealth as a primary objective, employing the full attack lifecycle from initial reconnaissance
  through objective completion while testing the organization's detection and response
  capabilities. This differs from penetration testing by focusing on adversary emulation
  rather than vulnerability identification. Activates for requests involving red team exercise,
  adversary simulation, adversary emulation, or full-scope offensive security assessment.
domain: cybersecurity
subdomain: penetration-testing
tags: [red-team, adversary-emulation, MITRE-ATT&CK, Cobalt-Strike, detection-assessment]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Executing Red Team Exercise

## When to Use

- Assessing an organization's ability to detect, respond to, and contain a realistic adversary operation
- Testing the effectiveness of the security operations center (SOC), incident response team, and threat hunting capabilities
- Validating security investments by simulating attacks that chain multiple vulnerabilities and techniques
- Evaluating the organization's security posture against specific threat actors (nation-state, ransomware groups, insider threats)
- Meeting regulatory requirements for adversary simulation (TIBER-EU, CBEST, AASE, iCAST)

**Do not use** without executive-level authorization and a detailed Rules of Engagement document, against systems where disruption could affect safety or critical operations, or as a replacement for basic vulnerability management (fix known vulnerabilities first).

## Prerequisites

- Executive-level written authorization with clearly defined objectives, scope, and off-limits systems
- Red team command and control (C2) infrastructure: primary and backup C2 channels with domain fronting or redirectors
- Operator workstations with OPSEC-hardened toolsets (Cobalt Strike, Sliver, Brute Ratel, or Mythic)
- Threat intelligence on adversary groups relevant to the target organization for adversary emulation planning
- Trusted agent (white cell) within the target organization who manages the exercise boundaries without alerting defenders
- MITRE ATT&CK matrix for mapping planned and executed techniques

## Workflow

### Step 1: Adversary Emulation Planning

Develop the operation plan based on a realistic threat model:

- **Threat actor selection**: Select an adversary group relevant to the organization's industry. For financial services, emulate FIN7 or Lazarus Group. For healthcare, emulate APT41 or FIN12. Map the selected adversary's known TTPs from MITRE ATT&CK.
- **Objective definition**: Define measurable objectives such as "Access customer financial data from the core banking system" or "Demonstrate ability to deploy ransomware across the domain"
- **Attack plan development**: Create a step-by-step operation plan mapping each phase to ATT&CK tactics:
  1. Initial Access (TA0001): Phishing, exploiting public-facing applications, or supply chain compromise
  2. Execution (TA0002): PowerShell, scripting, exploitation for client execution
  3. Persistence (TA0003): Scheduled tasks, registry modifications, implant deployment
  4. Privilege Escalation (TA0004): Token impersonation, exploitation for privilege escalation
  5. Defense Evasion (TA0005): Process injection, timestomping, indicator removal
  6. Credential Access (TA0006): LSASS dumping, Kerberoasting, credential stuffing
  7. Lateral Movement (TA0008): Remote services, pass-the-hash, remote desktop
  8. Collection/Exfiltration (TA0009/TA0010): Data staging, exfiltration over C2
- **Deconfliction plan**: Establish procedures for the white cell to distinguish red team activity from actual threats

### Step 2: Infrastructure Preparation

Build OPSEC-hardened attack infrastructure:

- **C2 infrastructure**: Deploy primary C2 server behind redirectors that filter Blue Team investigation traffic. Use domain fronting or legitimate cloud services (Azure CDN, CloudFront) to blend C2 traffic with normal web traffic.
- **Phishing infrastructure**: Register aged domains (30+ days old), configure SPF/DKIM/DMARC, and build credential harvesting or payload delivery pages
- **Payload development**: Create custom implants or configure C2 framework payloads with:
  - AMSI bypass for PowerShell execution
  - ETW patching to evade security product telemetry
  - Sleep masking and memory encryption to defeat memory scanning
  - Signed binary proxy execution (rundll32, msbuild, regsvr32) for defense evasion
- **Staging infrastructure**: Set up file hosting for second-stage payloads, exfiltration drop servers, and backup communication channels
- **OPSEC verification**: Test the entire infrastructure against the same EDR/AV products deployed in the target environment before going live

### Step 3: Initial Access

Gain initial foothold in the target environment:

- **Phishing campaign**: Send targeted spear-phishing emails to selected employees with weaponized documents or credential harvesting links. Use pretexts based on OSINT gathered during reconnaissance.
- **External exploitation**: Exploit vulnerabilities in internet-facing applications (VPN portals, web applications, email servers) identified during reconnaissance
- **Physical access**: If in scope, attempt physical access to deploy network implants (LAN Turtle, Bash Bunny) or USB drops
- **Supply chain**: If in scope, compromise a vendor or supplier relationship to gain indirect access
- Upon successful initial access, establish the first C2 beacon and confirm communication with the C2 server. Immediately implement persistence (multiple mechanisms) to survive reboots and credential changes.

### Step 4: Post-Exploitation and Objective Completion

Operate within the target environment while maintaining stealth:

- **Internal reconnaissance**: Enumerate the domain, identify high-value targets, and map the network using BloodHound and internal scanning, with traffic designed to blend with normal administrative activity
- **Privilege escalation**: Escalate from initial user to local admin, then to domain admin, using the least detectable techniques (Kerberoasting over pass-the-hash, living-off-the-land over custom tools)
- **Lateral movement**: Move to target systems using legitimate protocols (RDP, WinRM, SMB) with stolen credentials. Vary techniques to test multiple detection signatures.
- **Defense evasion**: Continuously adapt to avoid detection. If a technique triggers an alert, note the detection and switch to an alternative approach.
- **Objective execution**: Complete the defined objectives (access target data, demonstrate ransomware staging, exfiltrate data) and document evidence of achievement
- **Detection timeline**: Record timestamps for every technique executed to later compare against Blue Team's detection timeline

### Step 5: Purple Team Integration and Reporting

Convert red team findings into defensive improvements:

- **Detection gap analysis**: Compare the red team's technique timeline against the Blue Team's detection log. Identify which techniques were detected, which were missed, and the mean time to detect (MTTD) for each.
- **ATT&CK coverage mapping**: Create an ATT&CK Navigator heatmap showing which techniques were tested and whether they were detected, missed, or partially detected
- **Purple team sessions**: Conduct collaborative sessions where the red team reveals each technique step-by-step while the Blue Team identifies where detection should have occurred and writes new detection rules
- **Report**: Deliver a comprehensive report including the operation narrative, technique-by-technique analysis with detection status, and prioritized recommendations for improving detection and response

## Key Concepts

| Term | Definition |
|------|------------|
| **Adversary Emulation** | Simulating the specific TTPs of a known threat actor to test defenses against realistic threats relevant to the organization |
| **C2 (Command and Control)** | Infrastructure and communication channels used by the red team to remotely control implants deployed on compromised systems |
| **OPSEC** | Operational Security; practices employed by the red team to avoid detection by the defending team during the exercise |
| **Domain Fronting** | A technique for hiding C2 traffic behind legitimate CDN domains to evade network-based detection and domain blocking |
| **Purple Teaming** | Collaborative exercise where red and blue teams work together to improve detection by sharing attack techniques and defensive gaps |
| **White Cell** | The trusted agent or exercise control group that manages the exercise, handles deconfliction, and mediates between red and blue teams |
| **Implant** | Software deployed by the red team on compromised systems to maintain access, execute commands, and facilitate lateral movement |
| **MTTD/MTTR** | Mean Time to Detect / Mean Time to Respond; metrics measuring how long it takes the defending team to identify and contain threats |

## Tools & Systems

- **Cobalt Strike**: Commercial adversary simulation platform providing beacons, malleable C2 profiles, and post-exploitation capabilities
- **Sliver**: Open-source C2 framework supporting multiple protocols (mTLS, WireGuard, HTTP/S, DNS) with cross-platform implants
- **MITRE ATT&CK Navigator**: Tool for visualizing ATT&CK technique coverage, enabling comparison of planned vs. executed vs. detected techniques
- **Mythic**: Open-source C2 framework with a modular agent architecture and web-based operator interface

## Common Scenarios

### Scenario: Adversary Emulation of FIN7 Against a Retail Company

**Context**: A national retail chain wants to test its defenses against FIN7, a financially motivated threat group known for targeting retail and hospitality organizations with point-of-sale malware, phishing, and data exfiltration.

**Approach**:
1. Emulate FIN7 TTPs: spear-phishing with malicious document containing VBA macros that execute PowerShell
2. Initial access achieved through spear-phishing a marketing employee; macro drops Cobalt Strike beacon using rundll32 proxy execution
3. Internal reconnaissance with BloodHound reveals a path from the compromised user to a service account with access to the POS management server
4. Kerberoast the service account, crack the password, and move laterally to the POS management system
5. Demonstrate data access to cardholder data environment, staging simulated card data for exfiltration
6. Exfiltrate staged data over DNS C2 channel to simulate data theft
7. SOC detected the lateral movement at hour 47 but did not detect the initial phishing, macro execution, or Kerberoasting

**Pitfalls**:
- Operating too aggressively and getting detected immediately, providing no value for testing Blue Team's advanced detection capabilities
- Using exclusively custom tools instead of living-off-the-land techniques that real adversaries prefer
- Not recording detailed timestamps for every action, making post-exercise analysis and detection gap mapping impossible
- Failing to establish backup C2 channels, getting burned by a single detection, and losing access without completing objectives

## Output Format

```
## Red Team Exercise Report - FIN7 Adversary Emulation

### Exercise Summary
**Duration**: November 4-22, 2025 (15 business days)
**Objective**: Access cardholder data environment and demonstrate data exfiltration capability
**Outcome**: OBJECTIVE ACHIEVED - Red team accessed POS management system and staged cardholder data for exfiltration

### ATT&CK Technique Coverage
| Technique | ID | Status | Detected? | MTTD |
|-----------|----|--------|-----------|------|
| Spear-Phishing Attachment | T1566.001 | Executed | No | - |
| Visual Basic Macro | T1059.005 | Executed | No | - |
| Process Injection | T1055 | Executed | No | - |
| Kerberoasting | T1558.003 | Executed | No | - |
| Remote Desktop Protocol | T1021.001 | Executed | YES | 47h |
| Data Staged | T1074 | Executed | No | - |
| Exfiltration Over C2 | T1041 | Executed | No | - |

### Detection Summary
- **Techniques Executed**: 14
- **Techniques Detected**: 3 (21.4%)
- **Mean Time to Detect**: 47 hours (for detected techniques)
- **Mean Time to Respond**: 4 hours (from detection to containment)

### Priority Recommendations
1. Deploy email detonation sandboxing for macro-enabled document analysis
2. Implement Kerberoasting detection via Windows Event ID 4769 monitoring
3. Enhance PowerShell logging (Script Block Logging, Module Logging)
4. Deploy memory-scanning EDR capability to detect process injection
```
