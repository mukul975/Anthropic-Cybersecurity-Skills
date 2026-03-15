---
name: performing-web-application-scanning-with-nikto
description: Nikto is an open-source web server and web application scanner that tests against over 7,000 potentially dangerous files/programs, checks for outdated versions of over 1,250 servers, and identifies ve
domain: cybersecurity
subdomain: vulnerability-management
tags: [vulnerability-management, cve, nikto, web-scanning, owasp, risk]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Web Application Scanning with Nikto

## Overview
Nikto is an open-source web server and web application scanner that tests against over 7,000 potentially dangerous files/programs, checks for outdated versions of over 1,250 servers, and identifies version-specific problems on over 270 servers. It performs comprehensive tests including XSS, SQL injection, server misconfigurations, default credentials, and known vulnerable CGI scripts.

## Prerequisites
- Nikto installed (Perl-based, included in Kali Linux)
- Written authorization to scan target web servers
- Network access to target web applications
- Understanding of HTTP/HTTPS protocols

## Core Concepts

### What Nikto Detects
- Server misconfigurations and dangerous default files
- Outdated server software versions with known CVEs
- Common CGI vulnerabilities and dangerous scripts
- Default credentials and admin pages
- HTTP methods that should be disabled (PUT, DELETE, TRACE)
- SSL/TLS misconfigurations and weak ciphers
- Missing security headers (X-Frame-Options, CSP, HSTS)
- Information disclosure through headers and error pages

### Nikto vs Other Web Scanners
| Feature | Nikto | OWASP ZAP | Burp Suite | Nuclei |
|---------|-------|-----------|------------|--------|
| License | Open Source | Open Source | Commercial | Open Source |
| Focus | Server/Config | App Logic | Full Pentest | Template-Based |
| Speed | Fast | Medium | Slow | Very Fast |
| False Positives | Moderate | Low | Low | Low |
| Authentication | Basic | Full | Full | Template |
| Active Community | Yes | Yes | Yes | Yes |

## Implementation Steps

### Step 1: Basic Scanning
```bash
# Basic scan against a target
nikto -h https://target.example.com

# Scan specific port
nikto -h target.example.com -p 8443

# Scan multiple ports
nikto -h target.example.com -p 80,443,8080,8443

# Scan with SSL enforcement
nikto -h target.example.com -ssl

# Scan from a host list file
nikto -h targets.txt
```

### Step 2: Advanced Scanning Options
```bash
# Comprehensive scan with all tuning options
nikto -h https://target.example.com \
  -Tuning 123456789abcde \
  -timeout 10 \
  -Pause 2 \
  -Display V \
  -output report.html \
  -Format htm

# Tuning options control test types:
# 0 - File Upload
# 1 - Interesting File / Seen in logs
# 2 - Misconfiguration / Default File
# 3 - Information Disclosure
# 4 - Injection (XSS/Script/HTML)
# 5 - Remote File Retrieval - Inside Web Root
# 6 - Denial of Service
# 7 - Remote File Retrieval - Server Wide
# 8 - Command Execution / Remote Shell
# 9 - SQL Injection
# a - Authentication Bypass
# b - Software Identification
# c - Remote Source Inclusion
# d - WebService
# e - Administrative Console

# Scan with specific tuning (XSS + SQL injection + auth bypass)
nikto -h https://target.example.com -Tuning 49a

# Scan with authentication
nikto -h https://target.example.com -id admin:password

# Scan through a proxy
nikto -h https://target.example.com -useproxy http://proxy:8080

# Scan with custom User-Agent
nikto -h https://target.example.com -useragent "Mozilla/5.0 (Security Scan)"

# Scan specific CGI directories
nikto -h https://target.example.com -Cgidirs /cgi-bin/,/scripts/

# Evasion techniques (IDS avoidance for authorized testing)
# 1-Random URI encoding, 2-Directory self-reference
# 3-Premature URL ending, 4-Prepend long random string
nikto -h https://target.example.com -evasion 1234
```

### Step 3: Output and Reporting
```bash
# Generate multiple output formats
nikto -h https://target.example.com -output scan.csv -Format csv
nikto -h https://target.example.com -output scan.xml -Format xml
nikto -h https://target.example.com -output scan.html -Format htm
nikto -h https://target.example.com -output scan.txt -Format txt

# JSON output (newer versions)
nikto -h https://target.example.com -output scan.json -Format json

# Save to multiple formats simultaneously
nikto -h https://target.example.com \
  -output scan_report \
  -Format htm
```

### Step 4: Scan Multiple Targets
```bash
# Create targets file (one per line)
cat > targets.txt << 'EOF'
https://app1.example.com
https://app2.example.com:8443
http://internal-app.corp.local
192.168.1.100:8080
EOF

# Scan all targets
nikto -h targets.txt -output multi_scan.html -Format htm

# Parallel scanning with GNU parallel
cat targets.txt | parallel -j 5 "nikto -h {} -output {/}_report.html -Format htm"
```

### Step 5: SSL/TLS Assessment
```bash
# Comprehensive SSL scan
nikto -h https://target.example.com -ssl \
  -Tuning b \
  -Display V

# Check for specific SSL vulnerabilities
# Nikto checks for:
# - Expired certificates
# - Self-signed certificates
# - Weak cipher suites
# - SSLv2/SSLv3 enabled
# - BEAST, POODLE, Heartbleed indicators
# - Missing HSTS header
```

### Step 6: Integration with Other Tools
```bash
# Pipe Nmap results into Nikto
nmap -p 80,443,8080 --open -oG - 192.168.1.0/24 | \
  awk '/open/{print $2}' | \
  while read host; do nikto -h "$host" -output "${host}_nikto.html" -Format htm; done

# Export to Metasploit-compatible format
nikto -h target.example.com -output msf_import.xml -Format xml

# Parse Nikto XML output with Python for custom reporting
python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('scan.xml')
for item in tree.findall('.//item'):
    print(f\"[{item.get('id')}] {item.findtext('description', '')[:100]}\")
"
```

## Interpreting Results

### Severity Classification
- **OSVDB/CVE References**: Cross-reference with NVD for CVSS scores
- **Server Information Disclosure**: Version banners, technology stack
- **Dangerous HTTP Methods**: PUT, DELETE, TRACE enabled
- **Default/Backup Files**: .bak, .old, .swp, web.config.bak
- **Admin Interfaces**: /admin, /manager, /console exposed
- **Missing Security Headers**: CSP, X-Frame-Options, HSTS

### Common False Positives
- Generic checks triggered by custom 404 pages
- Anti-CSRF tokens flagged as form vulnerabilities
- CDN/WAF responses misidentified as vulnerable
- Load balancer health check pages

## Best Practices
1. Always obtain written authorization before scanning
2. Run Nikto in conjunction with application-level scanners (ZAP, Burp)
3. Use -Pause flag to reduce load on production servers
4. Validate findings manually before reporting
5. Combine with SSL testing tools (testssl.sh, sslyze) for comprehensive coverage
6. Schedule regular scans as part of continuous vulnerability management
7. Keep Nikto database updated for latest vulnerability checks
8. Use appropriate evasion settings only for authorized IDS testing

## Common Pitfalls
- Running Nikto without authorization (legal liability)
- Treating Nikto as a complete web application scanner (it focuses on server/config issues)
- Not validating results leading to false positive reports
- Scanning too aggressively against production systems
- Ignoring SSL/TLS findings as "informational"

## Related Skills
- scanning-infrastructure-with-nessus
- scanning-apis-for-security-vulnerabilities
- performing-network-vulnerability-assessment
