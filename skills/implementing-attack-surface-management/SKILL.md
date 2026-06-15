---
name: implementing-attack-surface-management
description: 'Implements external attack surface management (EASM) using Shodan, Censys,
  and ProjectDiscovery tools (subfinder, httpx, nuclei) for asset discovery, subdomain
  enumeration, service fingerprinting, and exposure scoring. Includes a weighted risk
  scoring algorithm based on OWASP attack surface analysis methodology and the Relative
  Attack Surface Quotient (RSQ). Use when building continuous ASM programs or performing
  external reconnaissance for security assessments.

  '
domain: cybersecurity
subdomain: offensive-security
tags:
- attack-surface
- reconnaissance
- shodan
- censys
- subfinder
- nuclei
- asset-discovery
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
mitre_attack:
- T1078
- T1190
- T1059
- T1595
- T1592
---

# Implementing Attack Surface Management

## When to Use

- When building an external attack surface management (EASM) program from scratch
- When performing authorized external reconnaissance for penetration testing engagements
- When continuously monitoring organizational exposure across internet-facing assets
- When scoring and prioritizing external attack surface risks for remediation
- When integrating multiple discovery tools into an automated ASM pipeline

## Prerequisites

- Python 3.8+ with requests, shodan, censys libraries installed
- Shodan API key (free tier provides 100 queries/month)
- Censys API ID and Secret (free tier available)
- ProjectDiscovery tools installed: subfinder, httpx, nuclei
- Go 1.21+ for building ProjectDiscovery tools from source
- Appropriate authorization for all external scanning activities
- Target domains and IP ranges with written scope documentation

## Instructions

### Phase 1: Subdomain Enumeration with Multiple Sources

Use subfinder for passive subdomain discovery leveraging dozens of data sources
including certificate transparency logs, DNS datasets, and search engines.

```bash
# Install ProjectDiscovery tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Basic subdomain enumeration
subfinder -d example.com -o subdomains.txt

# Verbose with all sources and recursive enumeration
subfinder -d example.com -all -recursive -o subdomains_full.txt

# Multi-domain enumeration from file
subfinder -dL domains.txt -o all_subdomains.txt

# Using OWASP Amass for deeper enumeration
amass enum -d example.com -passive -o amass_subdomains.txt

# Merge and deduplicate results
cat subdomains.txt amass_subdomains.txt | sort -u > combined_subdomains.txt
```

### Phase 2: Live Host Discovery and Service Fingerprinting

Probe discovered subdomains to identify live hosts, technologies, and services.

```bash
# HTTP probing with technology detection
cat combined_subdomains.txt | httpx -sc -cl -ct -title -tech-detect \
    -follow-redirects -json -o httpx_results.json

# Detailed service fingerprinting
cat combined_subdomains.txt | httpx -sc -cl -ct -title -tech-detect \
    -favicon -hash sha256 -jarm -cdn -cname \
    -follow-redirects -json -o httpx_detailed.json
```

### Phase 3: Shodan Asset Discovery

Query Shodan for exposed services, open ports, and known vulnerabilities
associated with discovered assets.

```python
import shodan

api = shodan.Shodan("YOUR_SHODAN_API_KEY")

# Search by organization
results = api.search("org:\"Example Corp\"")
for service in results["matches"]:
    print(f"{service['ip_str']}:{service['port']} - {service.get('product', 'unknown')}")
    if service.get("vulns"):
        for cve in service["vulns"]:
            print(f"  CVE: {cve}")

# Search by hostname
results = api.search("hostname:example.com")

# Search by SSL certificate
results = api.search("ssl.cert.subject.cn:example.com")

# Get host details with all services
host = api.host("93.184.216.34")
print(f"IP: {host['ip_str']}")
print(f"Ports: {host['ports']}")
print(f"Vulns: {host.get('vulns', [])}")
```

### Phase 4: Censys Asset Discovery

Use Censys to discover internet-facing assets through certificate and host search.

```python
from censys.search import CensysHosts, CensysCerts

# Host search
hosts = CensysHosts()
query = hosts.search("services.tls.certificates.leaf.subject.common_name: example.com")
for page in query:
    for host in page:
        print(f"IP: {host['ip']}")
        for service in host.get("services", []):
            print(f"  Port: {service['port']} Protocol: {service['transport_protocol']}")
            print(f"  Service: {service.get('service_name', 'unknown')}")

# Certificate transparency search
certs = CensysCerts()
query = certs.search("parsed.names: example.com")
for page in query:
    for cert in page:
        print(f"Fingerprint: {cert['fingerprint_sha256']}")
        print(f"Names: {cert.get('parsed', {}).get('names', [])}")
```

### Phase 5: Vulnerability Scanning with Nuclei

Run targeted vulnerability scans against discovered assets using Nuclei templates.

```bash
# Update nuclei templates
nuclei -ut

# Scan with all templates
cat combined_subdomains.txt | httpx -silent | nuclei -o nuclei_results.txt

# Scan with specific severity
cat combined_subdomains.txt | httpx -silent | \
    nuclei -severity critical,high -o critical_findings.txt

# Scan with specific template categories
cat combined_subdomains.txt | httpx -silent | \
    nuclei -tags cve,misconfig,exposure -o categorized_findings.txt

# Scan for exposed panels and sensitive files
cat combined_subdomains.txt | httpx -silent | \
    nuclei -tags panel,exposure,config -o exposed_panels.txt
```

### Phase 6: Exposure Scoring Algorithm

Score each asset based on OWASP attack surface analysis principles, using
a weighted formula derived from the Relative Attack Surface Quotient (RSQ)
and damage-potential-to-effort ratio.

The scoring algorithm considers:
1. **Open ports and services** - weighted by service risk (management ports score higher)
2. **Known vulnerabilities** - weighted by CVSS score
3. **Technology age** - outdated software increases score
4. **Exposure level** - internet-facing vs. authenticated access
5. **Data sensitivity** - based on service type and content indicators

```python
# Exposure Score = sum of weighted factors, normalized to 0-100
# See agent.py for the full implementation
```

## Examples

```bash
# Run complete ASM pipeline against a target domain
python agent.py \
    --domain example.com \
    --action full_scan \
    --shodan-key YOUR_KEY \
    --censys-id YOUR_ID \
    --censys-secret YOUR_SECRET \
    --output asm_report.json

# Subdomain enumeration only
python agent.py \
    --domain example.com \
    --action enumerate \
    --output subdomains.json

# Exposure scoring on previously discovered assets
python agent.py \
    --domain example.com \
    --action score \
    --input previous_scan.json \
    --output scored_assets.json

# Multi-domain scan from file
python agent.py \
    --domain-list targets.txt \
    --action full_scan \
    --output multi_domain_report.json
```
