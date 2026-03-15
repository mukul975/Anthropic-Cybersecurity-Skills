---
name: performing-subdomain-enumeration-with-subfinder
description: Enumerate subdomains of target domains using ProjectDiscovery's Subfinder passive reconnaissance tool to map the attack surface during security assessments.
domain: cybersecurity
subdomain: web-application-security
tags: [subdomain-enumeration, reconnaissance, bug-bounty, attack-surface, subfinder, passive-recon, osint]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Subdomain Enumeration with Subfinder

## When to Use
- During the reconnaissance phase of penetration testing or bug bounty hunting
- When mapping the external attack surface of a target organization
- Before performing vulnerability scanning on discovered subdomains
- When building an asset inventory for continuous security monitoring
- During red team engagements requiring passive information gathering

## Prerequisites
- Go 1.21+ installed for building from source
- Subfinder v2 installed (`go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`)
- API keys configured for passive sources (Shodan, Censys, VirusTotal, SecurityTrails, Chaos)
- Provider configuration file at `$HOME/.config/subfinder/provider-config.yaml`
- Network access to passive DNS and certificate transparency sources
- httpx or httprobe for validating discovered subdomains

## Workflow

### Step 1 — Install and Configure Subfinder
```bash
# Install subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Verify installation
subfinder -version

# Configure API keys for enhanced results
mkdir -p $HOME/.config/subfinder
cat > $HOME/.config/subfinder/provider-config.yaml << 'EOF'
shodan:
  - YOUR_SHODAN_API_KEY
censys:
  - YOUR_CENSYS_API_ID:YOUR_CENSYS_API_SECRET
virustotal:
  - YOUR_VT_API_KEY
securitytrails:
  - YOUR_ST_API_KEY
chaos:
  - YOUR_CHAOS_API_KEY
EOF
```

### Step 2 — Run Basic Subdomain Enumeration
```bash
# Single domain enumeration
subfinder -d example.com -o subdomains.txt

# Multiple domains from a file
subfinder -dL domains.txt -o all_subdomains.txt

# Use all passive sources (slower but more thorough)
subfinder -d example.com -all -o subdomains_all.txt

# Silent mode for piping to other tools
subfinder -d example.com -silent | httpx -silent -status-code
```

### Step 3 — Filter and Customize Source Selection
```bash
# Use specific sources only
subfinder -d example.com -s crtsh,virustotal,shodan -o filtered.txt

# Exclude specific sources
subfinder -d example.com -es github -o results.txt

# Enable recursive subdomain enumeration
subfinder -d example.com -recursive -o recursive_subs.txt

# Match specific patterns
subfinder -d example.com -m "api,dev,staging" -o matched.txt
```

### Step 4 — Control Rate Limiting and Output Format
```bash
# Rate limit to avoid API throttling
subfinder -d example.com -rate-limit 10 -t 5 -o rate_limited.txt

# JSON output for programmatic processing
subfinder -d example.com -oJ -o subdomains.json

# Output with source information
subfinder -d example.com -cs -o subdomains_with_sources.txt

# Collect results in a directory per domain
subfinder -dL domains.txt -oD ./results/
```

### Step 5 — Validate Discovered Subdomains with httpx
```bash
# Pipe subfinder output to httpx for live validation
subfinder -d example.com -silent | httpx -silent -status-code -title -tech-detect -o live_hosts.txt

# Check for specific ports
subfinder -d example.com -silent | httpx -ports 80,443,8080,8443 -o web_services.txt

# Resolve IP addresses
subfinder -d example.com -silent | dnsx -a -resp -o resolved.txt
```

### Step 6 — Integrate with Broader Recon Pipeline
```bash
# Chain with nuclei for vulnerability scanning
subfinder -d example.com -silent | httpx -silent | nuclei -t cves/ -o vulns.txt

# Combine with amass for comprehensive enumeration
subfinder -d example.com -o subfinder_results.txt
amass enum -passive -d example.com -o amass_results.txt
cat subfinder_results.txt amass_results.txt | sort -u > combined_subdomains.txt

# Screenshot discovered hosts
subfinder -d example.com -silent | httpx -silent | gowitness file -f - -P screenshots/
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Passive Enumeration | Discovering subdomains without directly querying target DNS servers |
| Certificate Transparency | Public logs of SSL/TLS certificates revealing subdomain names |
| DNS Aggregation | Collecting subdomain data from multiple passive DNS databases |
| Recursive Enumeration | Discovering subdomains of subdomains for deeper coverage |
| Source Providers | External APIs and databases queried for subdomain intelligence |
| CNAME Records | Canonical name records that may reveal additional infrastructure |
| Wildcard DNS | DNS configuration returning results for any subdomain query |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Subfinder | Primary passive subdomain enumeration engine |
| httpx | HTTP probe tool for validating live subdomains |
| dnsx | DNS resolution and validation toolkit |
| Nuclei | Template-based vulnerability scanner for discovered hosts |
| Amass | Complementary subdomain enumeration with active/passive modes |
| gowitness | Web screenshot utility for visual reconnaissance |
| Shodan | Internet-wide scanning database for subdomain intelligence |
| crt.sh | Certificate transparency log search engine |

## Common Scenarios

1. **Bug Bounty Reconnaissance** — Enumerate all subdomains of a target program scope to identify forgotten or misconfigured assets that may contain vulnerabilities
2. **Attack Surface Mapping** — Build a comprehensive inventory of externally accessible subdomains for ongoing security monitoring and risk assessment
3. **Cloud Asset Discovery** — Identify subdomains pointing to cloud services (AWS, Azure, GCP) that may be vulnerable to subdomain takeover
4. **CI/CD Integration** — Automate subdomain monitoring in pipelines to detect new subdomains and alert on changes to the attack surface
5. **Merger & Acquisition Due Diligence** — Map the complete external footprint of an acquisition target during security assessment

## Output Format

```
## Subdomain Enumeration Report
- **Target Domain**: example.com
- **Total Subdomains Found**: 247
- **Live Hosts**: 183
- **Unique IP Addresses**: 42
- **Sources Used**: crt.sh, VirusTotal, Shodan, SecurityTrails, Censys

### Discovered Subdomains
| Subdomain | IP Address | Status Code | Technology |
|-----------|-----------|-------------|------------|
| api.example.com | 10.0.1.5 | 200 | Nginx, Node.js |
| staging.example.com | 10.0.2.10 | 403 | Apache |
| dev.example.com | 10.0.3.15 | 200 | Express |

### Recommendations
- Remove DNS records for decommissioned subdomains
- Investigate subdomains with CNAME pointing to unclaimed services
- Restrict access to development and staging environments
```
