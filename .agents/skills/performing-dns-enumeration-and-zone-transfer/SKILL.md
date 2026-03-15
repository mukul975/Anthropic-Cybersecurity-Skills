---
name: performing-dns-enumeration-and-zone-transfer
description: >
  Enumerates DNS records, attempts zone transfers, brute-forces subdomains, and
  maps DNS infrastructure during authorized reconnaissance to identify attack surface,
  misconfigurations, and information disclosure in target domains.
domain: cybersecurity
subdomain: network-security
tags: [network-security, dns, enumeration, zone-transfer, reconnaissance]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing DNS Enumeration and Zone Transfer

## When to Use

- Mapping the external attack surface of a target organization during authorized penetration tests
- Discovering hidden subdomains, internal hostnames, and IP addresses exposed via DNS records
- Testing whether DNS servers allow unauthorized zone transfers that leak the entire zone file
- Identifying mail servers, name servers, and service records for further targeted testing
- Validating DNS security configurations including DNSSEC, SPF, DKIM, and DMARC

**Do not use** against domains you do not have authorization to test, for DNS amplification or reflection attacks, or to overwhelm DNS servers with excessive query volumes.

## Prerequisites

- Written authorization to perform DNS enumeration against the target domain
- DNS enumeration tools installed: dig, nslookup, host, dnsrecon, dnsenum, subfinder, amass
- Network access to the target's DNS servers (UDP/TCP port 53)
- Wordlist for subdomain brute-forcing (SecLists dns-wordlist or similar)
- Understanding of DNS record types (A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, PTR)

## Workflow

### Step 1: Identify DNS Servers and Basic Records

```bash
# Find authoritative name servers
dig NS example.com +short
# ns1.example.com.
# ns2.example.com.

# Get SOA record for zone metadata
dig SOA example.com +short
# ns1.example.com. admin.example.com. 2024031501 3600 900 604800 86400

# Enumerate all common record types
dig example.com ANY +noall +answer

# Get MX records (mail servers)
dig MX example.com +short
# 10 mail.example.com.
# 20 mail-backup.example.com.

# Get TXT records (SPF, DKIM, DMARC, verification)
dig TXT example.com +short

# Check for DMARC policy
dig TXT _dmarc.example.com +short

# Check for DKIM selectors
dig TXT default._domainkey.example.com +short
dig TXT selector1._domainkey.example.com +short
dig TXT google._domainkey.example.com +short

# Get SRV records for common services
dig SRV _sip._tcp.example.com +short
dig SRV _ldap._tcp.example.com +short
dig SRV _kerberos._tcp.example.com +short
```

### Step 2: Attempt Zone Transfers

```bash
# Attempt AXFR zone transfer against each name server
dig AXFR example.com @ns1.example.com
dig AXFR example.com @ns2.example.com

# Use host command for zone transfer
host -t axfr example.com ns1.example.com

# Use dnsrecon for automated zone transfer attempts
dnsrecon -d example.com -t axfr

# If zone transfer succeeds, save the output
dig AXFR example.com @ns1.example.com > zone_transfer_results.txt

# Test for IXFR (incremental zone transfer)
dig IXFR=2024031500 example.com @ns1.example.com
```

### Step 3: Subdomain Enumeration via Brute Force

```bash
# Use dnsenum for comprehensive enumeration
dnsenum --dnsserver ns1.example.com --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r example.com -o dnsenum_output.xml

# Use dnsrecon with brute force
dnsrecon -d example.com -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Use gobuster for fast DNS brute forcing
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 50 -o gobuster_dns.txt

# Use subfinder for passive subdomain discovery
subfinder -d example.com -all -o subfinder_results.txt

# Use amass for comprehensive enumeration (passive + active)
amass enum -d example.com -passive -o amass_passive.txt
amass enum -d example.com -active -brute -o amass_active.txt

# Combine and deduplicate results
cat subfinder_results.txt amass_passive.txt amass_active.txt gobuster_dns.txt | sort -u > all_subdomains.txt
```

### Step 4: Reverse DNS and PTR Enumeration

```bash
# Reverse DNS lookup on discovered IP ranges
dnsrecon -d example.com -t rvl -r 10.10.0.0/24

# PTR record enumeration for IP range
for ip in $(seq 1 254); do
  result=$(dig -x 10.10.1.$ip +short 2>/dev/null)
  if [ -n "$result" ]; then
    echo "10.10.1.$ip -> $result"
  fi
done

# Use Nmap for reverse DNS on a subnet
nmap -sL 10.10.0.0/24 | grep "(" | awk '{print $5, $6}'

# Check for DNS cache snooping (information about queried domains)
dig @ns1.example.com www.competitor.com +norecurse
```

### Step 5: Analyze DNS Security Configuration

```bash
# Check DNSSEC validation
dig example.com +dnssec +short
dig DNSKEY example.com +short
dig DS example.com +short

# Test for DNS rebinding vulnerability
# Check if the DNS server has a short TTL that could enable rebinding
dig example.com +noall +answer | grep -i ttl

# Check for open recursive resolver (misconfiguration)
dig @ns1.example.com google.com +recurse
# If it resolves, the server is an open resolver

# Check for wildcard DNS records
dig nonexistent-subdomain-xyz123.example.com +short
# If it resolves, a wildcard record exists

# Test DNS over HTTPS/TLS support
# DoH test
curl -s -H 'accept: application/dns-json' 'https://dns.google/resolve?name=example.com&type=A'

# Verify SPF record for email security
dig TXT example.com +short | grep "v=spf1"
# Check for overly permissive SPF (+all, ?all)
```

### Step 6: Resolve and Map All Discovered Subdomains

```bash
# Resolve all discovered subdomains to IP addresses
while read subdomain; do
  ip=$(dig +short A "$subdomain" | head -1)
  if [ -n "$ip" ]; then
    echo "$subdomain,$ip"
  fi
done < all_subdomains.txt > resolved_subdomains.csv

# Identify unique IP addresses and their locations
cut -d',' -f2 resolved_subdomains.csv | sort -u > unique_ips.txt

# Check for internal IP addresses leaked via DNS
grep -E "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\." resolved_subdomains.csv > internal_ip_leaks.txt

# Use httpx to probe web services on discovered subdomains
cat all_subdomains.txt | httpx -title -status-code -tech-detect -o httpx_results.txt

# Screenshot web services for documentation
cat all_subdomains.txt | httpx -screenshot -o screenshots/
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Zone Transfer (AXFR)** | DNS mechanism that replicates the complete zone file from a primary to secondary server; unauthorized transfers expose all records in the zone |
| **Subdomain Enumeration** | Process of discovering valid subdomains through brute force, certificate transparency logs, search engines, and passive DNS databases |
| **DNSSEC** | DNS Security Extensions that add cryptographic signatures to DNS responses, preventing cache poisoning and spoofing attacks |
| **SPF/DKIM/DMARC** | Email authentication protocols defined in DNS TXT records that prevent email spoofing and domain impersonation |
| **Wildcard DNS** | A DNS record using an asterisk (*) that matches any query for non-existent subdomains, potentially masking enumeration results |
| **PTR Record** | Reverse DNS record that maps an IP address to a hostname, often revealing internal naming conventions and server roles |

## Tools & Systems

- **dig**: Standard DNS lookup utility with full support for all record types, DNSSEC validation, and zone transfer queries
- **dnsrecon**: Comprehensive DNS enumeration tool supporting zone transfers, brute force, reverse lookup, cache snooping, and Google dork queries
- **subfinder**: Fast passive subdomain discovery tool that queries certificate transparency logs, search engines, and DNS databases
- **Amass (OWASP)**: Advanced attack surface mapping tool with both passive and active DNS enumeration, graph analysis, and data source integration
- **gobuster**: Fast brute-force tool for DNS subdomain enumeration using configurable wordlists and concurrent threads

## Common Scenarios

### Scenario: External Reconnaissance for a Web Application Penetration Test

**Context**: A security consultant is performing external reconnaissance for a web application penetration test. The client's primary domain is example.com, and the scope includes all subdomains and related infrastructure. The consultant has authorization to enumerate DNS records and probe discovered web services.

**Approach**:
1. Query NS, MX, TXT, and SOA records for example.com to map the DNS infrastructure
2. Attempt zone transfers against both nameservers -- ns2 succeeds, revealing 347 DNS records including internal staging environments
3. Run subfinder and amass in passive mode to discover 89 additional subdomains from certificate transparency logs
4. Brute-force subdomains with a 20,000-word list using gobuster, discovering 12 more subdomains not found in passive sources
5. Resolve all subdomains and identify 15 that resolve to internal RFC1918 addresses (information disclosure)
6. Probe all web-accessible subdomains with httpx, discovering a staging environment (staging.example.com) with default credentials
7. Report zone transfer vulnerability, internal IP disclosure, and exposed staging environment to the client

**Pitfalls**:
- Sending thousands of DNS queries per second and triggering rate limiting or DNS-based DDoS protection
- Not checking for wildcard DNS records, resulting in false positive subdomain discoveries
- Missing subdomains that use separate DNS providers or CDN-specific CNAME records
- Overlooking TXT records that contain API keys, verification tokens, or internal comments

## Output Format

```
## DNS Enumeration Report

**Target Domain**: example.com
**Authorized Nameservers**: ns1.example.com (203.0.113.10), ns2.example.com (203.0.113.11)

### Zone Transfer Status
| Nameserver | AXFR Result | Records Obtained |
|------------|-------------|------------------|
| ns1.example.com | REFUSED | 0 |
| ns2.example.com | SUCCESS | 347 records |

### Subdomain Discovery Summary
| Method | Subdomains Found |
|--------|-----------------|
| Zone Transfer | 347 |
| Passive (subfinder + amass) | 89 |
| Active Brute Force | 12 |
| **Total Unique** | **412** |

### Critical Findings
1. **Zone Transfer Allowed** (High): ns2.example.com allows AXFR from any source
2. **Internal IP Disclosure** (Medium): 15 subdomains resolve to RFC1918 addresses
3. **Exposed Staging Environment** (High): staging.example.com accessible with default credentials
4. **Missing DMARC Policy** (Medium): No DMARC record found, enabling email spoofing
5. **Weak SPF Record** (Low): SPF uses ~all (soft fail) instead of -all (hard fail)
```
