---
name: auditing-tls-certificate-transparency-logs
description: 'Monitors Certificate Transparency (CT) logs to detect unauthorized certificate
  issuance, discover subdomains via CT data, and alert on suspicious certificate activity
  for owned domains. Uses the crt.sh API and direct CT log querying based on RFC 6962
  to build continuous monitoring pipelines that catch rogue certificates, track CA
  behavior, and map the external attack surface. Activates for requests involving
  certificate transparency monitoring, CT log auditing, subdomain discovery via certificates,
  or certificate issuance alerting.

  '
domain: cybersecurity
subdomain: threat-intelligence
tags:
- certificate-transparency
- CT-logs
- crt-sh
- subdomain-discovery
- TLS-monitoring
- RFC-6962
version: 1.0.0
author: mukul975
license: Apache-2.0
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
mitre_attack:
- T1596.003
- T1583.001
- T1587.003
- T1593
- T1566.002
---
# Auditing TLS Certificate Transparency Logs

## When to Use

- Monitoring owned domains for unauthorized or unexpected certificate issuance by unknown Certificate Authorities
- Discovering subdomains and hidden services through certificates logged in public CT logs
- Detecting phishing infrastructure that uses look-alike domain certificates (typosquatting, homograph attacks)
- Auditing Certificate Authority compliance by verifying all issued certificates appear in CT logs as required by browser policies
- Building continuous certificate monitoring into a security operations pipeline with alerting for new issuances

**Do not use** for attacking or disrupting Certificate Authorities, for scraping CT logs in violation of rate limits or terms of service, or as the sole method of subdomain enumeration without corroborating results through DNS verification.

## Prerequisites

- Python 3.10+ with `requests`, `cryptography`, and `pyOpenSSL` libraries installed
- Network access to crt.sh (HTTPS) and public CT log servers
- A list of domains to monitor (owned domains, brand variations, typosquat candidates)
- SMTP credentials or webhook URL for alerting on new certificate discoveries
- Basic understanding of X.509 certificate structure and TLS certificate chain validation

## Workflow

### Step 1: Domain Inventory and Baseline

Build the initial certificate inventory for monitored domains:

- **Define monitoring scope**: List all owned root domains, registered brand names, and known subsidiaries. Include wildcard patterns (`%.example.com`) for comprehensive subdomain coverage.
- **Query crt.sh for historical certificates**: Use the crt.sh JSON API to retrieve all known certificates for each domain. The API endpoint `https://crt.sh/?q=%.example.com&output=json` returns certificates matching the wildcard pattern with fields including `issuer_ca_id`, `issuer_name`, `common_name`, `name_value`, `not_before`, `not_after`, and `serial_number`.
- **Build baseline database**: Store the initial certificate set in a local SQLite database with columns for certificate ID, domain, issuer, validity dates, SANs (Subject Alternative Names), and first-seen timestamp. This baseline prevents alerting on already-known certificates.
- **Identify authorized CAs**: From the baseline, extract the set of Certificate Authorities that have legitimately issued certificates for your domains. Any future issuance from a CA not in this set triggers a high-priority alert.
- **Map subdomains**: Extract all unique subdomains from the `name_value` field across all certificates to build an initial subdomain inventory.

### Step 2: Continuous CT Log Monitoring

Set up ongoing monitoring for new certificate issuances:

- **Poll crt.sh periodically**: Query the crt.sh API at regular intervals (every 15-60 minutes) for new certificates. Use the `exclude=expired` parameter to focus on currently valid certificates. Compare results against the baseline database to identify new entries.
- **Parse certificate details**: For each new certificate, extract the full SAN list, issuer chain, validity period, key type and size, CT log SCT (Signed Certificate Timestamp) details, and certificate fingerprint (SHA-256).
- **Detect precertificates**: CT logs include precertificates (poisoned certificates submitted before final issuance). Track these as early warnings since they indicate a certificate is about to be issued but may not yet be active.
- **Monitor CT log Signed Tree Heads (STH)**: For advanced monitoring, query CT log servers directly to fetch the latest STH and verify consistency proofs between consecutive tree heads. An inconsistency indicates log misbehavior (split-view attack).
- **Rate limiting awareness**: Respect crt.sh rate limits by spacing queries and caching responses. Implement exponential backoff on HTTP 429 responses. For high-volume monitoring, consider querying the crt.sh PostgreSQL interface directly at `crt.sh:5432`.
- **Atom/RSS feed alternative**: Subscribe to crt.sh's Atom feed for lighter-weight monitoring: `https://crt.sh/atom?q=%25.example.com` provides real-time notification of new log entries.

### Step 3: Subdomain Discovery via CT Data

Extract and validate subdomains found in certificate transparency data:

- **Wildcard expansion**: Certificates with wildcard SANs (`*.dev.example.com`) reveal the existence of subdomains that may not be in DNS zone files. Record the parent domain as a target for further enumeration.
- **Historical certificate mining**: Query crt.sh without the `exclude=expired` parameter to find subdomains from expired certificates that may still resolve in DNS. These represent historical infrastructure that could be vulnerable to subdomain takeover.
- **DNS validation**: For each discovered subdomain, perform DNS resolution (A, AAAA, CNAME records) to determine if the subdomain is currently active. Cross-reference with known IP ranges to identify shadow IT or unauthorized services.
- **Typosquat detection**: Generate permutations of the monitored domain (bitsquatting, homograph, insertion, omission, transposition, keyboard-adjacent replacement) and query CT logs for certificates issued to these variations. Certificates for typosquat domains strongly indicate phishing infrastructure.
- **Deduplication and enrichment**: Normalize discovered subdomains (lowercase, remove trailing dots), deduplicate, and enrich with WHOIS data, IP geolocation, and HTTP response headers to prioritize investigation.

### Step 4: Certificate Issuance Alerting

Configure alerting rules for security-relevant certificate events:

- **Unauthorized CA alert**: Trigger when a certificate is issued by a CA not in the authorized CA list. This is the highest-priority alert as it may indicate domain hijacking, BGP hijacking for domain validation, or a compromised CA.
- **New subdomain alert**: Trigger when a certificate contains a SAN with a previously unseen subdomain. This catches shadow IT deployments and unauthorized services.
- **Wildcard certificate alert**: Trigger on any new wildcard certificate issuance, as wildcard certificates have broader impact if compromised and their issuance should be tightly controlled.
- **Short-lived certificate anomaly**: Alert when certificates have unusually short validity periods (under 24 hours) that deviate from the organization's normal certificate lifecycle, as this may indicate Let's Encrypt abuse or automated phishing infrastructure.
- **Expiration warning**: Alert when certificates for critical services approach expiration (30, 14, 7 days) based on the `not_after` field from CT log data.
- **Alert delivery**: Send alerts via email (SMTP), Slack webhook, PagerDuty, or write to a SIEM-compatible JSON log format for integration with existing security monitoring.

### Step 5: CT Log Integrity Verification and Reporting

Verify log integrity and produce compliance evidence:

- **Signed Tree Head (STH) monitoring**: Fetch the latest STH from each monitored CT log via the `get-sth` API endpoint. The STH contains the tree size and a signed timestamp. Verify the signature using the log's public key.
- **Consistency proof verification**: Between consecutive STH fetches, request a consistency proof via `get-sth-consistency` to verify the log remains append-only and no entries have been modified or removed.
- **Certificate inventory report**: Produce a complete inventory of all certificates issued for monitored domains, grouped by issuer, with validity status and key strength metrics.
- **CA diversity analysis**: Report on how many different CAs issue certificates for the organization, identifying consolidation opportunities and single-points-of-failure.
- **Compliance evidence**: For organizations subject to PCI-DSS, SOC 2, or similar frameworks, CT monitoring logs provide evidence of certificate lifecycle management and unauthorized issuance detection capabilities.

## Key Concepts

| Term | Definition |
|------|------------|
| **Certificate Transparency (CT)** | An open framework (RFC 6962) requiring Certificate Authorities to log all issued certificates in publicly auditable append-only logs, enabling domain owners to detect unauthorized issuance |
| **Signed Certificate Timestamp (SCT)** | A promise from a CT log that a certificate will be included within the Maximum Merge Delay (typically 24 hours); browsers require SCTs from multiple logs before trusting a certificate |
| **Merkle Tree** | The cryptographic data structure used by CT logs where leaf nodes are certificate hashes and parent nodes are hashes of their children, enabling efficient consistency and inclusion proofs |
| **Precertificate** | A certificate submitted to CT logs before final issuance, containing a poison extension (OID 1.3.6.1.4.1.11129.2.4.3) that prevents it from being used for TLS but reserves its place in the log |
| **crt.sh** | A free web service operated by Sectigo that aggregates certificates from all major CT logs into a searchable PostgreSQL database, providing both web and API access |
| **Subdomain Takeover** | A vulnerability where a subdomain's DNS record points to a decommissioned service (cloud provider, CDN) that an attacker can reclaim, made discoverable through expired CT certificates |
| **Maximum Merge Delay (MMD)** | The maximum time (typically 24 hours) a CT log has to incorporate a submitted certificate into its Merkle tree after returning an SCT |
| **CAA Record** | DNS Certification Authority Authorization record that specifies which CAs are permitted to issue certificates for a domain; CT monitoring detects violations of CAA policy |

## Tools & Systems

- **crt.sh**: Primary CT log aggregator providing JSON API access at `https://crt.sh/?q=<query>&output=json` with support for wildcard queries, identity filtering, and certificate detail retrieval
- **ct-woodpecker**: Open-source CT log monitoring tool from Let's Encrypt that integrates with Prometheus and Grafana for operational monitoring of log health and consistency
- **certspotter**: SSLMate's CT log monitor that watches for newly issued certificates and sends notifications; available as hosted service or self-hosted tool
- **Google Argon / Xenon / Icarus**: Google-operated CT logs that are among the most widely used, queryable via the RFC 6962 API at their respective log URLs
- **OpenSSL**: Command-line tool for parsing certificate details, verifying chains, and extracting SAN lists from certificates retrieved through CT monitoring

## Common Scenarios

### Scenario: Detecting Unauthorized Certificate Issuance for a Financial Services Company

**Context**: A bank monitors its primary domain (`bank.example.com`) and discovers via CT logs that a certificate has been issued by a CA they have never used, covering `secure-login.bank.example.com` -- a subdomain that does not exist in their DNS.

**Approach**:
1. CT monitoring agent detects a new certificate from "FreeSSL CA" for `secure-login.bank.example.com` in crt.sh results, which is not in the authorized CA list (DigiCert, Sectigo)
2. Alert fires as unauthorized CA + new subdomain, escalating to the security team within 15 minutes of CT log entry
3. Investigate the certificate: extract the public key, check if the domain validated via HTTP-01 or DNS-01 challenge, query WHOIS for the issuing organization
4. DNS lookup for `secure-login.bank.example.com` reveals it resolves to an IP address in a hosting provider not used by the bank -- confirming this is attacker infrastructure
5. Initiate incident response: request certificate revocation from FreeSSL CA, file a domain abuse report, add the IP to blocklists, and notify the anti-phishing team
6. Implement CAA DNS records (`bank.example.com. CAA 0 issue "digicert.com"`) to prevent unauthorized CAs from issuing future certificates

**Pitfalls**:
- Not monitoring wildcard patterns (`%.bank.example.com`) and missing certificates for subdomains
- Ignoring precertificates that appear in CT logs before the actual certificate is issued, losing the early warning advantage
- Failing to verify that CAA records are properly configured on all domains after an incident
- Over-alerting on legitimate certificate renewals because the baseline database was not updated after authorized changes

### Scenario: Attack Surface Mapping Through CT Log Subdomain Discovery

**Context**: A penetration tester uses CT logs as the first phase of external reconnaissance to map the target organization's internet-facing services before active scanning.

**Approach**:
1. Query crt.sh for `%.target.com` and all known subsidiary domains, collecting 2,400 unique certificates spanning 8 years
2. Extract 347 unique subdomains from SAN fields across all certificates, including expired ones
3. DNS-resolve all 347 subdomains, finding 189 currently active with A/AAAA records
4. Identify 12 subdomains pointing to decommissioned cloud services (CNAME to S3 buckets, Azure endpoints) that are candidates for subdomain takeover
5. Discover `staging-api.target.com` and `dev-portal.target.com` which are not in the target's documented scope but are reachable and running older software versions
6. Present findings to the target organization showing the gap between their known asset inventory and the CT-derived attack surface

**Pitfalls**:
- Assuming all CT-discovered subdomains are in scope without confirming with the asset owner
- Not checking for wildcard DNS responses that make it appear subdomains exist when they resolve to a catch-all
- Relying solely on CT data without cross-referencing with passive DNS databases for comprehensive coverage

## Output Format

```
## CT Log Monitoring Report

**Domain**: example.com
**Monitoring Period**: 2026-03-01 to 2026-03-19
**Total Certificates Tracked**: 142
**New Certificates Detected**: 7
**Alerts Generated**: 2

### Alert: Unauthorized CA Issuance
- **Severity**: Critical
- **Certificate CN**: secure-login.example.com
- **SANs**: secure-login.example.com, www.secure-login.example.com
- **Issuer**: Unknown Free CA (NOT in authorized CA list)
- **Serial**: 04:A3:B7:2F:...:9E
- **Not Before**: 2026-03-18T00:00:00Z
- **Not After**: 2026-06-16T00:00:00Z
- **CT Log**: Google Argon 2026
- **SCT Timestamp**: 2026-03-17T22:15:33Z
- **Action Required**: Investigate immediately, request revocation

### Subdomain Discovery Summary
- **Total Unique Subdomains**: 89
- **New Subdomains This Period**: 3
  - api-v3.example.com (DigiCert, valid)
  - staging-new.example.com (Let's Encrypt, valid)
  - old-portal.example.com (expired 2025-12-01, CNAME to Azure -- takeover risk)

### Typosquatting Alerts
| Domain | Certificate Count | Issuer | Action Required |
|--------|-------------------|--------|-----------------|
| exarnple.com | 2 | Let's Encrypt | Investigate phishing |
| examp1e.com | 1 | ZeroSSL | Investigate phishing |
```
