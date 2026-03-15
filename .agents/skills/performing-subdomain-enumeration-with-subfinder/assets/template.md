# Subdomain Enumeration Report Template

## Engagement Details
- **Target Domain**: [domain]
- **Date**: [date]
- **Assessor**: [name]
- **Scope**: Passive subdomain enumeration only

## Executive Summary
Performed passive subdomain enumeration against [domain] using Subfinder and complementary tools. Discovered [N] unique subdomains, of which [M] are live and responding to HTTP requests.

## Methodology
1. Passive subdomain enumeration using Subfinder with all available sources
2. DNS resolution and validation using dnsx
3. HTTP probing with httpx for live host identification
4. CNAME analysis for subdomain takeover risk assessment

## Results Summary

| Metric | Count |
|--------|-------|
| Total Subdomains Discovered | |
| Live HTTP Hosts | |
| Unique IP Addresses | |
| Subdomain Takeover Candidates | |
| Cloud-Hosted Subdomains | |

## Live Hosts

| Subdomain | IP Address | Status Code | Title | Technologies |
|-----------|-----------|-------------|-------|-------------|
| | | | | |

## Subdomain Takeover Risks

| Subdomain | CNAME Target | Service | Risk Level |
|-----------|-------------|---------|------------|
| | | | |

## Recommendations
1. Remove dangling DNS records for decommissioned services
2. Claim or remove CNAME records pointing to unclaimed cloud resources
3. Restrict access to development and staging subdomains
4. Implement continuous subdomain monitoring for new asset detection
5. Review cloud service configurations for publicly accessible resources
