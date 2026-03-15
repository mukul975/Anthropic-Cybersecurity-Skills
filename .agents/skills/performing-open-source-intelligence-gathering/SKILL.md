---
name: performing-open-source-intelligence-gathering
description: Open Source Intelligence (OSINT) gathering is the first active phase of a red team engagement, where operators collect publicly available information about the target organization to identify attack s
domain: cybersecurity
subdomain: red-teaming
tags: [red-team, adversary-simulation, mitre-attack, exploitation, post-exploitation, osint, reconnaissance]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Open Source Intelligence Gathering

## Overview

Open Source Intelligence (OSINT) gathering is the first active phase of a red team engagement, where operators collect publicly available information about the target organization to identify attack surfaces, potential targets for social engineering, technology stacks, and credential exposures. Effective OSINT directly shapes initial access strategies and reduces operational risk.

## Objectives

- Enumerate the target organization's external attack surface (domains, IPs, cloud assets)
- Identify employees and their roles for social engineering targeting
- Discover leaked credentials, API keys, and sensitive documents
- Map the organization's technology stack and vendors
- Identify physical locations, office layouts, and access control details
- Build target profiles for spearphishing campaign development

## Core Concepts

### OSINT Categories

| Category | Sources | Value |
|----------|---------|-------|
| Domain Intelligence | DNS records, WHOIS, CT logs, subdomain enumeration | Network attack surface |
| Personnel Intelligence | LinkedIn, social media, conference talks, publications | Social engineering targets |
| Credential Intelligence | Breach databases, paste sites, GitHub leaks | Valid credential discovery |
| Technology Intelligence | Job postings, Wappalyzer, Shodan, Censys | Vulnerability identification |
| Physical Intelligence | Google Maps, social media photos, Glassdoor | Physical access planning |
| Document Intelligence | SEC filings, public documents, metadata extraction | Organizational structure |

### MITRE ATT&CK Mapping

- **T1595.001** - Active Scanning: Scanning IP Blocks
- **T1595.002** - Active Scanning: Vulnerability Scanning
- **T1592** - Gather Victim Host Information
- **T1589** - Gather Victim Identity Information
- **T1590** - Gather Victim Network Information
- **T1591** - Gather Victim Org Information
- **T1593** - Search Open Websites/Domains
- **T1594** - Search Victim-Owned Websites
- **T1596** - Search Open Technical Databases

## Implementation Steps

### Phase 1: Domain and Network Reconnaissance
1. Perform WHOIS lookups for target domains
2. Enumerate subdomains using Certificate Transparency logs, DNS brute-force, and web scraping
3. Identify IP ranges and ASN ownership
4. Scan for exposed services using Shodan/Censys
5. Check for cloud storage buckets (S3, Azure Blob, GCS)
6. Map CDN and hosting providers

### Phase 2: Personnel and Social Intelligence
1. Enumerate employees via LinkedIn, company website, and conference speaker lists
2. Identify email naming conventions
3. Discover personal social media accounts of key targets
4. Map organizational hierarchy and reporting structure
5. Identify recently hired IT/security personnel
6. Check for conference presentations and technical publications

### Phase 3: Credential and Data Leak Discovery
1. Search breach databases (Have I Been Pwned, DeHashed)
2. Check paste sites (Pastebin, GitHub Gists)
3. Search GitHub/GitLab for leaked secrets and API keys
4. Look for exposed configuration files and backups
5. Check for leaked internal documents via Google dorking

### Phase 4: Technology Stack Identification
1. Analyze job postings for technology mentions
2. Use Wappalyzer/BuiltWith for web technology fingerprinting
3. Check for exposed admin panels and development environments
4. Identify VPN and remote access technologies
5. Map cloud services and SaaS applications

## Tools and Resources

| Tool | Purpose | Type |
|------|---------|------|
| Amass | Subdomain enumeration and network mapping | Open Source |
| Subfinder | Passive subdomain discovery | Open Source |
| theHarvester | Email, subdomain, and name harvesting | Open Source |
| Maltego | Visual link analysis and data correlation | Commercial |
| SpiderFoot | Automated OSINT collection | Open Source |
| Shodan | Internet-connected device search | Commercial |
| Censys | Internet asset discovery | Commercial |
| Recon-ng | Web reconnaissance framework | Open Source |
| GitDorker | GitHub secret scanning | Open Source |
| Photon | Web crawler for OSINT | Open Source |

## Validation Criteria

- [ ] Complete list of target domains and subdomains
- [ ] Employee list with roles and email addresses
- [ ] Technology stack identified
- [ ] Credential leak assessment completed
- [ ] Attack surface map documented
- [ ] OSINT report compiled for engagement team
