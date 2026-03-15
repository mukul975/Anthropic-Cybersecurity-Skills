# OSINT Gathering Workflows

## Workflow 1: Domain and Infrastructure Reconnaissance

### Step 1: Passive DNS and WHOIS
```bash
# WHOIS lookup
whois targetdomain.com

# DNS record enumeration
dig targetdomain.com ANY
dig targetdomain.com MX
dig targetdomain.com TXT
dig targetdomain.com NS

# Reverse DNS
dig -x <IP_ADDRESS>

# Zone transfer attempt
dig axfr @ns1.targetdomain.com targetdomain.com
```

### Step 2: Subdomain Enumeration
```bash
# Using Subfinder for passive enumeration
subfinder -d targetdomain.com -o subdomains.txt

# Using Amass for comprehensive enumeration
amass enum -passive -d targetdomain.com -o amass_results.txt

# Certificate Transparency log search
curl -s "https://crt.sh/?q=%.targetdomain.com&output=json" | jq -r '.[].name_value' | sort -u

# Using httpx to probe discovered subdomains
cat subdomains.txt | httpx -status-code -title -tech-detect -o live_subdomains.txt
```

### Step 3: IP Range and ASN Discovery
```bash
# ASN lookup
whois -h whois.radb.net -- '-i origin AS12345'

# BGP prefix lookup via Hurricane Electric
curl -s "https://bgp.he.net/AS12345#_prefixes"

# Shodan search for organization
shodan search "org:Target Corporation" --fields ip_str,port,product
```

### Step 4: Cloud Asset Discovery
```bash
# AWS S3 bucket enumeration
python3 cloud_enum.py -k targetcorp -l cloud_results.txt

# Azure blob storage check
for name in targetcorp targetcorp-dev targetcorp-backup; do
  curl -s -o /dev/null -w "%{http_code}" "https://${name}.blob.core.windows.net/"
done

# GCP bucket check
gsutil ls gs://targetcorp-*
```

## Workflow 2: Personnel Intelligence

### Step 1: Employee Enumeration
```bash
# theHarvester for email and name harvesting
theHarvester -d targetdomain.com -b all -l 500 -f harvest_results

# LinkedIn enumeration (manual + tools)
# Use LinkedIn search operators:
# site:linkedin.com/in "targetcorp" "security engineer"
# site:linkedin.com/in "targetcorp" "system administrator"

# CrossLinked for LinkedIn name harvesting
python3 crosslinked.py -f '{first}.{last}@targetdomain.com' "Target Corporation"
```

### Step 2: Email Validation
```bash
# Verify email format using Hunter.io API
curl "https://api.hunter.io/v2/domain-search?domain=targetdomain.com&api_key=YOUR_KEY"

# SMTP verification (careful - can be logged)
# Use tools like EmailHippo or NeverBounce for passive verification
```

### Step 3: Social Media Profiling
```bash
# Sherlock for username enumeration across platforms
python3 sherlock username --timeout 5 --output sherlock_results.txt

# Social media searching
# Twitter advanced search: from:username targetcorp
# Instagram: #targetcorp
# GitHub: org:targetcorp
```

## Workflow 3: Credential and Data Leak Discovery

### Step 1: Breach Database Search
```bash
# Have I Been Pwned API check
curl "https://haveibeenpwned.com/api/v3/breachedaccount/user@targetdomain.com" \
  -H "hibp-api-key: YOUR_KEY"

# DeHashed search (requires subscription)
curl "https://api.dehashed.com/search?query=domain:targetdomain.com" \
  -u email:api_key
```

### Step 2: GitHub Secret Scanning
```bash
# GitDorker for GitHub dorking
python3 GitDorker.py -tf tokens.txt -d dorks/alldorksv3 -q targetdomain.com

# truffleHog for repository scanning
trufflehog github --org=targetcorp --only-verified

# Manual GitHub dorking
# Search: "targetdomain.com" password
# Search: "targetdomain.com" api_key
# Search: "targetcorp" filename:.env
# Search: "targetcorp" filename:wp-config.php
```

### Step 3: Google Dorking
```
# Sensitive files
site:targetdomain.com filetype:pdf
site:targetdomain.com filetype:xlsx
site:targetdomain.com filetype:docx confidential

# Configuration files
site:targetdomain.com filetype:xml
site:targetdomain.com filetype:conf
site:targetdomain.com filetype:env

# Login pages and admin panels
site:targetdomain.com inurl:admin
site:targetdomain.com inurl:login
site:targetdomain.com intitle:"index of"

# Error messages with sensitive info
site:targetdomain.com "error" "sql" "syntax"
site:targetdomain.com "php error" "on line"
```

## Workflow 4: Technology Stack Identification

### Step 1: Web Technology Fingerprinting
```bash
# Wappalyzer CLI
wappalyzer https://targetdomain.com

# WhatWeb for technology identification
whatweb targetdomain.com -v

# Nuclei for technology detection
nuclei -u https://targetdomain.com -t technologies/
```

### Step 2: Service and Version Detection
```bash
# Nmap service detection (active - requires authorization)
nmap -sV -sC -p- targetdomain.com -oA nmap_results

# Shodan host lookup
shodan host <IP_ADDRESS>

# Censys host search
censys search "services.tls.certificates.leaf_data.subject.organization:Target Corp"
```

### Step 3: Job Posting Analysis
```
# Search job boards for technology mentions:
# LinkedIn Jobs: "Target Corporation" AND ("AWS" OR "Azure" OR "GCP")
# Indeed: "Target Corporation" "security" tools
# Glassdoor: Target Corporation technology stack

# Look for mentions of:
# - Cloud platforms (AWS, Azure, GCP)
# - Security tools (CrowdStrike, Carbon Black, Splunk)
# - Development languages and frameworks
# - Network equipment vendors (Cisco, Palo Alto, Fortinet)
# - Identity providers (Okta, Azure AD, Ping Identity)
```

## Workflow 5: Physical Intelligence

### Step 1: Location Mapping
```
# Google Maps reconnaissance:
# - Office locations and building layouts
# - Parking areas and entry points
# - Nearby businesses for staging
# - Delivery entrance locations

# Google Street View:
# - Access control systems (card readers, turnstiles)
# - Security camera locations
# - Badge/lanyard colors and designs
# - Building signage
```

### Step 2: Document Metadata Extraction
```bash
# ExifTool for document metadata
exiftool -r -ext pdf -ext docx -ext xlsx ./downloaded_documents/

# FOCA for metadata analysis (Windows)
# Import documents and analyze:
# - Author names and usernames
# - Software versions
# - Internal file paths
# - Printer names and network paths
```

## Workflow 6: OSINT Report Compilation

### Report Structure
```
1. Executive Summary
   - Key findings overview
   - Risk assessment

2. Attack Surface Map
   - External infrastructure diagram
   - Domain and subdomain inventory
   - Exposed services and applications

3. Personnel Intelligence
   - Key personnel profiles
   - Email address list
   - Organizational chart

4. Credential Exposure
   - Breach database findings
   - Leaked secrets and API keys
   - Password pattern analysis

5. Technology Stack
   - Identified technologies and versions
   - Known vulnerabilities for detected versions
   - Security tool coverage gaps

6. Recommended Attack Vectors
   - Prioritized initial access options
   - Social engineering target list
   - Technical vulnerability targets
```
