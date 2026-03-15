---
name: triaging-vulnerabilities-with-ssvc-framework
description: Triage and prioritize vulnerabilities using CISA's Stakeholder-Specific Vulnerability Categorization (SSVC) decision tree framework to produce actionable remediation priorities.
domain: cybersecurity
subdomain: vulnerability-management
tags: [ssvc, vulnerability-triage, cisa, vulnerability-prioritization, decision-tree, cvss, remediation, risk-management]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Triaging Vulnerabilities with SSVC Framework

## Overview

The Stakeholder-Specific Vulnerability Categorization (SSVC) framework, developed by Carnegie Mellon University's Software Engineering Institute (SEI) in collaboration with CISA, provides a structured decision-tree methodology for vulnerability prioritization. Unlike CVSS alone, SSVC accounts for exploitation status, technical impact, automatability, mission prevalence, and public well-being impact to produce one of four actionable outcomes: **Track**, **Track***, **Attend**, or **Act**.

## Prerequisites

- Python 3.9+ with `requests`, `pandas`, and `jinja2` libraries
- Access to CISA KEV catalog API and EPSS API from FIRST
- NVD API key (optional, for higher rate limits)
- Vulnerability scan results from tools like OpenVAS, Nessus, or Qualys

## SSVC Decision Points

### 1. Exploitation Status
Assess current exploitation activity:
- **None** - No evidence of active exploitation
- **PoC** - Proof-of-concept exists publicly
- **Active** - Active exploitation observed in the wild (check CISA KEV)

```bash
# Check if a CVE is in CISA Known Exploited Vulnerabilities catalog
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" | \
  python3 -c "import sys,json; data=json.load(sys.stdin); cves=[v['cveID'] for v in data['vulnerabilities']]; print('Active' if 'CVE-2024-3400' in cves else 'Check PoC/None')"
```

### 2. Technical Impact
Determine scope of compromise if exploited:
- **Partial** - Limited to a subset of system functionality or data
- **Total** - Full control of the affected system, complete data access

### 3. Automatability
Evaluate if exploitation can be automated at scale:
- **No** - Requires manual, targeted exploitation per victim
- **Yes** - Can be scripted or worm-like propagation is possible

### 4. Mission Prevalence
How widespread is the affected product in your environment:
- **Minimal** - Limited deployment, non-critical systems
- **Support** - Supports mission-critical functions indirectly
- **Essential** - Directly enables core mission capabilities

### 5. Public Well-Being Impact
Potential consequences for physical safety and public welfare:
- **Minimal** - Negligible impact on safety or public services
- **Material** - Noticeable degradation of public services
- **Irreversible** - Loss of life, major property damage, or critical infrastructure failure

## SSVC Decision Outcomes

| Outcome | Action Required | SLA |
|---------|----------------|-----|
| **Track** | Monitor, remediate in normal patch cycle | 90 days |
| **Track*** | Monitor closely, prioritize in next patch window | 60 days |
| **Attend** | Escalate to senior management, accelerate remediation | 14 days |
| **Act** | Apply mitigations immediately, executive-level awareness | 48 hours |

## Implementation Steps

### Step 1: Ingest Vulnerability Data
```python
import requests
import json

# Fetch CISA KEV catalog
kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
kev_data = requests.get(kev_url).json()
kev_cves = {v['cveID'] for v in kev_data['vulnerabilities']}

# Fetch EPSS scores for context
epss_url = "https://api.first.org/data/v1/epss"
epss_response = requests.get(epss_url, params={"cve": "CVE-2024-3400"}).json()
```

### Step 2: Evaluate Each Decision Point
```python
def evaluate_exploitation(cve_id, kev_set):
    """Determine exploitation status from CISA KEV and EPSS data."""
    if cve_id in kev_set:
        return "active"
    epss = requests.get(
        "https://api.first.org/data/v1/epss",
        params={"cve": cve_id}
    ).json()
    if epss.get("data"):
        score = float(epss["data"][0].get("epss", 0))
        if score > 0.5:
            return "poc"
    return "none"

def evaluate_technical_impact(cvss_vector):
    """Parse CVSS vector for scope and impact metrics."""
    if "S:C" in cvss_vector or "C:H/I:H/A:H" in cvss_vector:
        return "total"
    return "partial"

def evaluate_automatability(cvss_vector, cve_description):
    """Check if attack vector is network-based with low complexity."""
    if "AV:N" in cvss_vector and "AC:L" in cvss_vector and "UI:N" in cvss_vector:
        return "yes"
    return "no"
```

### Step 3: Apply SSVC Decision Tree
```python
def ssvc_decision(exploitation, tech_impact, automatability, mission_prevalence, public_wellbeing):
    """CISA SSVC decision tree implementation."""
    if exploitation == "active":
        if tech_impact == "total" or automatability == "yes":
            return "Act"
        if mission_prevalence in ("essential", "support"):
            return "Act"
        return "Attend"
    if exploitation == "poc":
        if automatability == "yes" and tech_impact == "total":
            return "Attend"
        if mission_prevalence == "essential":
            return "Attend"
        return "Track*"
    # exploitation == "none"
    if tech_impact == "total" and mission_prevalence == "essential":
        return "Track*"
    return "Track"
```

### Step 4: Generate Triage Report
```bash
# Run the SSVC triage script against scan results
python3 scripts/process.py --input scan_results.csv --output ssvc_triage_report.json

# View summary
cat ssvc_triage_report.json | python3 -m json.tool | head -50
```

## Integration with Vulnerability Scanners

### Import from Nessus CSV
```bash
# Export Nessus scan as CSV, then process
python3 scripts/process.py \
  --input nessus_export.csv \
  --format nessus \
  --output ssvc_results.json
```

### Import from OpenVAS
```bash
# Export OpenVAS results as XML
python3 scripts/process.py \
  --input openvas_report.xml \
  --format openvas \
  --output ssvc_results.json
```

## Validation and Testing

```bash
# Test SSVC decision logic with known CVEs
python3 -c "
from scripts.process import ssvc_decision
# CVE-2024-3400 - Palo Alto PAN-OS command injection (KEV listed)
assert ssvc_decision('active', 'total', 'yes', 'essential', 'material') == 'Act'
# CVE-2024-21887 - Ivanti Connect Secure (PoC available)
assert ssvc_decision('poc', 'total', 'yes', 'support', 'minimal') == 'Attend'
print('All SSVC decision tests passed')
"
```

## References

- [CISA SSVC Framework](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)
- [CERT/CC SSVC Documentation](https://certcc.github.io/SSVC/)
- [CISA SSVC Guide PDF](https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf)
- [FIRST EPSS API](https://www.first.org/epss/)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
