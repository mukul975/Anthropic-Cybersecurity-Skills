---
name: analyzing-sbom-for-supply-chain-vulnerabilities
description: 'Parses Software Bill of Materials (SBOM) in CycloneDX and SPDX JSON
  formats to identify supply chain vulnerabilities by correlating components against
  the NVD CVE database via the NVD 2.0 API. Builds dependency graphs, calculates risk
  scores, identifies transitive vulnerability paths, and generates compliance reports.
  Activates for requests involving SBOM analysis, software composition analysis, supply
  chain security assessment, dependency vulnerability scanning, CycloneDX/SPDX parsing,
  or CVE correlation.

  '
domain: cybersecurity
subdomain: supply-chain-security
tags:
- SBOM
- CycloneDX
- SPDX
- NVD
- CVE
- supply-chain
- dependency-analysis
- syft
- grype
version: 1.0.0
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0010
- AML.T0104
nist_ai_rmf:
- GOVERN-5.2
- MAP-1.6
- MANAGE-2.2
- GOVERN-1.1
- GOVERN-4.2
nist_csf:
- GV.SC-01
- GV.SC-03
- GV.SC-06
- GV.SC-07
mitre_attack:
- T1195.001
- T1195.002
- T1554
- T1190
---

# Analyzing SBOM for Supply Chain Vulnerabilities

## When to Use

- A new regulatory requirement (EO 14028, EU CRA) mandates SBOM analysis for software deliveries
- Security team needs to assess third-party risk by scanning vendor-provided SBOMs
- CI/CD pipeline requires automated vulnerability checks against generated SBOMs
- Incident response needs to determine if a newly disclosed CVE affects deployed software
- Procurement team requires supply chain risk assessment for a software acquisition

**Do not use** for runtime vulnerability scanning of live systems; use container scanning tools (Trivy, Grype CLI) or host-based vulnerability scanners (Nessus, Qualys) instead.

## Prerequisites

- SBOM file in CycloneDX JSON (v1.4+) or SPDX JSON (v2.3+) format
- Python 3.9+ with requests, networkx, and packaging libraries installed
- NVD API key (free, from https://nvd.nist.gov/developers/request-an-api-key) for higher rate limits
- Network access to NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0)
- Optionally: syft for SBOM generation, grype for cross-validation

## Workflow

### Step 1: Generate SBOM (if not provided)

Use syft to create an SBOM from a container image or project directory:

```bash
# Generate CycloneDX JSON from a container image
syft alpine:latest -o cyclonedx-json > sbom-cyclonedx.json

# Generate SPDX JSON from a project directory
syft dir:/path/to/project -o spdx-json > sbom-spdx.json

# Generate from a running container
syft docker:my-app-container -o cyclonedx-json > sbom.json
```

Syft supports over 30 package ecosystems including npm, PyPI, Maven, Go modules, apt, apk, and RPM. The generated SBOM includes package names, versions, licenses, CPE identifiers, and PURL (Package URL) references.

### Step 2: Parse SBOM and Extract Components

Parse the SBOM to extract all software components with their identifiers:

**CycloneDX JSON Structure:**
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.20",
      "purl": "pkg:npm/lodash@4.17.20",
      "cpe": "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:*:*:*",
      "licenses": [{"license": {"id": "MIT"}}]
    }
  ],
  "dependencies": [
    {"ref": "pkg:npm/express@4.18.2", "dependsOn": ["pkg:npm/lodash@4.17.20"]}
  ]
}
```

**SPDX JSON Structure:**
```json
{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {
      "name": "lodash",
      "versionInfo": "4.17.20",
      "externalRefs": [
        {"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.20"},
        {"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:*:*:*"}
      ],
      "licenseConcluded": "MIT"
    }
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-express", "relatedSpdxElement": "SPDXRef-lodash",
     "relationshipType": "DEPENDS_ON"}
  ]
}
```

### Step 3: Correlate Components with NVD CVE Database

Query the NVD 2.0 API to find known vulnerabilities for each component:

```python
import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def search_cves_by_cpe(cpe_name, api_key=None):
    params = {"cpeName": cpe_name, "resultsPerPage": 50}
    headers = {"apiKey": api_key} if api_key else {}
    resp = requests.get(NVD_API, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])

def search_cves_by_keyword(keyword, version=None, api_key=None):
    params = {"keywordSearch": keyword, "resultsPerPage": 50}
    headers = {"apiKey": api_key} if api_key else {}
    resp = requests.get(NVD_API, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])
```

The NVD API supports searching by CPE name (most precise), keyword, CVE ID, and date ranges. Rate limits: 5 requests/30 seconds without API key, 50 requests/30 seconds with key.

### Step 4: Build Dependency Graph and Identify Transitive Risks

Construct a directed graph of dependencies to trace vulnerability propagation:

```python
import networkx as nx

def build_dependency_graph(sbom):
    G = nx.DiGraph()
    # Add nodes for each component
    for comp in sbom["components"]:
        G.add_node(comp["purl"], name=comp["name"], version=comp["version"])
    # Add edges from dependency relationships
    for dep in sbom.get("dependencies", []):
        for child in dep.get("dependsOn", []):
            G.add_edge(dep["ref"], child)
    return G
```

Transitive dependency analysis identifies components that are not directly included but are pulled in through dependency chains. A vulnerability in a deeply nested transitive dependency (e.g., 4 levels deep) still represents risk but may be harder to remediate.

Key graph metrics for risk assessment:
- **In-degree**: How many components depend on this one (high in-degree = high blast radius)
- **Shortest path to root**: Distance from application entry point (closer = more exploitable)
- **Betweenness centrality**: Components that sit on many dependency paths (bottleneck risk)

### Step 5: Calculate Risk Scores

Aggregate vulnerability data into component and overall risk scores:

```
Risk Score Calculation:
━━━━━━━━━━━━━━━━━━━━━━
Component Risk = max(CVSS scores of all CVEs affecting the component)

Weighted Risk = Component Risk * Dependency Factor
  where Dependency Factor = 1.0 + (0.1 * in_degree)
  (more dependents = higher organizational impact)

Overall SBOM Risk = weighted average of all component risks
  weighted by dependency centrality

Risk Levels:
  CRITICAL: CVSS >= 9.0 or known exploited (CISA KEV)
  HIGH:     CVSS >= 7.0
  MEDIUM:   CVSS >= 4.0
  LOW:      CVSS < 4.0
```

### Step 6: Cross-Validate with Grype

Use grype to independently scan the SBOM and compare findings:

```bash
# Scan CycloneDX SBOM with grype
grype sbom:sbom-cyclonedx.json -o json > grype-results.json

# Scan SPDX SBOM
grype sbom:sbom-spdx.json -o table

# Filter by severity
grype sbom:sbom-cyclonedx.json --only-fixed --fail-on critical
```

Grype pulls vulnerability data from NVD, GitHub Security Advisories, Alpine SecDB, Red Hat, Debian, Ubuntu, Amazon Linux, and Oracle security databases, providing broader coverage than NVD alone.

### Step 7: Generate Compliance Report

Produce a structured report suitable for regulatory compliance:

```
SBOM VULNERABILITY ANALYSIS REPORT
====================================
SBOM File:         app-sbom-cyclonedx.json
Format:            CycloneDX v1.5
Analysis Date:     2026-03-19
Total Components:  247
Total Dependencies: 1,842 (direct: 34, transitive: 213)

VULNERABILITY SUMMARY
  Critical:  3 components / 5 CVEs
  High:      11 components / 18 CVEs
  Medium:    27 components / 41 CVEs
  Low:       8 components / 12 CVEs

CRITICAL FINDINGS
1. lodash@4.17.20
   CVE-2021-23337 (CVSS 7.2) - Command Injection via template
   CVE-2020-28500 (CVSS 5.3) - ReDoS in trimEnd
   Dependents: 14 components (high blast radius)
   Fix: Upgrade to 4.17.21+

2. log4j-core@2.14.1
   CVE-2021-44228 (CVSS 10.0) - Log4Shell RCE [CISA KEV]
   CVE-2021-45046 (CVSS 9.0) - Incomplete fix bypass
   Dependents: 8 components
   Fix: Upgrade to 2.17.1+

DEPENDENCY GRAPH RISKS
  Most depended-on: core-util@1.2.3 (47 dependents)
  Deepest chain: app -> framework -> adapter -> codec -> zlib (5 levels)
  Bottleneck components: 3 components on >50% of dependency paths

LICENSE COMPLIANCE
  Copyleft licenses found: 2 (GPL-3.0 in libxml2, AGPL-3.0 in mongodb-driver)
  Review required for commercial distribution
```

## Key Concepts

| Term | Definition |
|------|------------|
| **SBOM** | Software Bill of Materials; a formal inventory of all components, libraries, and dependencies in a software product |
| **CycloneDX** | OWASP-maintained SBOM standard supporting JSON, XML, and protobuf formats with dependency graph and vulnerability data |
| **SPDX** | Linux Foundation SBOM standard focused on license compliance with support for package, file, and snippet-level detail |
| **PURL** | Package URL; a standardized scheme for identifying software packages across ecosystems (e.g., pkg:npm/lodash@4.17.21) |
| **CPE** | Common Platform Enumeration; NIST naming scheme for IT products used to correlate with NVD CVE data |
| **NVD** | National Vulnerability Database; US government repository of vulnerability data indexed by CVE identifiers |
| **Transitive Dependency** | A dependency not directly declared but pulled in through the dependency chain of direct dependencies |
| **CISA KEV** | CISA Known Exploited Vulnerabilities catalog; CVEs confirmed to be actively exploited in the wild |

## Tools & Systems

- **syft** (Anchore): Open-source SBOM generator supporting 30+ package ecosystems and CycloneDX/SPDX output
- **grype** (Anchore): Vulnerability scanner that accepts SBOMs as input and correlates against multiple advisory databases
- **cyclonedx-python-lib**: Python library for creating, parsing, and validating CycloneDX SBOMs programmatically
- **lib4sbom**: Python library for parsing both SPDX and CycloneDX format SBOMs
- **nvdlib**: Python wrapper for the NVD 2.0 API supporting CVE and CPE queries with rate limit management
- **OWASP Dependency-Track**: Platform for continuous SBOM analysis, vulnerability tracking, and policy enforcement

## Common Scenarios

### Scenario: Assessing Vendor Software After Log4Shell Disclosure

**Context**: After the Log4Shell (CVE-2021-44228) disclosure, the security team needs to determine which vendor-supplied applications contain vulnerable versions of log4j. Several vendors have provided SBOMs per contractual requirements.

**Approach**:
1. Collect all vendor SBOMs (CycloneDX or SPDX JSON format)
2. Parse each SBOM and search for log4j-core components with versions < 2.17.1
3. Query NVD API for the specific CVEs (CVE-2021-44228, CVE-2021-45046, CVE-2021-45105)
4. Build dependency graphs to identify which application components depend on log4j
5. Calculate blast radius: how many services and endpoints are exposed
6. Generate prioritized remediation report sorted by exposure and business criticality
7. Cross-validate findings with grype scan of the same SBOMs

**Pitfalls**:
- Vendor SBOMs may be incomplete, missing shaded/bundled JAR files that embed log4j
- SPDX and CycloneDX version differences may affect parser compatibility
- NVD API rate limits can slow analysis when scanning hundreds of components without an API key
- CPE names in SBOMs may not exactly match NVD entries, requiring fuzzy matching
- Transitive dependencies may include log4j even when it is not a direct dependency
