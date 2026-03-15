---
name: implementing-attack-path-analysis-with-xm-cyber
description: Deploy XM Cyber's continuous exposure management platform to map attack paths, identify choke points, and prioritize the 2% of exposures that threaten critical assets.
domain: cybersecurity
subdomain: vulnerability-management
tags: [xm-cyber, attack-path-analysis, exposure-management, ctem, choke-points, breach-simulation, attack-surface]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Implementing Attack Path Analysis with XM Cyber

## Overview
XM Cyber is a continuous exposure management platform that uses attack graph analysis to identify how adversaries can chain together exposures -- vulnerabilities, misconfigurations, identity risks, and credential weaknesses -- to reach critical business assets. According to XM Cyber's 2024 research analyzing over 40 million exposures across 11.5 million entities, organizations typically have around 15,000 exploitable exposures, but traditional CVEs account for less than 1% of total exposures. The platform identifies that only 2% of exposures reside on "choke points" of converging attack paths, enabling security teams to focus on fixes that eliminate the most risk with the least effort.

## Prerequisites
- XM Cyber platform license and tenant access
- Network connectivity to monitored environments (on-premises, cloud, hybrid)
- Administrative access for agent deployment or agentless integration
- Cloud provider API access (AWS, Azure, GCP) for cloud attack path analysis
- Active Directory read access for identity-based attack path modeling
- CMDB or asset inventory defining critical business assets

## Core Concepts

### Attack Graph Analysis
Unlike point-in-time vulnerability scanning, XM Cyber continuously models all possible attack paths across the entire environment:

| Traditional Scanning | XM Cyber Attack Path Analysis |
|---------------------|-------------------------------|
| Lists individual vulnerabilities | Maps chained attack paths |
| Scores by CVSS severity | Scores by reachability to critical assets |
| Point-in-time assessment | Continuous real-time modeling |
| No context of lateral movement | Models full lateral movement chains |
| Treats each vuln independently | Shows how vulns chain together |

### Key Metrics from XM Cyber Research (2024)

| Finding | Statistic |
|---------|-----------|
| Average exposures per organization | ~15,000 |
| CVE-based exposures | < 1% of total |
| Misconfiguration-based exposures | ~80% of total |
| Exposures on critical choke points | 2% |
| Orgs where attackers can pivot on-prem to cloud | 70% |
| Cloud critical assets compromisable in 2 hops | 93% |
| Critical asset exposures in cloud platforms | 56% |

### Choke Point Concept
A choke point is a single entity (host, identity, credential, misconfiguration) that sits at the intersection of multiple attack paths leading to critical assets. Fixing a choke point eliminates many attack paths simultaneously, providing maximum risk reduction per remediation effort.

```
Attack Path 1:  Web Server -> SQL Injection -> DB Admin Creds
                                                    \
Attack Path 2:  VPN -> Stolen Creds -> File Server   -> Domain Controller
                                                    /     (Critical Asset)
Attack Path 3:  Workstation -> Mimikatz -> Cached Creds
                                    ^
                              CHOKE POINT
                     (Cached Domain Admin credential)
```

### Exposure Categories

| Category | % of Exposures | Examples |
|----------|---------------|----------|
| Identity & Credentials | 40% | Cached credentials, over-privileged accounts, Kerberoastable SPNs |
| Misconfigurations | 38% | Open shares, weak permissions, missing hardening |
| Network Exposures | 12% | Open ports, flat networks, missing segmentation |
| Software Vulnerabilities | 8% | Unpatched CVEs, outdated software |
| Cloud Exposures | 2% | IAM misconfig, public storage, overly permissive roles |

## Implementation Steps

### Step 1: Define Critical Assets (Business Context)

```
Critical Asset Definition:
    Tier 1 - Crown Jewels:
        - Domain Controllers (Active Directory)
        - Database servers with PII/financial data
        - ERP systems (SAP, Oracle)
        - Certificate Authority servers
        - Backup infrastructure (Veeam, Commvault)

    Tier 2 - High Value:
        - Email servers (Exchange)
        - File servers with IP/trade secrets
        - CI/CD pipeline servers
        - Jump servers / PAM vaults

    Tier 3 - Supporting Infrastructure:
        - DNS/DHCP servers
        - Monitoring systems
        - Logging infrastructure
```

### Step 2: Deploy XM Cyber Sensors

```
Deployment Architecture:
    On-Premises:
        - Install XM Cyber sensor on management server
        - Configure AD integration (read-only service account)
        - Enable network discovery protocols
        - Set scanning scope (IP ranges, AD OUs)

    Cloud (AWS):
        - Deploy XM Cyber CloudConnect via CloudFormation
        - Configure IAM role with read-only permissions
        - Enable cross-account scanning for multi-account orgs

    Cloud (Azure):
        - Deploy via Azure Marketplace
        - Configure Entra ID (Azure AD) integration
        - Grant Reader role on subscriptions

    Hybrid:
        - Configure cross-environment path analysis
        - Map on-premises to cloud trust relationships
        - Enable identity correlation across environments
```

### Step 3: Configure Attack Scenarios

```
Scenario 1: External Attacker to Domain Admin
    Starting Point:  Internet-facing assets
    Target:          Domain Admin privileges
    Attack Techniques: Exploit public CVEs, credential theft,
                      lateral movement, privilege escalation

Scenario 2: Insider Threat to Financial Data
    Starting Point:  Any corporate workstation
    Target:          Financial database servers
    Attack Techniques: Credential harvesting, share enumeration,
                      privilege escalation, data access

Scenario 3: Cloud Account Takeover
    Starting Point:  Compromised cloud IAM user
    Target:          Production cloud infrastructure
    Attack Techniques: IAM privilege escalation, cross-account
                      pivot, storage access, compute compromise

Scenario 4: Ransomware Propagation
    Starting Point:  Phished workstation
    Target:          Maximum host compromise (lateral spread)
    Attack Techniques: Credential reuse, SMB exploitation,
                      PsExec/WMI lateral movement
```

### Step 4: Analyze Attack Path Results

```python
# Interpreting XM Cyber attack path analysis results
def analyze_choke_points(attack_graph_results):
    """Analyze attack graph results for priority remediation."""

    choke_points = []
    for entity in attack_graph_results.get("entities", []):
        if entity.get("is_choke_point"):
            choke_points.append({
                "entity_name": entity["name"],
                "entity_type": entity["type"],
                "attack_paths_blocked": entity["paths_through"],
                "critical_assets_protected": entity["protects_assets"],
                "remediation_complexity": entity["fix_complexity"],
                "exposure_type": entity["exposure_category"],
            })

    # Sort by impact (paths blocked * assets protected)
    choke_points.sort(
        key=lambda x: x["attack_paths_blocked"] * len(x["critical_assets_protected"]),
        reverse=True
    )

    print(f"Total choke points identified: {len(choke_points)}")
    print(f"\nTop 10 choke points for maximum risk reduction:")
    for i, cp in enumerate(choke_points[:10], 1):
        print(f"  {i}. {cp['entity_name']} ({cp['entity_type']})")
        print(f"     Paths blocked: {cp['attack_paths_blocked']}")
        print(f"     Assets protected: {len(cp['critical_assets_protected'])}")
        print(f"     Exposure type: {cp['exposure_type']}")
        print(f"     Fix complexity: {cp['remediation_complexity']}")

    return choke_points
```

### Step 5: Prioritize Remediation by Impact

```
Remediation Priority Matrix:

Priority 1 (Immediate - 48h):
    - Choke points on paths to Tier 1 assets
    - Identity exposures (cached Domain Admin creds)
    - Internet-facing vulnerabilities with attack paths

Priority 2 (Urgent - 7 days):
    - Choke points on paths to Tier 2 assets
    - Cloud IAM misconfigurations with privilege escalation
    - Network segmentation gaps enabling lateral movement

Priority 3 (Important - 30 days):
    - Remaining choke points
    - Misconfigurations reducing defense depth
    - Non-critical software vulnerabilities on attack paths

Priority 4 (Standard - 90 days):
    - Exposures NOT on any attack path to critical assets
    - Informational findings
    - Hardening recommendations
```

## Best Practices
1. Define critical assets before deploying the platform; attack paths without target context are meaningless
2. Focus remediation on choke points first; fixing 2% of exposures can eliminate the majority of risk
3. Use attack path context to justify remediation urgency to IT teams (show the chain, not just the vuln)
4. Re-run attack path analysis after each remediation to verify paths are truly eliminated
5. Include cloud environments in analysis; 56% of critical asset exposures exist in cloud platforms
6. Monitor for new attack paths created by infrastructure changes (new servers, permission changes)
7. Integrate findings with ticketing systems for automated remediation tracking

## Common Pitfalls
- Focusing solely on CVEs when 80% of exposures come from misconfigurations
- Not defining critical assets, leading to unfocused attack path analysis
- Treating all exposures equally instead of focusing on choke points
- Ignoring identity-based attack paths (cached credentials, Kerberoastable accounts)
- Not correlating on-premises and cloud attack paths in hybrid environments
- Running analysis once instead of continuously

## Related Skills
- implementing-continuous-security-validation-with-bas
- performing-asset-criticality-scoring-for-vulns
- detecting-lateral-movement-in-network
- exploiting-active-directory-with-bloodhound
