---
name: performing-asset-criticality-scoring-for-vulns
description: Develop and apply a multi-factor asset criticality scoring model to weight vulnerability prioritization based on business impact, data sensitivity, and operational importance.
domain: cybersecurity
subdomain: vulnerability-management
tags: [asset-criticality, vulnerability-prioritization, risk-management, cmdb, business-impact, crown-jewels, asset-classification]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Asset Criticality Scoring for Vulns

## Overview
Asset criticality scoring assigns a business impact rating to each IT asset so that vulnerability remediation efforts focus on systems with the greatest organizational risk. Without criticality context, a CVSS 9.0 vulnerability on a test server receives the same urgency as the same vulnerability on a payment processing database. This skill covers building a multi-factor scoring model incorporating data sensitivity, business function dependency, regulatory scope, network exposure, and recoverability to create a 1-5 criticality tier that directly modifies vulnerability remediation SLAs.

## Prerequisites
- Configuration Management Database (CMDB) or asset inventory
- Business Impact Analysis (BIA) data
- Data classification policy
- Network architecture documentation
- Stakeholder input from business unit owners

## Core Concepts

### Asset Criticality Scoring Model

| Factor | Weight | Score Range | Description |
|--------|--------|-------------|-------------|
| Business Function Impact | 25% | 1-5 | How critical is the supported business process |
| Data Sensitivity | 25% | 1-5 | Type and sensitivity of data processed/stored |
| Regulatory Scope | 15% | 1-5 | Regulatory requirements (PCI, HIPAA, SOX) |
| Network Exposure | 15% | 1-5 | Internet-facing vs internal-only |
| Recoverability | 10% | 1-5 | RTO/RPO requirements, DR capability |
| User Population | 10% | 1-5 | Number of users/customers affected |

### Criticality Tier Definitions

| Tier | Score Range | Label | SLA Modifier | Examples |
|------|------------|-------|-------------|---------|
| 1 | 4.5-5.0 | Crown Jewels | -50% SLA | Domain controllers, payment systems, ERP |
| 2 | 3.5-4.4 | High Value | -25% SLA | Email servers, HR systems, CI/CD |
| 3 | 2.5-3.4 | Standard | Baseline SLA | Internal apps, file servers |
| 4 | 1.5-2.4 | Low Impact | +25% SLA | Test environments, printers |
| 5 | 1.0-1.4 | Minimal | +50% SLA | Decommissioning, isolated labs |

### Data Sensitivity Scoring

| Score | Classification | Examples |
|-------|---------------|---------|
| 5 | Restricted/Secret | PII, PHI, payment card data, trade secrets |
| 4 | Confidential | Financial reports, HR records, source code |
| 3 | Internal | Internal documents, policies, project files |
| 2 | Semi-public | Marketing materials, press releases (draft) |
| 1 | Public | Published content, public APIs |

## Implementation Steps

### Step 1: Define Scoring Criteria

```python
class AssetCriticalityScorer:
    """Multi-factor asset criticality scoring engine."""

    WEIGHTS = {
        "business_function": 0.25,
        "data_sensitivity": 0.25,
        "regulatory_scope": 0.15,
        "network_exposure": 0.15,
        "recoverability": 0.10,
        "user_population": 0.10,
    }

    TIER_THRESHOLDS = [
        (4.5, 1, "Crown Jewels", -0.50),
        (3.5, 2, "High Value", -0.25),
        (2.5, 3, "Standard", 0.00),
        (1.5, 4, "Low Impact", 0.25),
        (1.0, 5, "Minimal", 0.50),
    ]

    def score_asset(self, asset):
        """Calculate criticality score for an asset."""
        weighted_score = sum(
            asset.get(factor, 3) * weight
            for factor, weight in self.WEIGHTS.items()
        )
        score = round(weighted_score, 2)

        for threshold, tier, label, sla_mod in self.TIER_THRESHOLDS:
            if score >= threshold:
                return {
                    "score": score,
                    "tier": tier,
                    "label": label,
                    "sla_modifier": sla_mod,
                }
        return {"score": score, "tier": 5, "label": "Minimal", "sla_modifier": 0.50}

    def adjust_vuln_sla(self, base_sla_days, asset_tier_data):
        """Adjust vulnerability SLA based on asset criticality."""
        modifier = asset_tier_data["sla_modifier"]
        adjusted = int(base_sla_days * (1 + modifier))
        return max(1, adjusted)  # Minimum 1 day SLA
```

### Step 2: Integrate with Vulnerability Prioritization

```python
def apply_criticality_to_vulns(vulns_df, asset_scores):
    """Enrich vulnerability data with asset criticality context."""
    for idx, vuln in vulns_df.iterrows():
        asset_id = vuln.get("asset_id", "")
        asset_data = asset_scores.get(asset_id, {"tier": 3, "sla_modifier": 0})

        vulns_df.at[idx, "asset_tier"] = asset_data["tier"]
        vulns_df.at[idx, "asset_label"] = asset_data.get("label", "Standard")

        base_sla = get_base_sla(vuln["severity"])
        adjusted_sla = int(base_sla * (1 + asset_data["sla_modifier"]))
        vulns_df.at[idx, "adjusted_sla_days"] = max(1, adjusted_sla)

    return vulns_df
```

## Best Practices
1. Involve business stakeholders in criticality scoring; IT alone cannot assess business impact
2. Review and update criticality scores at least quarterly or when systems change roles
3. Automate scoring where possible using CMDB tags and data classification labels
4. Apply criticality tiers to vulnerability SLAs for risk-proportional remediation
5. Validate scoring against actual incident impact data to calibrate the model
6. Start with a simple 3-tier model before expanding to 5 tiers

## Common Pitfalls
- Classifying all assets as "critical" which defeats the purpose of tiering
- Not updating criticality scores when systems are repurposed or decommissioned
- Using only technical factors without business context
- Applying uniform SLAs regardless of asset importance
- Not documenting the scoring methodology for audit and consistency

## Related Skills
- performing-cve-prioritization-with-kev-catalog
- building-vulnerability-aging-and-sla-tracking
- performing-business-impact-analysis
- implementing-asset-management-program
