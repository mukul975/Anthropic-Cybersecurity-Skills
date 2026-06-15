---
name: performing-privacy-impact-assessment
description: 'Automates the Privacy Impact Assessment (PIA) workflow including data
  flow mapping, privacy risk scoring matrices, GDPR Article 35 DPIA and CCPA/CPRA
  alignment checks, data inventory cataloging, and remediation tracking. Implements
  the NIST Privacy Framework PRAM methodology and ICO DPIA guidance for systematic
  identification and mitigation of privacy risks across processing activities. Use
  when conducting privacy assessments for new systems, evaluating regulatory compliance
  posture, or building automated privacy governance programs.

  '
domain: cybersecurity
subdomain: privacy-compliance
tags:
- privacy
- impact-assessment
- GDPR
- CCPA
- NIST
- DPIA
- data-flow-mapping
- risk-scoring
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
- GV.PO-01
- PR.DS-01
- GV.OC-05
mitre_attack:
- T1078
- T1190
- T1059
---

# Performing Privacy Impact Assessment

## When to Use

- When launching a new system, product, or processing activity that handles personal data
- When conducting GDPR Article 35 Data Protection Impact Assessments (DPIAs)
- When evaluating CCPA/CPRA compliance for data processing operations
- When performing privacy risk assessments aligned to the NIST Privacy Framework
- When mapping data flows across organizational boundaries and third-party processors
- When building automated privacy governance and assessment pipelines
- When preparing for regulatory audits or demonstrating accountability obligations

## Prerequisites

- Familiarity with GDPR, CCPA/CPRA, and NIST Privacy Framework concepts
- Access to data processing inventories and system architecture documentation
- Python 3.8+ with required dependencies installed
- Appropriate authorization from the Data Protection Officer (DPO) or privacy team
- Knowledge of organizational data flows and third-party processor relationships

## Instructions

### Phase 1: Data Inventory and Processing Activity Catalog

Build a complete inventory of personal data processing activities. Each record of
processing activity (ROPA) entry must capture the data categories, legal basis,
retention periods, and data subjects involved.

```python
from agent import PrivacyImpactAssessmentEngine

engine = PrivacyImpactAssessmentEngine()

# Register a processing activity for assessment
activity = engine.register_processing_activity(
    name="Customer Analytics Platform",
    description="Collects browsing behavior and purchase history for personalization",
    data_controller="Acme Corp",
    data_processor="CloudAnalytics Inc",
    data_categories=["browsing_history", "purchase_records", "ip_address", "device_id"],
    data_subjects=["customers", "website_visitors"],
    legal_basis="consent",
    retention_period_days=730,
    cross_border_transfer=True,
    transfer_destinations=["US", "IN"],
    automated_decision_making=True,
)
print(f"Registered activity: {activity['activity_id']}")
```

### Phase 2: Data Flow Mapping

Map all data flows from collection to deletion, identifying every touchpoint,
transformation, and storage location. This reveals hidden privacy risks in data
movement across systems.

```python
# Build the data flow map
flow_map = engine.map_data_flows(
    activity_id=activity["activity_id"],
    flows=[
        {
            "stage": "collection",
            "source": "Web browser cookie + form submission",
            "destination": "CDN edge server",
            "data_elements": ["ip_address", "device_id", "browsing_history"],
            "encryption_in_transit": True,
            "protocol": "TLS 1.3",
        },
        {
            "stage": "processing",
            "source": "CDN edge server",
            "destination": "Analytics data warehouse (US-East)",
            "data_elements": ["browsing_history", "purchase_records", "device_id"],
            "encryption_in_transit": True,
            "encryption_at_rest": True,
            "protocol": "mTLS",
        },
        {
            "stage": "storage",
            "source": "Analytics data warehouse",
            "destination": "S3 encrypted bucket",
            "data_elements": ["browsing_history", "purchase_records"],
            "encryption_at_rest": True,
            "retention_days": 730,
            "access_controls": "IAM role-based, MFA required",
        },
        {
            "stage": "sharing",
            "source": "Analytics data warehouse",
            "destination": "Third-party ML provider (IN)",
            "data_elements": ["browsing_history", "purchase_records"],
            "encryption_in_transit": True,
            "data_processing_agreement": True,
            "cross_border": True,
        },
        {
            "stage": "deletion",
            "source": "S3 bucket + data warehouse",
            "destination": "Secure erasure",
            "method": "Cryptographic erasure + lifecycle policy",
            "verification": "Automated deletion audit log",
        },
    ],
)
engine.render_data_flow_diagram(flow_map)
```

### Phase 3: Privacy Risk Assessment with Scoring Matrix

Apply a structured risk scoring methodology evaluating likelihood and impact
across multiple privacy risk dimensions. The matrix aligns with both the
NIST PRAM and ICO DPIA risk assessment approaches.

```python
# Run the risk assessment
risk_report = engine.assess_privacy_risks(
    activity_id=activity["activity_id"],
    assessment_type="full_dpia",
)

# Display risk matrix results
for risk in risk_report["risks"]:
    print(f"[{risk['severity']}] {risk['category']}: {risk['description']}")
    print(f"  Likelihood: {risk['likelihood']}/5 | Impact: {risk['impact']}/5 | Score: {risk['risk_score']}/25")
    print(f"  Mitigation: {risk['recommended_mitigation']}")
```

Risk categories evaluated include:
1. **Data Minimization** -- Excessive collection beyond stated purpose
2. **Purpose Limitation** -- Secondary use without legal basis
3. **Cross-Border Transfer** -- Transfers without adequate safeguards (SCCs, BCRs)
4. **Automated Decision Making** -- Profiling without human oversight or appeal
5. **Data Subject Rights** -- Inability to fulfill access/erasure/portability requests
6. **Third-Party Risk** -- Processor compliance gaps, subprocessor chains
7. **Security Controls** -- Encryption, access control, breach response gaps
8. **Retention** -- Storing data beyond necessity or legal requirement
9. **Consent Management** -- Invalid or ambiguous consent mechanisms
10. **Breach Notification** -- Inability to detect and notify within 72 hours (GDPR)

### Phase 4: GDPR and CCPA/CPRA Alignment Checks

Run automated compliance checks against specific regulatory requirements.
The engine maps each processing activity against article-level GDPR obligations
and CCPA/CPRA consumer rights requirements.

```python
# GDPR compliance check
gdpr_report = engine.check_gdpr_compliance(activity_id=activity["activity_id"])
print(f"GDPR Score: {gdpr_report['compliance_score']}/100")
for finding in gdpr_report["findings"]:
    print(f"  [{finding['status']}] Art.{finding['article']}: {finding['description']}")

# CCPA/CPRA compliance check
ccpa_report = engine.check_ccpa_compliance(activity_id=activity["activity_id"])
print(f"CCPA Score: {ccpa_report['compliance_score']}/100")
for finding in ccpa_report["findings"]:
    print(f"  [{finding['status']}] Sec.{finding['section']}: {finding['description']}")
```

### Phase 5: Remediation Plan and Report Generation

Generate a prioritized remediation plan with specific action items, responsible
parties, deadlines, and generate the formal PIA/DPIA report document.

```python
# Generate remediation plan
remediation = engine.generate_remediation_plan(
    activity_id=activity["activity_id"],
    risk_report=risk_report,
    gdpr_report=gdpr_report,
    ccpa_report=ccpa_report,
)

for item in remediation["action_items"]:
    print(f"[{item['priority']}] {item['action']}")
    print(f"  Owner: {item['owner']} | Deadline: {item['deadline']}")
    print(f"  Addresses: {', '.join(item['addresses_risks'])}")

# Generate formal DPIA report
engine.generate_dpia_report(
    activity_id=activity["activity_id"],
    output_path="dpia_report_customer_analytics.json",
    format="json",
)
print("[+] DPIA report generated")
```

## Examples

### Quick Screening Assessment

Determine whether a full DPIA is required using the ICO screening checklist:

```python
engine = PrivacyImpactAssessmentEngine()

screening = engine.run_screening_checklist(
    uses_special_category_data=False,
    large_scale_processing=True,
    systematic_monitoring=True,
    automated_decision_making=True,
    cross_border_transfer=True,
    vulnerable_data_subjects=False,
    innovative_technology=True,
    denial_of_service_or_rights=False,
)
print(f"DPIA Required: {screening['dpia_required']}")
print(f"Triggers: {screening['triggers']}")
# Output: DPIA Required: True
# Triggers: ['large_scale_processing', 'systematic_monitoring',
#            'automated_decision_making', 'cross_border_transfer',
#            'innovative_technology']
```

### Batch Assessment of Multiple Processing Activities

```python
engine = PrivacyImpactAssessmentEngine()

activities = [
    {"name": "Email Marketing", "data_categories": ["email", "name"],
     "legal_basis": "consent", "cross_border_transfer": False},
    {"name": "HR Analytics", "data_categories": ["employee_id", "performance_scores",
     "health_data"], "legal_basis": "legitimate_interest", "cross_border_transfer": True},
    {"name": "Fraud Detection", "data_categories": ["transaction_data", "ip_address",
     "device_fingerprint"], "legal_basis": "legitimate_interest",
     "automated_decision_making": True, "cross_border_transfer": False},
]

for act_def in activities:
    activity = engine.register_processing_activity(**act_def)
    risk = engine.assess_privacy_risks(activity_id=activity["activity_id"])
    print(f"{act_def['name']}: Overall Risk={risk['overall_risk_level']} "
          f"({risk['risk_count_by_severity']})")
```

### NIST Privacy Framework Profile Mapping

```python
engine = PrivacyImpactAssessmentEngine()

profile = engine.generate_nist_privacy_profile(
    activity_id=activity["activity_id"],
    target_tier="tier_3",  # Repeatable
)

for function_id, outcomes in profile["functions"].items():
    print(f"\n{function_id}:")
    for outcome in outcomes:
        status = "PASS" if outcome["implemented"] else "GAP"
        print(f"  [{status}] {outcome['subcategory']}: {outcome['description']}")
```
