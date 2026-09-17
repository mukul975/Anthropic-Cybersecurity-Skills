#!/usr/bin/env python3
"""Agent for performing automated Privacy Impact Assessments (PIA/DPIA).

Implements the NIST Privacy Framework PRAM methodology and ICO DPIA guidance
for systematic identification and mitigation of privacy risks. Supports
GDPR Article 35 and CCPA/CPRA compliance checks with risk scoring matrices.
"""

import json
import uuid
import argparse
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Data sensitivity classification
# ---------------------------------------------------------------------------
DATA_SENSITIVITY = {
    # Special category / sensitive (GDPR Art. 9)
    "health_data": {"sensitivity": "special_category", "weight": 5},
    "biometric_data": {"sensitivity": "special_category", "weight": 5},
    "genetic_data": {"sensitivity": "special_category", "weight": 5},
    "racial_ethnic_origin": {"sensitivity": "special_category", "weight": 5},
    "political_opinions": {"sensitivity": "special_category", "weight": 5},
    "religious_beliefs": {"sensitivity": "special_category", "weight": 5},
    "sexual_orientation": {"sensitivity": "special_category", "weight": 5},
    "trade_union_membership": {"sensitivity": "special_category", "weight": 5},
    # High sensitivity PII
    "ssn": {"sensitivity": "high", "weight": 4},
    "financial_account": {"sensitivity": "high", "weight": 4},
    "credit_card": {"sensitivity": "high", "weight": 4},
    "passport_number": {"sensitivity": "high", "weight": 4},
    "drivers_license": {"sensitivity": "high", "weight": 4},
    "login_credentials": {"sensitivity": "high", "weight": 4},
    "performance_scores": {"sensitivity": "high", "weight": 4},
    "salary_data": {"sensitivity": "high", "weight": 4},
    # Medium sensitivity
    "email": {"sensitivity": "medium", "weight": 3},
    "phone_number": {"sensitivity": "medium", "weight": 3},
    "date_of_birth": {"sensitivity": "medium", "weight": 3},
    "home_address": {"sensitivity": "medium", "weight": 3},
    "ip_address": {"sensitivity": "medium", "weight": 3},
    "geolocation": {"sensitivity": "medium", "weight": 3},
    "employee_id": {"sensitivity": "medium", "weight": 3},
    "purchase_records": {"sensitivity": "medium", "weight": 3},
    "transaction_data": {"sensitivity": "medium", "weight": 3},
    # Low sensitivity
    "name": {"sensitivity": "low", "weight": 2},
    "job_title": {"sensitivity": "low", "weight": 2},
    "company_name": {"sensitivity": "low", "weight": 2},
    "browsing_history": {"sensitivity": "low", "weight": 2},
    "device_id": {"sensitivity": "low", "weight": 2},
    "device_fingerprint": {"sensitivity": "low", "weight": 2},
    "cookie_id": {"sensitivity": "low", "weight": 1},
    "public_profile": {"sensitivity": "low", "weight": 1},
}

# Countries with GDPR adequacy decisions (as of 2026)
GDPR_ADEQUATE_COUNTRIES = {
    "AD", "AR", "CA", "FO", "GG", "IL", "IM", "JP", "JE", "NZ",
    "KR", "CH", "GB", "UY", "US",  # US under EU-US Data Privacy Framework
    # All EU/EEA member states
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
    "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
    "PL", "PT", "RO", "SK", "SI", "ES", "SE", "IS", "LI", "NO",
}

# GDPR articles relevant to DPIA
GDPR_DPIA_ARTICLES = {
    "5": {
        "title": "Principles relating to processing of personal data",
        "checks": [
            {"id": "5.1a", "desc": "Lawfulness, fairness and transparency",
             "field": "legal_basis", "required": True},
            {"id": "5.1b", "desc": "Purpose limitation",
             "field": "purpose_specified", "required": True},
            {"id": "5.1c", "desc": "Data minimization",
             "field": "data_minimization_justified", "required": True},
            {"id": "5.1d", "desc": "Accuracy of data",
             "field": "accuracy_measures", "required": True},
            {"id": "5.1e", "desc": "Storage limitation",
             "field": "retention_period_days", "required": True},
            {"id": "5.1f", "desc": "Integrity and confidentiality",
             "field": "security_measures", "required": True},
        ],
    },
    "6": {
        "title": "Lawfulness of processing",
        "checks": [
            {"id": "6.1", "desc": "Valid legal basis identified",
             "field": "legal_basis", "valid_values": [
                 "consent", "contract", "legal_obligation",
                 "vital_interests", "public_task", "legitimate_interest"]},
        ],
    },
    "7": {
        "title": "Conditions for consent",
        "checks": [
            {"id": "7.1", "desc": "Demonstrable consent obtained",
             "field": "consent_mechanism", "condition_field": "legal_basis",
             "condition_value": "consent"},
            {"id": "7.3", "desc": "Right to withdraw consent",
             "field": "consent_withdrawal_mechanism", "condition_field": "legal_basis",
             "condition_value": "consent"},
        ],
    },
    "13": {
        "title": "Information to be provided at collection",
        "checks": [
            {"id": "13.1", "desc": "Privacy notice provided at collection",
             "field": "privacy_notice", "required": True},
        ],
    },
    "22": {
        "title": "Automated individual decision-making",
        "checks": [
            {"id": "22.1", "desc": "Right not to be subject to automated decision",
             "field": "human_oversight", "condition_field": "automated_decision_making",
             "condition_value": True},
            {"id": "22.3", "desc": "Right to contest automated decision",
             "field": "appeal_mechanism", "condition_field": "automated_decision_making",
             "condition_value": True},
        ],
    },
    "25": {
        "title": "Data protection by design and by default",
        "checks": [
            {"id": "25.1", "desc": "Privacy by design measures implemented",
             "field": "privacy_by_design", "required": True},
            {"id": "25.2", "desc": "Data protection by default",
             "field": "data_protection_defaults", "required": True},
        ],
    },
    "28": {
        "title": "Processor obligations",
        "checks": [
            {"id": "28.3", "desc": "Data processing agreement with processor",
             "field": "data_processing_agreement", "condition_field": "data_processor",
             "condition_value": "_nonempty"},
        ],
    },
    "30": {
        "title": "Records of processing activities",
        "checks": [
            {"id": "30.1", "desc": "ROPA maintained",
             "field": "ropa_entry", "required": True},
        ],
    },
    "32": {
        "title": "Security of processing",
        "checks": [
            {"id": "32.1", "desc": "Appropriate technical and organizational measures",
             "field": "security_measures", "required": True},
        ],
    },
    "33": {
        "title": "Notification of breach to supervisory authority",
        "checks": [
            {"id": "33.1", "desc": "Breach notification within 72 hours capability",
             "field": "breach_notification_plan", "required": True},
        ],
    },
    "35": {
        "title": "Data protection impact assessment",
        "checks": [
            {"id": "35.7a", "desc": "Systematic description of processing",
             "field": "processing_description", "required": True},
            {"id": "35.7b", "desc": "Necessity and proportionality assessment",
             "field": "necessity_assessment", "required": True},
            {"id": "35.7c", "desc": "Risks to rights and freedoms assessment",
             "field": "risk_assessment_completed", "required": True},
            {"id": "35.7d", "desc": "Measures to address risks",
             "field": "risk_mitigation_measures", "required": True},
        ],
    },
    "44": {
        "title": "General principle for transfers",
        "checks": [
            {"id": "44.1", "desc": "Transfer safeguards for cross-border data",
             "field": "transfer_safeguards", "condition_field": "cross_border_transfer",
             "condition_value": True},
        ],
    },
}

# CCPA/CPRA sections for compliance checks
CCPA_SECTIONS = {
    "1798.100": {
        "title": "Consumer right to know",
        "checks": [
            {"id": "100.a", "desc": "Right to know what PI is collected",
             "field": "data_inventory_available", "required": True},
            {"id": "100.b", "desc": "Disclosure of categories of PI collected",
             "field": "categories_disclosed", "required": True},
        ],
    },
    "1798.105": {
        "title": "Consumer right to delete",
        "checks": [
            {"id": "105.a", "desc": "Right to request deletion of PI",
             "field": "deletion_mechanism", "required": True},
        ],
    },
    "1798.106": {
        "title": "Consumer right to correct",
        "checks": [
            {"id": "106.a", "desc": "Right to correct inaccurate PI",
             "field": "correction_mechanism", "required": True},
        ],
    },
    "1798.110": {
        "title": "Right to know specific pieces of PI",
        "checks": [
            {"id": "110.a", "desc": "Disclose categories, sources, purposes, third parties",
             "field": "data_inventory_available", "required": True},
        ],
    },
    "1798.115": {
        "title": "Right to know about selling/sharing",
        "checks": [
            {"id": "115.a", "desc": "Disclosure of selling or sharing of PI",
             "field": "selling_sharing_disclosed", "required": True},
        ],
    },
    "1798.120": {
        "title": "Consumer right to opt-out of sale/sharing",
        "checks": [
            {"id": "120.a", "desc": "Do Not Sell or Share opt-out mechanism",
             "field": "opt_out_mechanism", "condition_field": "sells_or_shares_data",
             "condition_value": True},
        ],
    },
    "1798.121": {
        "title": "Right to limit use of sensitive PI",
        "checks": [
            {"id": "121.a", "desc": "Limit use and disclosure of sensitive PI",
             "field": "sensitive_data_controls", "condition_field": "_has_sensitive_data",
             "condition_value": True},
        ],
    },
    "1798.125": {
        "title": "Non-discrimination",
        "checks": [
            {"id": "125.a", "desc": "No discrimination for exercising rights",
             "field": "non_discrimination_policy", "required": True},
        ],
    },
    "1798.130": {
        "title": "Notice and request handling",
        "checks": [
            {"id": "130.a", "desc": "Methods for submitting consumer requests",
             "field": "request_submission_methods", "required": True},
            {"id": "130.a.2", "desc": "Respond to requests within 45 days",
             "field": "response_sla_days", "required": True, "max_value": 45},
        ],
    },
    "1798.135": {
        "title": "Do Not Sell or Share link",
        "checks": [
            {"id": "135.a", "desc": "Clear and conspicuous opt-out link on homepage",
             "field": "opt_out_link_on_homepage", "condition_field": "sells_or_shares_data",
             "condition_value": True},
        ],
    },
    "1798.185": {
        "title": "CPRA risk assessment requirement",
        "checks": [
            {"id": "185.a.15", "desc": "Risk assessment for significant processing",
             "field": "risk_assessment_completed", "required": True},
        ],
    },
}

# NIST Privacy Framework functions and categories
NIST_PRIVACY_FUNCTIONS = {
    "ID-P": {
        "name": "Identify-P",
        "description": "Develop organizational understanding to manage privacy risk",
        "categories": {
            "ID.IM-P": {
                "name": "Inventory and Mapping",
                "subcategories": [
                    {"id": "ID.IM-P1", "desc": "Systems and assets that process data are inventoried",
                     "check": "data_inventory_available"},
                    {"id": "ID.IM-P2", "desc": "Data actions mapped to system operations",
                     "check": "data_flow_mapped"},
                    {"id": "ID.IM-P3", "desc": "Data elements mapped within data actions",
                     "check": "data_elements_mapped"},
                    {"id": "ID.IM-P4", "desc": "Data actions of service providers identified",
                     "check": "processor_actions_identified"},
                    {"id": "ID.IM-P5", "desc": "Affected individuals identified",
                     "check": "data_subjects_identified"},
                    {"id": "ID.IM-P6", "desc": "Data processing purposes identified",
                     "check": "purpose_specified"},
                    {"id": "ID.IM-P7", "desc": "Legal authorities for data actions identified",
                     "check": "legal_basis"},
                    {"id": "ID.IM-P8", "desc": "Problematic data actions assessed",
                     "check": "risk_assessment_completed"},
                ],
            },
            "ID.BE-P": {
                "name": "Business Environment",
                "subcategories": [
                    {"id": "ID.BE-P1", "desc": "Privacy values and policies established",
                     "check": "privacy_policy_established"},
                    {"id": "ID.BE-P2", "desc": "Privacy role in enterprise risk management",
                     "check": "privacy_in_erm"},
                ],
            },
            "ID.RA-P": {
                "name": "Risk Assessment",
                "subcategories": [
                    {"id": "ID.RA-P1", "desc": "Contextual factors related to data processing identified",
                     "check": "contextual_factors_documented"},
                    {"id": "ID.RA-P2", "desc": "Data analytic inputs and outputs identified",
                     "check": "analytics_io_documented"},
                    {"id": "ID.RA-P3", "desc": "Potential problematic data actions assessed",
                     "check": "risk_assessment_completed"},
                    {"id": "ID.RA-P4", "desc": "Problematic data actions prioritized",
                     "check": "risks_prioritized"},
                    {"id": "ID.RA-P5", "desc": "Risk responses identified and prioritized",
                     "check": "risk_responses_identified"},
                ],
            },
        },
    },
    "GV-P": {
        "name": "Govern-P",
        "description": "Develop and implement organizational governance structure",
        "categories": {
            "GV.PO-P": {
                "name": "Governance Policies, Processes, and Procedures",
                "subcategories": [
                    {"id": "GV.PO-P1", "desc": "Organizational privacy policy established",
                     "check": "privacy_policy_established"},
                    {"id": "GV.PO-P2", "desc": "Privacy risk management processes established",
                     "check": "risk_management_process"},
                    {"id": "GV.PO-P3", "desc": "Roles and responsibilities defined",
                     "check": "privacy_roles_defined"},
                    {"id": "GV.PO-P4", "desc": "Governance and risk management reviewed",
                     "check": "governance_reviewed"},
                    {"id": "GV.PO-P5", "desc": "Legal requirements identified",
                     "check": "legal_requirements_identified"},
                    {"id": "GV.PO-P6", "desc": "Governance structure includes privacy",
                     "check": "privacy_in_governance"},
                ],
            },
            "GV.AT-P": {
                "name": "Awareness and Training",
                "subcategories": [
                    {"id": "GV.AT-P1", "desc": "Workforce informed of privacy policies",
                     "check": "privacy_training"},
                    {"id": "GV.AT-P2", "desc": "Senior executives understand privacy risk",
                     "check": "executive_awareness"},
                    {"id": "GV.AT-P3", "desc": "Privacy personnel understand responsibilities",
                     "check": "privacy_team_trained"},
                    {"id": "GV.AT-P4", "desc": "Third parties understand privacy obligations",
                     "check": "third_party_aware"},
                ],
            },
            "GV.MT-P": {
                "name": "Monitoring and Review",
                "subcategories": [
                    {"id": "GV.MT-P1", "desc": "Privacy risk re-assessed on ongoing basis",
                     "check": "ongoing_reassessment"},
                    {"id": "GV.MT-P2", "desc": "Privacy values reflected in practices",
                     "check": "privacy_values_in_practice"},
                    {"id": "GV.MT-P3", "desc": "Policies updated to reflect changes",
                     "check": "policy_update_process"},
                ],
            },
        },
    },
    "CT-P": {
        "name": "Control-P",
        "description": "Develop and implement appropriate activities for data management",
        "categories": {
            "CT.DM-P": {
                "name": "Data Management",
                "subcategories": [
                    {"id": "CT.DM-P1", "desc": "Data elements managed consistent with risk strategy",
                     "check": "data_management_aligned"},
                    {"id": "CT.DM-P2", "desc": "Data retention and disposal policy",
                     "check": "retention_policy"},
                    {"id": "CT.DM-P3", "desc": "Data processing accuracy maintained",
                     "check": "accuracy_measures"},
                    {"id": "CT.DM-P4", "desc": "Data disclosed only as authorized",
                     "check": "disclosure_controls"},
                    {"id": "CT.DM-P5", "desc": "Data from processing manipulations managed",
                     "check": "derived_data_managed"},
                    {"id": "CT.DM-P6", "desc": "Data in transit managed",
                     "check": "transit_controls"},
                    {"id": "CT.DM-P7", "desc": "Mechanisms for transmitting consent preferences",
                     "check": "consent_preference_mechanism"},
                    {"id": "CT.DM-P8", "desc": "Audit/log records for data processing",
                     "check": "processing_audit_log"},
                    {"id": "CT.DM-P9", "desc": "Technical measures for consent management",
                     "check": "consent_management_system"},
                    {"id": "CT.DM-P10", "desc": "Data quality maintained through lifecycle",
                     "check": "data_quality_lifecycle"},
                ],
            },
            "CT.PO-P": {
                "name": "Data Processing Policies",
                "subcategories": [
                    {"id": "CT.PO-P1", "desc": "De-identification policies and processes",
                     "check": "deidentification_policy"},
                    {"id": "CT.PO-P2", "desc": "Data tagging for purpose and provenance",
                     "check": "data_tagging"},
                    {"id": "CT.PO-P3", "desc": "Administrative access safeguards",
                     "check": "admin_access_controls"},
                    {"id": "CT.PO-P4", "desc": "System monitoring for privacy compliance",
                     "check": "privacy_monitoring"},
                ],
            },
        },
    },
    "CM-P": {
        "name": "Communicate-P",
        "description": "Develop and implement communication activities",
        "categories": {
            "CM.AW-P": {
                "name": "Communication Policies",
                "subcategories": [
                    {"id": "CM.AW-P1", "desc": "Privacy practices communicated to individuals",
                     "check": "privacy_notice"},
                    {"id": "CM.AW-P2", "desc": "Mechanisms for individual complaints",
                     "check": "complaint_mechanism"},
                    {"id": "CM.AW-P3", "desc": "System changes communicated",
                     "check": "change_notification"},
                    {"id": "CM.AW-P4", "desc": "Data processing awareness program",
                     "check": "awareness_program"},
                ],
            },
        },
    },
    "PR-P": {
        "name": "Protect-P",
        "description": "Develop and implement safeguards for data processing",
        "categories": {
            "PR.AC-P": {
                "name": "Identity Management, Authentication and Access Control",
                "subcategories": [
                    {"id": "PR.AC-P1", "desc": "Identities and credentials managed",
                     "check": "identity_management"},
                    {"id": "PR.AC-P2", "desc": "Physical access managed",
                     "check": "physical_access_controls"},
                    {"id": "PR.AC-P3", "desc": "Remote access managed",
                     "check": "remote_access_controls"},
                    {"id": "PR.AC-P4", "desc": "Access permissions managed",
                     "check": "access_permissions"},
                    {"id": "PR.AC-P5", "desc": "Network integrity protected",
                     "check": "network_integrity"},
                    {"id": "PR.AC-P6", "desc": "Individuals authenticated",
                     "check": "authentication_controls"},
                ],
            },
            "PR.DS-P": {
                "name": "Data Security",
                "subcategories": [
                    {"id": "PR.DS-P1", "desc": "Data at rest protected",
                     "check": "encryption_at_rest"},
                    {"id": "PR.DS-P2", "desc": "Data in transit protected",
                     "check": "encryption_in_transit"},
                    {"id": "PR.DS-P3", "desc": "Systems and data formally managed",
                     "check": "asset_management"},
                    {"id": "PR.DS-P4", "desc": "Adequate capacity maintained",
                     "check": "capacity_management"},
                    {"id": "PR.DS-P5", "desc": "Protections against data leaks implemented",
                     "check": "dlp_controls"},
                    {"id": "PR.DS-P6", "desc": "Integrity checking mechanisms used",
                     "check": "integrity_checking"},
                    {"id": "PR.DS-P7", "desc": "Development and testing use non-production data",
                     "check": "non_production_data"},
                    {"id": "PR.DS-P8", "desc": "Hardware integrity verified",
                     "check": "hardware_integrity"},
                ],
            },
            "PR.PO-P": {
                "name": "Protective Policies",
                "subcategories": [
                    {"id": "PR.PO-P1", "desc": "Baseline configuration maintained",
                     "check": "baseline_config"},
                    {"id": "PR.PO-P2", "desc": "Configuration change control in place",
                     "check": "change_control"},
                    {"id": "PR.PO-P3", "desc": "Backups maintained and tested",
                     "check": "backup_tested"},
                    {"id": "PR.PO-P4", "desc": "Response and recovery plans tested",
                     "check": "incident_response_tested"},
                    {"id": "PR.PO-P5", "desc": "Improvements implemented from testing",
                     "check": "continuous_improvement"},
                    {"id": "PR.PO-P6", "desc": "Data disposal performed",
                     "check": "data_disposal"},
                    {"id": "PR.PO-P7", "desc": "Protection processes improved",
                     "check": "protection_improvement"},
                    {"id": "PR.PO-P8", "desc": "Protection technology shared",
                     "check": "protection_shared"},
                    {"id": "PR.PO-P9", "desc": "Response plans managed",
                     "check": "response_plans"},
                    {"id": "PR.PO-P10", "desc": "Protection updated with testing results",
                     "check": "protection_updated"},
                ],
            },
        },
    },
}

# Risk assessment rules
PRIVACY_RISK_RULES = [
    {
        "id": "RISK-001",
        "category": "Data Minimization",
        "description": "Excessive data collection beyond stated processing purpose",
        "check": lambda a: len(a.get("data_categories", [])) > 5 and not a.get("data_minimization_justified"),
        "likelihood_base": 4,
        "impact_base": 3,
        "mitigation": "Conduct data minimization review; remove data elements not required for stated purpose; document justification for each element collected",
    },
    {
        "id": "RISK-002",
        "category": "Purpose Limitation",
        "description": "Processing purpose not clearly specified or data used beyond original purpose",
        "check": lambda a: not a.get("purpose_specified") or a.get("secondary_purposes"),
        "likelihood_base": 3,
        "impact_base": 4,
        "mitigation": "Document explicit processing purposes; obtain separate legal basis for any secondary use; implement purpose limitation controls in data pipeline",
    },
    {
        "id": "RISK-003",
        "category": "Cross-Border Transfer",
        "description": "Personal data transferred to jurisdiction without adequate protection",
        "check": lambda a: a.get("cross_border_transfer") and any(
            d not in GDPR_ADEQUATE_COUNTRIES for d in a.get("transfer_destinations", [])),
        "likelihood_base": 3,
        "impact_base": 5,
        "mitigation": "Implement Standard Contractual Clauses (SCCs) or Binding Corporate Rules (BCRs); conduct Transfer Impact Assessment; consider data localization",
    },
    {
        "id": "RISK-004",
        "category": "Automated Decision Making",
        "description": "Automated profiling or decision-making without human oversight or appeal",
        "check": lambda a: a.get("automated_decision_making") and not a.get("human_oversight"),
        "likelihood_base": 4,
        "impact_base": 5,
        "mitigation": "Implement meaningful human review for significant automated decisions; provide appeal mechanism; document algorithm logic and bias testing results",
    },
    {
        "id": "RISK-005",
        "category": "Data Subject Rights",
        "description": "Insufficient mechanisms to fulfill data subject access, erasure, or portability requests",
        "check": lambda a: not a.get("dsr_mechanism"),
        "likelihood_base": 3,
        "impact_base": 4,
        "mitigation": "Implement automated DSR fulfillment workflows; test access, rectification, erasure, portability, and objection request handling; ensure response within regulatory timeframes",
    },
    {
        "id": "RISK-006",
        "category": "Third-Party Risk",
        "description": "Data processor lacks adequate privacy controls or valid DPA",
        "check": lambda a: a.get("data_processor") and not a.get("data_processing_agreement"),
        "likelihood_base": 3,
        "impact_base": 4,
        "mitigation": "Execute Data Processing Agreement with all processors; conduct processor privacy audits; implement subprocessor approval workflows; require breach notification clauses",
    },
    {
        "id": "RISK-007",
        "category": "Security Controls",
        "description": "Inadequate encryption, access controls, or breach detection capabilities",
        "check": lambda a: not a.get("encryption_at_rest") or not a.get("encryption_in_transit"),
        "likelihood_base": 4,
        "impact_base": 5,
        "mitigation": "Implement AES-256 encryption at rest and TLS 1.3 in transit; enforce MFA and least-privilege access; deploy intrusion detection and breach monitoring",
    },
    {
        "id": "RISK-008",
        "category": "Retention",
        "description": "Data retained beyond necessary period or no retention policy defined",
        "check": lambda a: not a.get("retention_period_days") or a.get("retention_period_days", 0) > 1095,
        "likelihood_base": 3,
        "impact_base": 3,
        "mitigation": "Define and enforce retention schedules per data category; implement automated deletion workflows; conduct periodic retention audits",
    },
    {
        "id": "RISK-009",
        "category": "Consent Management",
        "description": "Consent mechanisms are ambiguous, pre-checked, or lack granularity",
        "check": lambda a: a.get("legal_basis") == "consent" and not a.get("consent_mechanism"),
        "likelihood_base": 4,
        "impact_base": 4,
        "mitigation": "Implement granular consent management with clear opt-in; record consent evidence with timestamp and scope; provide easy withdrawal mechanism; avoid dark patterns",
    },
    {
        "id": "RISK-010",
        "category": "Breach Notification",
        "description": "No documented breach response plan or inability to notify within 72 hours",
        "check": lambda a: not a.get("breach_notification_plan"),
        "likelihood_base": 3,
        "impact_base": 5,
        "mitigation": "Document and test incident response procedures; implement automated breach detection; establish 72-hour notification workflow for supervisory authority and affected individuals",
    },
    {
        "id": "RISK-011",
        "category": "Special Category Data",
        "description": "Processing of special category data without explicit consent or Art. 9 exemption",
        "check": lambda a: any(
            DATA_SENSITIVITY.get(cat, {}).get("sensitivity") == "special_category"
            for cat in a.get("data_categories", [])
        ) and a.get("legal_basis") != "explicit_consent" and not a.get("art9_exemption"),
        "likelihood_base": 3,
        "impact_base": 5,
        "mitigation": "Obtain explicit consent for special category data; document Article 9 exemption basis; implement additional safeguards including encryption and access logging",
    },
    {
        "id": "RISK-012",
        "category": "Transparency",
        "description": "Privacy notice is incomplete, inaccessible, or not provided at point of collection",
        "check": lambda a: not a.get("privacy_notice"),
        "likelihood_base": 3,
        "impact_base": 3,
        "mitigation": "Provide clear layered privacy notice at point of collection; include all GDPR Art. 13/14 required information; make notice accessible in plain language",
    },
    {
        "id": "RISK-013",
        "category": "Vulnerable Data Subjects",
        "description": "Processing data of children, elderly, or other vulnerable individuals without additional safeguards",
        "check": lambda a: any(s in a.get("data_subjects", []) for s in [
            "children", "minors", "patients", "elderly", "disabled", "employees"]),
        "likelihood_base": 3,
        "impact_base": 4,
        "mitigation": "Implement age verification for children's data; apply heightened protections; conduct specific impact assessment for vulnerable populations; ensure guardian consent where required",
    },
    {
        "id": "RISK-014",
        "category": "Data Quality",
        "description": "No mechanisms to ensure accuracy, completeness, and currency of personal data",
        "check": lambda a: not a.get("accuracy_measures"),
        "likelihood_base": 2,
        "impact_base": 3,
        "mitigation": "Implement data validation at collection; provide self-service data correction; establish periodic data quality reviews; document accuracy requirements per data element",
    },
]


def _risk_severity(score):
    """Map a numeric risk score (1-25) to a severity label."""
    if score >= 20:
        return "CRITICAL"
    if score >= 15:
        return "HIGH"
    if score >= 10:
        return "MEDIUM"
    if score >= 5:
        return "LOW"
    return "INFORMATIONAL"


class PrivacyImpactAssessmentEngine:
    """Engine for conducting automated Privacy Impact Assessments."""

    def __init__(self, organization_name="", dpo_email=""):
        self.organization_name = organization_name
        self.dpo_email = dpo_email
        self.activities = {}
        self.flow_maps = {}
        self.risk_reports = {}
        self.gdpr_reports = {}
        self.ccpa_reports = {}

    # ------------------------------------------------------------------
    # Processing activity registration
    # ------------------------------------------------------------------
    def register_processing_activity(self, name, description="",
                                     data_controller="", data_processor="",
                                     data_categories=None, data_subjects=None,
                                     legal_basis="", retention_period_days=None,
                                     cross_border_transfer=False,
                                     transfer_destinations=None,
                                     automated_decision_making=False,
                                     **kwargs):
        """Register a processing activity for assessment."""
        activity_id = f"PA-{uuid.uuid4().hex[:8].upper()}"
        activity = {
            "activity_id": activity_id,
            "name": name,
            "description": description,
            "data_controller": data_controller,
            "data_processor": data_processor,
            "data_categories": data_categories or [],
            "data_subjects": data_subjects or [],
            "legal_basis": legal_basis,
            "retention_period_days": retention_period_days,
            "cross_border_transfer": cross_border_transfer,
            "transfer_destinations": transfer_destinations or [],
            "automated_decision_making": automated_decision_making,
            "registered_at": datetime.utcnow().isoformat(),
            "ropa_entry": True,
            "purpose_specified": bool(description),
            "processing_description": description,
        }
        activity.update(kwargs)

        # Calculate data sensitivity profile
        max_sensitivity = "low"
        total_weight = 0
        for cat in activity["data_categories"]:
            info = DATA_SENSITIVITY.get(cat, {"sensitivity": "unknown", "weight": 2})
            total_weight += info["weight"]
            if info["sensitivity"] == "special_category":
                max_sensitivity = "special_category"
            elif info["sensitivity"] == "high" and max_sensitivity not in ("special_category",):
                max_sensitivity = "high"
            elif info["sensitivity"] == "medium" and max_sensitivity in ("low",):
                max_sensitivity = "medium"

        activity["_sensitivity_profile"] = {
            "max_sensitivity": max_sensitivity,
            "total_weight": total_weight,
            "category_count": len(activity["data_categories"]),
        }

        self.activities[activity_id] = activity
        return activity

    # ------------------------------------------------------------------
    # Data flow mapping
    # ------------------------------------------------------------------
    def map_data_flows(self, activity_id, flows):
        """Map data flows for a processing activity."""
        if activity_id not in self.activities:
            raise ValueError(f"Activity {activity_id} not found")

        flow_map = {
            "activity_id": activity_id,
            "activity_name": self.activities[activity_id]["name"],
            "mapped_at": datetime.utcnow().isoformat(),
            "flows": [],
            "flow_summary": {
                "total_stages": 0,
                "has_cross_border": False,
                "encryption_gaps": [],
                "third_parties": [],
            },
        }

        for i, flow in enumerate(flows):
            flow_entry = {
                "flow_id": f"FL-{i+1:03d}",
                "stage": flow.get("stage", "unknown"),
                "source": flow.get("source", ""),
                "destination": flow.get("destination", ""),
                "data_elements": flow.get("data_elements", []),
                "encryption_in_transit": flow.get("encryption_in_transit", False),
                "encryption_at_rest": flow.get("encryption_at_rest", False),
                "protocol": flow.get("protocol", ""),
                "cross_border": flow.get("cross_border", False),
                "data_processing_agreement": flow.get("data_processing_agreement", False),
                "retention_days": flow.get("retention_days"),
                "access_controls": flow.get("access_controls", ""),
                "method": flow.get("method", ""),
                "verification": flow.get("verification", ""),
            }
            flow_map["flows"].append(flow_entry)
            flow_map["flow_summary"]["total_stages"] += 1

            if flow_entry["cross_border"]:
                flow_map["flow_summary"]["has_cross_border"] = True

            if flow_entry["stage"] in ("processing", "storage", "sharing"):
                if not flow_entry["encryption_in_transit"] and flow_entry["stage"] != "storage":
                    flow_map["flow_summary"]["encryption_gaps"].append({
                        "flow_id": flow_entry["flow_id"],
                        "gap": "No encryption in transit",
                        "stage": flow_entry["stage"],
                    })
                if not flow_entry["encryption_at_rest"] and flow_entry["stage"] == "storage":
                    flow_map["flow_summary"]["encryption_gaps"].append({
                        "flow_id": flow_entry["flow_id"],
                        "gap": "No encryption at rest",
                        "stage": flow_entry["stage"],
                    })

        self.flow_maps[activity_id] = flow_map

        # Update activity with flow-derived flags
        activity = self.activities[activity_id]
        activity["data_flow_mapped"] = True
        activity["data_elements_mapped"] = True
        if flow_map["flow_summary"]["has_cross_border"]:
            activity["cross_border_transfer"] = True
        if not flow_map["flow_summary"]["encryption_gaps"]:
            activity["encryption_in_transit"] = True
            activity["encryption_at_rest"] = True

        return flow_map

    def render_data_flow_diagram(self, flow_map):
        """Render an ASCII data flow diagram to stdout."""
        print(f"\n{'='*70}")
        print(f"DATA FLOW DIAGRAM: {flow_map['activity_name']}")
        print(f"{'='*70}")

        for flow in flow_map["flows"]:
            stage_label = flow["stage"].upper()
            enc_icon = "[ENC]" if flow["encryption_in_transit"] else "[!!!]"
            border_icon = "[XBORDER]" if flow["cross_border"] else ""
            elements = ", ".join(flow["data_elements"][:3])
            if len(flow["data_elements"]) > 3:
                elements += f" (+{len(flow['data_elements'])-3} more)"

            print(f"\n  [{stage_label}] {flow['source']}")
            print("    |")
            print(f"    | {enc_icon} {border_icon} ({elements})")
            print("    v")
            print(f"  [{stage_label}] {flow['destination']}")

        if flow_map["flow_summary"]["encryption_gaps"]:
            print(f"\n  WARNING: {len(flow_map['flow_summary']['encryption_gaps'])} encryption gap(s) detected")
            for gap in flow_map["flow_summary"]["encryption_gaps"]:
                print(f"    - {gap['flow_id']}: {gap['gap']} at {gap['stage']} stage")

        print(f"\n{'='*70}\n")

    # ------------------------------------------------------------------
    # Risk assessment
    # ------------------------------------------------------------------
    def assess_privacy_risks(self, activity_id, assessment_type="full_dpia"):
        """Assess privacy risks for a processing activity."""
        if activity_id not in self.activities:
            raise ValueError(f"Activity {activity_id} not found")

        activity = self.activities[activity_id]
        sensitivity = activity.get("_sensitivity_profile", {})

        risks = []
        for rule in PRIVACY_RISK_RULES:
            try:
                triggered = rule["check"](activity)
            except Exception:
                triggered = False

            if triggered:
                # Adjust scores based on data sensitivity
                likelihood_adj = 0
                impact_adj = 0
                if sensitivity.get("max_sensitivity") == "special_category":
                    impact_adj = 1
                elif sensitivity.get("max_sensitivity") == "high":
                    impact_adj = 0.5
                if sensitivity.get("category_count", 0) > 8:
                    likelihood_adj = 1

                likelihood = min(5, rule["likelihood_base"] + likelihood_adj)
                impact = min(5, rule["impact_base"] + impact_adj)
                risk_score = round(likelihood * impact, 1)

                risks.append({
                    "risk_id": rule["id"],
                    "category": rule["category"],
                    "description": rule["description"],
                    "likelihood": likelihood,
                    "impact": impact,
                    "risk_score": risk_score,
                    "severity": _risk_severity(risk_score),
                    "recommended_mitigation": rule["mitigation"],
                })

        # Sort by risk score descending
        risks.sort(key=lambda r: r["risk_score"], reverse=True)

        # Calculate summary
        severity_counts = {}
        for r in risks:
            severity_counts[r["severity"]] = severity_counts.get(r["severity"], 0) + 1

        overall = "LOW"
        if severity_counts.get("CRITICAL", 0) > 0:
            overall = "CRITICAL"
        elif severity_counts.get("HIGH", 0) > 0:
            overall = "HIGH"
        elif severity_counts.get("MEDIUM", 0) > 0:
            overall = "MEDIUM"

        report = {
            "activity_id": activity_id,
            "activity_name": activity["name"],
            "assessment_type": assessment_type,
            "assessed_at": datetime.utcnow().isoformat(),
            "overall_risk_level": overall,
            "total_risks": len(risks),
            "risk_count_by_severity": severity_counts,
            "risks": risks,
            "data_sensitivity_profile": sensitivity,
        }

        self.risk_reports[activity_id] = report
        activity["risk_assessment_completed"] = True
        activity["risks_prioritized"] = True
        activity["risk_responses_identified"] = True

        return report

    # ------------------------------------------------------------------
    # ICO DPIA screening checklist
    # ------------------------------------------------------------------
    def run_screening_checklist(self, uses_special_category_data=False,
                                large_scale_processing=False,
                                systematic_monitoring=False,
                                automated_decision_making=False,
                                cross_border_transfer=False,
                                vulnerable_data_subjects=False,
                                innovative_technology=False,
                                denial_of_service_or_rights=False,
                                evaluation_or_scoring=False,
                                matching_or_combining_datasets=False):
        """Run ICO DPIA screening checklist to determine if full DPIA is required.

        A DPIA is required if at least two criteria are met, or if any single
        high-impact criterion is triggered.
        """
        criteria = {
            "special_category_data": uses_special_category_data,
            "large_scale_processing": large_scale_processing,
            "systematic_monitoring": systematic_monitoring,
            "automated_decision_making": automated_decision_making,
            "cross_border_transfer": cross_border_transfer,
            "vulnerable_data_subjects": vulnerable_data_subjects,
            "innovative_technology": innovative_technology,
            "denial_of_service_or_rights": denial_of_service_or_rights,
            "evaluation_or_scoring": evaluation_or_scoring,
            "matching_or_combining_datasets": matching_or_combining_datasets,
        }

        triggers = [name for name, value in criteria.items() if value]
        high_impact_single = {"special_category_data", "large_scale_processing",
                              "denial_of_service_or_rights"}
        dpia_required = (len(triggers) >= 2 or
                         bool(set(triggers) & high_impact_single))

        return {
            "dpia_required": dpia_required,
            "triggers": triggers,
            "trigger_count": len(triggers),
            "criteria_evaluated": len(criteria),
            "recommendation": (
                "Full DPIA must be conducted before processing begins"
                if dpia_required
                else "Full DPIA not mandatory but recommended as good practice"
            ),
            "ico_reference": "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/accountability-and-governance/data-protection-impact-assessments-dpias/",
        }

    # ------------------------------------------------------------------
    # GDPR compliance check
    # ------------------------------------------------------------------
    def check_gdpr_compliance(self, activity_id):
        """Run GDPR article-level compliance checks against a processing activity."""
        if activity_id not in self.activities:
            raise ValueError(f"Activity {activity_id} not found")

        activity = self.activities[activity_id]
        findings = []
        total_checks = 0
        passed = 0

        for article_num, article_def in GDPR_DPIA_ARTICLES.items():
            for check in article_def["checks"]:
                total_checks += 1
                check_id = check["id"]
                desc = check["desc"]

                # Determine if check is applicable
                applicable = True
                if "condition_field" in check:
                    cond_field = check["condition_field"]
                    cond_value = check["condition_value"]
                    actual = activity.get(cond_field)
                    if cond_value == "_nonempty":
                        applicable = bool(actual)
                    else:
                        applicable = actual == cond_value

                if not applicable:
                    findings.append({
                        "article": check_id,
                        "description": desc,
                        "status": "NOT_APPLICABLE",
                        "details": f"Condition not met: {check.get('condition_field', '')}",
                    })
                    passed += 1
                    continue

                # Check field value
                field = check.get("field", "")
                value = activity.get(field)

                if "valid_values" in check:
                    if value in check["valid_values"]:
                        status = "COMPLIANT"
                        passed += 1
                    else:
                        status = "NON_COMPLIANT"
                elif check.get("required"):
                    if value:
                        status = "COMPLIANT"
                        passed += 1
                    else:
                        status = "NON_COMPLIANT"
                else:
                    if value:
                        status = "COMPLIANT"
                        passed += 1
                    else:
                        status = "NON_COMPLIANT"

                findings.append({
                    "article": check_id,
                    "description": desc,
                    "status": status,
                    "field": field,
                    "value_present": bool(value),
                })

        score = round((passed / total_checks) * 100, 1) if total_checks else 0

        report = {
            "activity_id": activity_id,
            "regulation": "GDPR",
            "checked_at": datetime.utcnow().isoformat(),
            "compliance_score": score,
            "total_checks": total_checks,
            "passed": passed,
            "failed": total_checks - passed,
            "findings": findings,
        }

        self.gdpr_reports[activity_id] = report
        return report

    # ------------------------------------------------------------------
    # CCPA/CPRA compliance check
    # ------------------------------------------------------------------
    def check_ccpa_compliance(self, activity_id):
        """Run CCPA/CPRA section-level compliance checks."""
        if activity_id not in self.activities:
            raise ValueError(f"Activity {activity_id} not found")

        activity = self.activities[activity_id]

        # Derive helper flags
        has_sensitive = any(
            DATA_SENSITIVITY.get(cat, {}).get("sensitivity") in ("special_category", "high")
            for cat in activity.get("data_categories", [])
        )
        activity["_has_sensitive_data"] = has_sensitive

        findings = []
        total_checks = 0
        passed = 0

        for section_num, section_def in CCPA_SECTIONS.items():
            for check in section_def["checks"]:
                total_checks += 1
                check_id = check["id"]
                desc = check["desc"]

                # Applicability
                applicable = True
                if "condition_field" in check:
                    cond_field = check["condition_field"]
                    cond_value = check["condition_value"]
                    actual = activity.get(cond_field)
                    applicable = actual == cond_value

                if not applicable:
                    findings.append({
                        "section": check_id,
                        "description": desc,
                        "status": "NOT_APPLICABLE",
                    })
                    passed += 1
                    continue

                field = check.get("field", "")
                value = activity.get(field)

                if "max_value" in check:
                    if value and isinstance(value, (int, float)) and value <= check["max_value"]:
                        status = "COMPLIANT"
                        passed += 1
                    elif not value:
                        status = "NON_COMPLIANT"
                    else:
                        status = "NON_COMPLIANT"
                elif check.get("required"):
                    if value:
                        status = "COMPLIANT"
                        passed += 1
                    else:
                        status = "NON_COMPLIANT"
                else:
                    if value:
                        status = "COMPLIANT"
                        passed += 1
                    else:
                        status = "NON_COMPLIANT"

                findings.append({
                    "section": check_id,
                    "description": desc,
                    "status": status,
                    "field": field,
                    "value_present": bool(value),
                })

        score = round((passed / total_checks) * 100, 1) if total_checks else 0

        report = {
            "activity_id": activity_id,
            "regulation": "CCPA/CPRA",
            "checked_at": datetime.utcnow().isoformat(),
            "compliance_score": score,
            "total_checks": total_checks,
            "passed": passed,
            "failed": total_checks - passed,
            "findings": findings,
        }

        self.ccpa_reports[activity_id] = report
        return report

    # ------------------------------------------------------------------
    # NIST Privacy Framework profile
    # ------------------------------------------------------------------
    def generate_nist_privacy_profile(self, activity_id, target_tier="tier_2"):
        """Generate NIST Privacy Framework profile for an activity."""
        if activity_id not in self.activities:
            raise ValueError(f"Activity {activity_id} not found")

        activity = self.activities[activity_id]
        profile = {
            "activity_id": activity_id,
            "target_tier": target_tier,
            "generated_at": datetime.utcnow().isoformat(),
            "functions": {},
        }

        total_subcats = 0
        implemented = 0

        for func_id, func_def in NIST_PRIVACY_FUNCTIONS.items():
            func_outcomes = []
            for cat_id, cat_def in func_def["categories"].items():
                for subcat in cat_def["subcategories"]:
                    total_subcats += 1
                    check_field = subcat["check"]
                    is_implemented = bool(activity.get(check_field))
                    if is_implemented:
                        implemented += 1

                    func_outcomes.append({
                        "subcategory": subcat["id"],
                        "description": subcat["desc"],
                        "category": cat_def["name"],
                        "implemented": is_implemented,
                        "check_field": check_field,
                    })

            profile["functions"][func_id] = func_outcomes

        profile["coverage"] = {
            "total_subcategories": total_subcats,
            "implemented": implemented,
            "gaps": total_subcats - implemented,
            "coverage_percentage": round((implemented / total_subcats) * 100, 1) if total_subcats else 0,
        }

        return profile

    # ------------------------------------------------------------------
    # Remediation plan
    # ------------------------------------------------------------------
    def generate_remediation_plan(self, activity_id, risk_report=None,
                                   gdpr_report=None, ccpa_report=None):
        """Generate a prioritized remediation plan from assessment results."""
        action_items = []
        now = datetime.utcnow()

        # From risk report
        if risk_report:
            for risk in risk_report.get("risks", []):
                priority_map = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4"}
                deadline_days = {"CRITICAL": 14, "HIGH": 30, "MEDIUM": 60, "LOW": 90}
                sev = risk["severity"]
                action_items.append({
                    "source": "risk_assessment",
                    "priority": priority_map.get(sev, "P4"),
                    "action": risk["recommended_mitigation"],
                    "addresses_risks": [risk["risk_id"]],
                    "risk_category": risk["category"],
                    "risk_score": risk["risk_score"],
                    "owner": "Privacy Team",
                    "deadline": (now + timedelta(days=deadline_days.get(sev, 90))).strftime("%Y-%m-%d"),
                    "status": "open",
                })

        # From GDPR findings
        if gdpr_report:
            for finding in gdpr_report.get("findings", []):
                if finding["status"] == "NON_COMPLIANT":
                    action_items.append({
                        "source": "gdpr_compliance",
                        "priority": "P2",
                        "action": f"Address GDPR Art. {finding['article']} non-compliance: {finding['description']}",
                        "addresses_risks": [f"GDPR-{finding['article']}"],
                        "risk_category": "Regulatory Compliance",
                        "owner": "DPO / Legal",
                        "deadline": (now + timedelta(days=30)).strftime("%Y-%m-%d"),
                        "status": "open",
                    })

        # From CCPA findings
        if ccpa_report:
            for finding in ccpa_report.get("findings", []):
                if finding["status"] == "NON_COMPLIANT":
                    action_items.append({
                        "source": "ccpa_compliance",
                        "priority": "P2",
                        "action": f"Address CCPA Sec. {finding['section']} non-compliance: {finding['description']}",
                        "addresses_risks": [f"CCPA-{finding['section']}"],
                        "risk_category": "Regulatory Compliance",
                        "owner": "Privacy Team / Legal",
                        "deadline": (now + timedelta(days=30)).strftime("%Y-%m-%d"),
                        "status": "open",
                    })

        # Sort by priority
        priority_order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
        action_items.sort(key=lambda x: priority_order.get(x["priority"], 9))

        return {
            "activity_id": activity_id,
            "generated_at": now.isoformat(),
            "total_actions": len(action_items),
            "by_priority": {
                p: sum(1 for a in action_items if a["priority"] == p)
                for p in ["P1", "P2", "P3", "P4"]
            },
            "action_items": action_items,
        }

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------
    def generate_dpia_report(self, activity_id, output_path="dpia_report.json",
                              format="json"):
        """Generate the formal DPIA report document."""
        if activity_id not in self.activities:
            raise ValueError(f"Activity {activity_id} not found")

        activity = self.activities[activity_id]
        report = {
            "report_type": "Data Protection Impact Assessment (DPIA)",
            "report_id": f"DPIA-{uuid.uuid4().hex[:8].upper()}",
            "generated_at": datetime.utcnow().isoformat(),
            "organization": self.organization_name,
            "dpo_contact": self.dpo_email,
            "processing_activity": {
                k: v for k, v in activity.items() if not k.startswith("_")
            },
            "data_flow_map": self.flow_maps.get(activity_id),
            "risk_assessment": self.risk_reports.get(activity_id),
            "gdpr_compliance": self.gdpr_reports.get(activity_id),
            "ccpa_compliance": self.ccpa_reports.get(activity_id),
            "dpo_sign_off": {
                "status": "pending",
                "dpo_name": "",
                "date": "",
                "comments": "",
            },
            "review_schedule": {
                "next_review": (datetime.utcnow() + timedelta(days=365)).strftime("%Y-%m-%d"),
                "review_frequency": "annual",
                "triggers_for_early_review": [
                    "Change in processing purpose",
                    "New data categories collected",
                    "Change in processor or subprocessor",
                    "Security incident or breach",
                    "Regulatory change",
                    "Complaints from data subjects",
                ],
            },
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        return report


def main():
    parser = argparse.ArgumentParser(
        description="Privacy Impact Assessment (PIA/DPIA) Automation Agent"
    )
    parser.add_argument("--org", default="", help="Organization name")
    parser.add_argument("--dpo-email", default="", help="DPO email address")
    parser.add_argument("--output", default="pia_report.json", help="Output report path")
    parser.add_argument("--action", choices=[
        "screening", "full_assessment", "gdpr_check", "ccpa_check",
        "nist_profile", "demo",
    ], default="demo", help="Action to perform")
    args = parser.parse_args()

    engine = PrivacyImpactAssessmentEngine(
        organization_name=args.org,
        dpo_email=args.dpo_email,
    )

    if args.action == "screening":
        result = engine.run_screening_checklist(
            large_scale_processing=True,
            systematic_monitoring=True,
            automated_decision_making=True,
        )
        print(f"[+] DPIA Required: {result['dpia_required']}")
        print(f"    Triggers: {result['triggers']}")

    elif args.action == "demo":
        print("[*] Running demonstration PIA workflow...\n")

        # Register activity
        activity = engine.register_processing_activity(
            name="Customer Analytics Platform",
            description="Collects browsing behavior and purchase history for personalization",
            data_controller="Demo Corp",
            data_processor="CloudAnalytics Inc",
            data_categories=["browsing_history", "purchase_records", "ip_address",
                             "device_id", "email", "name"],
            data_subjects=["customers", "website_visitors"],
            legal_basis="consent",
            retention_period_days=730,
            cross_border_transfer=True,
            transfer_destinations=["US", "IN"],
            automated_decision_making=True,
        )
        print(f"[+] Registered activity: {activity['activity_id']}")

        # Map data flows
        flow_map = engine.map_data_flows(
            activity_id=activity["activity_id"],
            flows=[
                {"stage": "collection", "source": "Web browser",
                 "destination": "CDN edge", "data_elements": ["ip_address", "device_id"],
                 "encryption_in_transit": True, "protocol": "TLS 1.3"},
                {"stage": "processing", "source": "CDN edge",
                 "destination": "Data warehouse (US)", "data_elements": ["browsing_history", "purchase_records"],
                 "encryption_in_transit": True, "encryption_at_rest": True, "protocol": "mTLS"},
                {"stage": "sharing", "source": "Data warehouse",
                 "destination": "ML Provider (IN)", "data_elements": ["browsing_history"],
                 "encryption_in_transit": True, "cross_border": True,
                 "data_processing_agreement": True},
                {"stage": "deletion", "source": "All stores",
                 "destination": "Secure erasure", "method": "Cryptographic erasure"},
            ],
        )
        engine.render_data_flow_diagram(flow_map)

        # Risk assessment
        risk_report = engine.assess_privacy_risks(activity_id=activity["activity_id"])
        print(f"[+] Risk Assessment: {risk_report['overall_risk_level']}")
        print(f"    Total Risks: {risk_report['total_risks']}")
        for risk in risk_report["risks"][:5]:
            print(f"    [{risk['severity']}] {risk['category']}: Score {risk['risk_score']}/25")

        # GDPR check
        gdpr = engine.check_gdpr_compliance(activity_id=activity["activity_id"])
        print(f"\n[+] GDPR Compliance Score: {gdpr['compliance_score']}/100")
        for f in gdpr["findings"]:
            if f["status"] == "NON_COMPLIANT":
                print(f"    [FAIL] Art.{f['article']}: {f['description']}")

        # CCPA check
        ccpa = engine.check_ccpa_compliance(activity_id=activity["activity_id"])
        print(f"\n[+] CCPA Compliance Score: {ccpa['compliance_score']}/100")
        for f in ccpa["findings"]:
            if f["status"] == "NON_COMPLIANT":
                print(f"    [FAIL] Sec.{f['section']}: {f['description']}")

        # Remediation
        remediation = engine.generate_remediation_plan(
            activity_id=activity["activity_id"],
            risk_report=risk_report,
            gdpr_report=gdpr,
            ccpa_report=ccpa,
        )
        print(f"\n[+] Remediation Plan: {remediation['total_actions']} action items")
        print(f"    By Priority: {remediation['by_priority']}")

        # Generate report
        engine.generate_dpia_report(
            activity_id=activity["activity_id"],
            output_path=args.output,
        )
        print(f"\n[+] DPIA report saved to {args.output}")

    else:
        print(f"[!] Action '{args.action}' requires an activity to be registered first.")
        print("    Use --action demo for a full demonstration workflow.")


if __name__ == "__main__":
    main()
