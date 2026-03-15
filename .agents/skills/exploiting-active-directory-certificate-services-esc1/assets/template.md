# AD CS ESC1 Assessment Template

## Engagement Details

| Field | Value |
|-------|-------|
| Assessment Date | |
| Target Domain | |
| CA Server(s) | |
| Assessor | |

## Certificate Authority Information

| CA Name | Server | Type | OS Version |
|---------|--------|------|------------|
| | | Enterprise / Standalone | |

## Vulnerable Templates Identified

| Template Name | ENROLLEE_SUPPLIES_SUBJECT | Auth EKU | Low-Priv Enroll | No Approval | ESC1 |
|--------------|--------------------------|----------|-----------------|-------------|------|
| | Yes/No | Yes/No | Yes/No | Yes/No | Yes/No |

## Exploitation Evidence

| Step | Action | Result | Screenshot |
|------|--------|--------|------------|
| 1 | CA Enumeration | | |
| 2 | Template Discovery | | |
| 3 | Certificate Request with SAN | | |
| 4 | PKINIT Authentication | | |
| 5 | Privilege Validation | | |

## Remediation Recommendations

| # | Recommendation | Priority | Status |
|---|---------------|----------|--------|
| 1 | Disable Supply in Request on vulnerable templates | Critical | |
| 2 | Enable manager approval for certificate requests | High | |
| 3 | Restrict template enrollment to specific groups | High | |
| 4 | Enable CA audit logging | Medium | |
| 5 | Deploy certificate monitoring | Medium | |
