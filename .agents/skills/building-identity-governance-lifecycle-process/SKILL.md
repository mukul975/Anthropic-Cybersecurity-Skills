---
name: building-identity-governance-lifecycle-process
description: >
  Builds comprehensive identity governance and lifecycle management processes including
  joiner-mover-leaver automation, role mining, access request workflows, periodic
  recertification, and orphaned account remediation using IGA platforms.
  Activates for requests involving identity lifecycle management, JML processes,
  role-based access provisioning, or identity governance program design.
domain: cybersecurity
subdomain: identity-access-management
tags: [identity-governance, lifecycle-management, JML, access-provisioning, RBAC, IGA]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Building Identity Governance Lifecycle Process

## When to Use

- Organization lacks automated joiner-mover-leaver (JML) processes for identity management
- Access provisioning is manual and takes days, creating productivity loss and security gaps
- Former employees retain access to systems after termination (orphaned accounts)
- Role explosion has created thousands of roles with unclear ownership and overlapping entitlements
- Compliance requirements mandate documented identity lifecycle processes (SOX, HIPAA, GDPR)
- No centralized visibility into who has access to what across the enterprise

**Do not use** for single-application user management; identity governance addresses cross-system lifecycle management requiring correlation of authoritative HR sources with downstream application provisioning.

## Prerequisites

- Authoritative HR system (Workday, SAP SuccessFactors, BambooHR) as identity source of truth
- IGA platform (SailPoint, Saviynt, One Identity) or Microsoft Entra ID Governance
- Active Directory and/or Azure AD as primary directory services
- Application connectors for target systems requiring automated provisioning
- Defined organizational role structure and reporting hierarchy
- Stakeholder buy-in from HR, IT, security, and business unit managers

## Workflow

### Step 1: Define Identity Lifecycle States and Transitions

Map the identity lifecycle from hire to termination:

```python
"""
Identity Lifecycle State Machine
Defines all identity states and valid transitions with automated actions.
"""

IDENTITY_LIFECYCLE = {
    "states": {
        "PRE_HIRE": {
            "description": "Identity created from HR feed before start date",
            "automated_actions": [
                "Create identity record in IGA platform",
                "Generate unique employee ID",
                "Create mailbox reservation",
                "Assign birthright roles based on job code",
                "Initiate background check workflow"
            ],
            "valid_transitions": ["ACTIVE", "CANCELLED"]
        },
        "ACTIVE": {
            "description": "Employee has started, full access provisioned",
            "automated_actions": [
                "Create Active Directory account",
                "Create email mailbox",
                "Provision birthright application access",
                "Assign department-specific roles",
                "Add to distribution groups",
                "Issue MFA token/security key",
                "Create VPN account if remote worker"
            ],
            "valid_transitions": ["ROLE_CHANGE", "LEAVE_OF_ABSENCE", "TERMINATED"]
        },
        "ROLE_CHANGE": {
            "description": "Employee transferred, promoted, or changed departments",
            "automated_actions": [
                "Recalculate role assignments based on new job code",
                "Remove access from previous department applications",
                "Provision access for new department applications",
                "Update group memberships",
                "Transfer manager in directory",
                "Trigger access review for retained entitlements",
                "Notify new manager of inherited access"
            ],
            "valid_transitions": ["ACTIVE", "LEAVE_OF_ABSENCE", "TERMINATED"]
        },
        "LEAVE_OF_ABSENCE": {
            "description": "Employee on extended leave (medical, parental, sabbatical)",
            "automated_actions": [
                "Disable interactive login (preserve account)",
                "Suspend VPN access",
                "Set out-of-office auto-reply",
                "Delegate mailbox to manager",
                "Preserve all role assignments for return",
                "Set reactivation date from HR feed"
            ],
            "valid_transitions": ["ACTIVE", "TERMINATED"]
        },
        "TERMINATED": {
            "description": "Employee has left the organization",
            "automated_actions": [
                "Disable AD account immediately",
                "Revoke all application access",
                "Revoke VPN and remote access",
                "Convert mailbox to shared (manager access for 90 days)",
                "Transfer OneDrive files to manager",
                "Remove from all security and distribution groups",
                "Revoke OAuth tokens and API keys",
                "Wipe corporate data from mobile devices",
                "Archive identity record",
                "Schedule account deletion after retention period"
            ],
            "valid_transitions": ["REHIRE", "DELETED"]
        },
        "REHIRE": {
            "description": "Previously terminated employee returning",
            "automated_actions": [
                "Reactivate existing identity record",
                "Reset credentials and require MFA re-enrollment",
                "Provision based on new job code (not previous access)",
                "Flag for enhanced access review in first 30 days"
            ],
            "valid_transitions": ["ACTIVE"]
        },
        "DELETED": {
            "description": "Account permanently removed after retention period",
            "automated_actions": [
                "Delete AD account",
                "Delete email mailbox archive",
                "Remove identity record from IGA",
                "Generate deletion audit log"
            ],
            "valid_transitions": []
        }
    },
    "retention_periods": {
        "terminated_to_deleted": "90 days (default)",
        "mailbox_retention": "90 days as shared mailbox",
        "onedrive_retention": "30 days manager access, then archived",
        "audit_log_retention": "7 years for compliance"
    }
}
```

### Step 2: Implement Authoritative Source Integration

Connect HR system as the single source of truth for identity data:

```python
"""
HR Source Integration - Workday to IGA Platform Connector
Polls Workday for employee lifecycle events and triggers provisioning.
"""
import requests
from datetime import datetime, timedelta
import logging

class WorkdayIdentityConnector:
    def __init__(self, config):
        self.base_url = config["workday_api_url"]
        self.tenant = config["tenant"]
        self.client_id = config["client_id"]
        self.client_secret = config["client_secret"]
        self.session = requests.Session()
        self.logger = logging.getLogger("workday_connector")

    def get_access_token(self):
        """Authenticate to Workday REST API."""
        token_url = f"{self.base_url}/ccx/oauth2/{self.tenant}/token"
        response = self.session.post(token_url, data={
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret
        })
        response.raise_for_status()
        return response.json()["access_token"]

    def fetch_worker_changes(self, since_datetime):
        """Fetch all worker lifecycle events since the last sync."""
        headers = {"Authorization": f"Bearer {self.get_access_token()}"}
        params = {
            "Updated_From": since_datetime.isoformat(),
            "Updated_Through": datetime.utcnow().isoformat(),
            "Count": 100
        }

        workers = []
        url = f"{self.base_url}/ccx/api/v1/{self.tenant}/workers"

        while url:
            response = self.session.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            workers.extend(data.get("data", []))
            url = data.get("next", None)
            params = {}

        return workers

    def map_lifecycle_event(self, worker):
        """Map Workday worker data to identity lifecycle event."""
        worker_data = worker.get("workerData", {})
        employment = worker_data.get("employmentData", {})
        personal = worker_data.get("personalData", {})

        event = {
            "employee_id": worker.get("id"),
            "first_name": personal.get("legalName", {}).get("firstName"),
            "last_name": personal.get("legalName", {}).get("lastName"),
            "email": worker_data.get("emailAddress"),
            "job_code": employment.get("jobProfile", {}).get("id"),
            "job_title": employment.get("jobProfile", {}).get("name"),
            "department": employment.get("organization", {}).get("name"),
            "department_code": employment.get("organization", {}).get("id"),
            "manager_id": employment.get("managerId"),
            "location": employment.get("location", {}).get("name"),
            "cost_center": employment.get("costCenter", {}).get("id"),
            "hire_date": employment.get("hireDate"),
            "termination_date": employment.get("terminationDate"),
            "status": employment.get("status"),
            "worker_type": employment.get("workerType"),
        }

        # Determine lifecycle transition
        if event["status"] == "Active" and event["hire_date"]:
            hire_date = datetime.fromisoformat(event["hire_date"])
            if hire_date > datetime.utcnow():
                event["lifecycle_event"] = "PRE_HIRE"
            else:
                event["lifecycle_event"] = "JOINER"
        elif event["status"] == "Active":
            event["lifecycle_event"] = "MOVER"  # Department or role change
        elif event["status"] == "Terminated":
            event["lifecycle_event"] = "LEAVER"
        elif event["status"] == "On Leave":
            event["lifecycle_event"] = "LEAVE_OF_ABSENCE"

        return event

    def process_lifecycle_events(self, since_datetime):
        """Main processing loop for identity lifecycle events."""
        workers = self.fetch_worker_changes(since_datetime)
        events = []

        for worker in workers:
            event = self.map_lifecycle_event(worker)
            events.append(event)
            self.logger.info(
                f"Lifecycle event: {event['lifecycle_event']} for "
                f"{event['first_name']} {event['last_name']} "
                f"(EmpID: {event['employee_id']})"
            )

        return events
```

### Step 3: Implement Role Mining and Birthright Access

Define roles based on job functions for automated provisioning:

```python
"""
Role Mining Engine
Analyzes existing access patterns to derive role definitions
for birthright (automatic) provisioning.
"""
import pandas as pd
from collections import Counter
from itertools import combinations

class RoleMiningEngine:
    def __init__(self, access_data):
        """
        access_data: DataFrame with columns
        [employee_id, job_code, department, application, entitlement]
        """
        self.access_data = access_data

    def mine_birthright_roles(self, min_assignment_pct=0.8):
        """
        Identify entitlements that should be automatically assigned
        based on job code. If 80%+ of users with same job code
        have an entitlement, it becomes birthright access.
        """
        birthright_roles = {}

        for job_code, group in self.access_data.groupby("job_code"):
            total_users = group["employee_id"].nunique()
            entitlement_counts = group.groupby(
                ["application", "entitlement"]
            )["employee_id"].nunique()

            birthright_entitlements = []
            for (app, ent), count in entitlement_counts.items():
                pct = count / total_users
                if pct >= min_assignment_pct:
                    birthright_entitlements.append({
                        "application": app,
                        "entitlement": ent,
                        "assignment_percentage": round(pct * 100, 1),
                        "user_count": count
                    })

            if birthright_entitlements:
                birthright_roles[job_code] = {
                    "job_code": job_code,
                    "total_users": total_users,
                    "birthright_entitlements": birthright_entitlements
                }

        return birthright_roles

    def detect_role_explosion(self):
        """Identify roles with excessive overlap indicating need for consolidation."""
        roles = self.access_data.groupby("job_code").apply(
            lambda x: set(zip(x["application"], x["entitlement"]))
        )

        overlap_report = []
        for (role1, ents1), (role2, ents2) in combinations(roles.items(), 2):
            if len(ents1) == 0 or len(ents2) == 0:
                continue
            overlap = len(ents1 & ents2)
            max_size = max(len(ents1), len(ents2))
            overlap_pct = overlap / max_size * 100

            if overlap_pct > 70:
                overlap_report.append({
                    "role_1": role1,
                    "role_2": role2,
                    "role_1_entitlements": len(ents1),
                    "role_2_entitlements": len(ents2),
                    "overlapping_entitlements": overlap,
                    "overlap_percentage": round(overlap_pct, 1),
                    "recommendation": "CONSOLIDATE" if overlap_pct > 90 else "REVIEW"
                })

        return sorted(overlap_report, key=lambda x: x["overlap_percentage"], reverse=True)

    def find_orphaned_access(self):
        """
        Find entitlements that no longer align with any role definition.
        These are exceptions that accumulated over time.
        """
        # Get birthright definitions
        birthright = self.mine_birthright_roles(min_assignment_pct=0.5)

        orphaned = []
        for _, row in self.access_data.iterrows():
            job_birthright = birthright.get(row["job_code"], {})
            expected_ents = set()
            for ent in job_birthright.get("birthright_entitlements", []):
                expected_ents.add((ent["application"], ent["entitlement"]))

            current_ent = (row["application"], row["entitlement"])
            if current_ent not in expected_ents:
                orphaned.append({
                    "employee_id": row["employee_id"],
                    "job_code": row["job_code"],
                    "application": row["application"],
                    "entitlement": row["entitlement"],
                    "recommendation": "Review for revocation"
                })

        return pd.DataFrame(orphaned)
```

### Step 4: Build Access Request and Approval Workflow

Implement self-service access request with risk-based approvals:

```python
"""
Access Request Workflow Engine
Handles self-service access requests with multi-level approvals
based on risk classification of requested entitlements.
"""

ACCESS_REQUEST_WORKFLOW = {
    "risk_levels": {
        "LOW": {
            "description": "Standard business applications",
            "examples": ["Email distribution groups", "SharePoint team sites", "Standard SaaS apps"],
            "approval_chain": ["manager"],
            "sla_hours": 4,
            "auto_approve_if_birthright": True
        },
        "MEDIUM": {
            "description": "Sensitive data access or elevated permissions",
            "examples": ["CRM admin", "Financial reporting", "HR systems"],
            "approval_chain": ["manager", "application_owner"],
            "sla_hours": 24,
            "auto_approve_if_birthright": False
        },
        "HIGH": {
            "description": "Privileged access or regulated data",
            "examples": ["Database admin", "Cloud admin", "PAM vault access"],
            "approval_chain": ["manager", "application_owner", "security_team"],
            "sla_hours": 48,
            "auto_approve_if_birthright": False,
            "require_justification": True,
            "require_time_limit": True
        },
        "CRITICAL": {
            "description": "Domain admin, root access, or production data modification",
            "examples": ["Domain Admin", "AWS root", "Production DB write"],
            "approval_chain": ["manager", "application_owner", "security_team", "ciso"],
            "sla_hours": 72,
            "auto_approve_if_birthright": False,
            "require_justification": True,
            "require_time_limit": True,
            "require_sod_check": True,
            "max_duration_days": 90
        }
    }
}

class AccessRequestEngine:
    def __init__(self, iga_client, risk_catalog):
        self.iga = iga_client
        self.risk_catalog = risk_catalog

    def submit_request(self, requester_id, entitlement_id, justification, duration_days=None):
        """Submit an access request with automatic risk classification."""
        # Classify risk level of requested entitlement
        risk_level = self.risk_catalog.get_risk_level(entitlement_id)
        workflow = ACCESS_REQUEST_WORKFLOW["risk_levels"][risk_level]

        # Check if entitlement is birthright for requester's role
        requester = self.iga.get_identity(requester_id)
        is_birthright = self.iga.is_birthright_for_role(
            entitlement_id, requester["job_code"]
        )

        if is_birthright and workflow.get("auto_approve_if_birthright"):
            return self._auto_approve(requester_id, entitlement_id, "Birthright access")

        # Run SOD check if required
        if workflow.get("require_sod_check"):
            sod_violations = self.iga.check_sod(requester_id, entitlement_id)
            if sod_violations:
                return {
                    "status": "SOD_VIOLATION",
                    "violations": sod_violations,
                    "action": "Request requires compensating control approval"
                }

        # Create approval chain
        request = {
            "requester": requester_id,
            "entitlement": entitlement_id,
            "risk_level": risk_level,
            "justification": justification,
            "duration_days": duration_days or workflow.get("max_duration_days"),
            "approval_chain": self._build_approval_chain(
                requester, workflow["approval_chain"]
            ),
            "sla_deadline": workflow["sla_hours"],
            "status": "PENDING_APPROVAL"
        }

        return self.iga.create_request(request)

    def _build_approval_chain(self, requester, approver_types):
        """Resolve approval chain to actual approver identities."""
        chain = []
        for approver_type in approver_types:
            if approver_type == "manager":
                chain.append({
                    "type": "manager",
                    "identity": requester["manager_id"],
                    "fallback": requester.get("skip_manager_id")
                })
            elif approver_type == "application_owner":
                chain.append({
                    "type": "application_owner",
                    "identity": "resolved_at_runtime",
                    "fallback": "it-governance-team"
                })
            elif approver_type == "security_team":
                chain.append({
                    "type": "group",
                    "identity": "security-governance-team",
                    "required_approvals": 1
                })
            elif approver_type == "ciso":
                chain.append({
                    "type": "role",
                    "identity": "CISO",
                    "fallback": "deputy-ciso"
                })
        return chain
```

### Step 5: Implement Orphaned Account Detection and Remediation

Identify and remediate accounts without active identity associations:

```python
"""
Orphaned Account Detection
Identifies accounts in target systems that have no corresponding
active identity in the authoritative HR source.
"""

class OrphanedAccountDetector:
    def __init__(self, hr_connector, app_connectors):
        self.hr = hr_connector
        self.apps = app_connectors

    def detect_orphaned_accounts(self):
        """Compare application accounts against HR active employees."""
        active_employees = set(self.hr.get_active_employee_ids())
        orphaned_accounts = []

        for app_name, connector in self.apps.items():
            app_accounts = connector.get_all_accounts()

            for account in app_accounts:
                correlated_id = account.get("employee_id") or account.get("correlation_id")

                if correlated_id and correlated_id not in active_employees:
                    # Check if recently terminated (within grace period)
                    termination_info = self.hr.get_termination_info(correlated_id)

                    orphaned_accounts.append({
                        "application": app_name,
                        "account_name": account["username"],
                        "correlated_employee_id": correlated_id,
                        "account_status": account.get("status", "unknown"),
                        "last_login": account.get("last_login"),
                        "termination_date": termination_info.get("date") if termination_info else None,
                        "days_since_termination": (
                            (datetime.utcnow() - termination_info["date"]).days
                            if termination_info and termination_info.get("date") else None
                        ),
                        "risk_level": self._assess_orphan_risk(account, termination_info)
                    })

                elif not correlated_id:
                    # Uncorrelated account - no link to any employee
                    orphaned_accounts.append({
                        "application": app_name,
                        "account_name": account["username"],
                        "correlated_employee_id": None,
                        "account_status": account.get("status", "unknown"),
                        "last_login": account.get("last_login"),
                        "risk_level": "HIGH",
                        "reason": "Uncorrelated - no employee association"
                    })

        return orphaned_accounts

    def _assess_orphan_risk(self, account, termination_info):
        """Assess risk level of orphaned account."""
        if account.get("is_privileged"):
            return "CRITICAL"
        if termination_info and termination_info.get("involuntary"):
            return "HIGH"
        if account.get("status") == "active":
            return "HIGH"
        return "MEDIUM"

    def generate_remediation_plan(self, orphaned_accounts):
        """Create remediation actions for orphaned accounts."""
        plan = []
        for account in orphaned_accounts:
            if account["risk_level"] == "CRITICAL":
                action = "DISABLE_IMMEDIATELY"
                sla = "4 hours"
            elif account["risk_level"] == "HIGH":
                action = "DISABLE_WITHIN_24H"
                sla = "24 hours"
            else:
                action = "REVIEW_AND_DISABLE"
                sla = "7 days"

            plan.append({
                **account,
                "remediation_action": action,
                "sla": sla,
                "assigned_to": "identity-governance-team"
            })

        return sorted(plan, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x["risk_level"]))
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Joiner-Mover-Leaver (JML)** | Core identity lifecycle transitions covering employee onboarding (joiner), role/department changes (mover), and offboarding (leaver) |
| **Birthright Access** | Baseline entitlements automatically provisioned based on job code, department, or location without requiring an access request |
| **Role Mining** | Analysis of existing access patterns to derive role definitions by identifying common entitlement groupings across similar job functions |
| **Orphaned Account** | Application account that no longer has a corresponding active identity in the authoritative HR source, representing a security risk |
| **Authoritative Source** | System of record (typically HR) that serves as the single source of truth for identity attributes and employment status |
| **Access Request Workflow** | Self-service process enabling users to request additional entitlements with risk-based approval routing |

## Tools & Systems

- **SailPoint IdentityIQ/IdentityNow**: Enterprise IGA platform for lifecycle management, access certifications, and automated provisioning
- **Saviynt Enterprise Identity Cloud**: Cloud-native IGA with identity warehouse, access governance, and application access management
- **Microsoft Entra ID Governance**: Identity governance capabilities including lifecycle workflows, access reviews, and entitlement management
- **One Identity Manager**: IGA solution with business role management, attestation, and IT shop for access requests

## Common Scenarios

### Scenario: Building JML Process for 10,000-Employee Organization

**Context**: Rapidly growing company has no automated identity lifecycle. IT manually creates accounts, taking 3-5 days for new hires. Terminated employees retain access for weeks. Audit found 2,300 orphaned accounts across 45 applications.

**Approach**:
1. Integrate Workday as authoritative source with daily delta sync to IGA platform
2. Mine existing access patterns to define birthright roles for the top 20 job codes (covering 80% of employees)
3. Implement pre-hire provisioning triggered 7 days before start date for AD, email, and birthright apps
4. Build termination workflow that disables all access within 1 hour of HR status change
5. Create mover workflow that recalculates roles when job code or department changes
6. Deploy self-service access request portal with risk-based approval chains
7. Run orphaned account detection to identify and remediate the 2,300 existing orphans
8. Schedule quarterly access certifications to prevent access accumulation

**Pitfalls**:
- Not defining a single authoritative source leads to conflicting identity data from multiple HR systems
- Mining roles without business validation creates technical roles that do not align with organizational structure
- Automating termination without grace period for knowledge transfer frustrates business managers
- Not handling contractor and vendor identities that exist outside the HR system

## Output Format

```
IDENTITY GOVERNANCE LIFECYCLE REPORT
=======================================
Authoritative Source:   Workday
IGA Platform:          SailPoint IdentityIQ
Total Identities:      10,247
Active Employees:      9,834
Contractors:           413

LIFECYCLE AUTOMATION
Joiner (Pre-Hire) SLA:     Target: 0 days | Actual: 0.2 days avg
Mover Processing SLA:      Target: 1 day  | Actual: 0.8 days avg
Leaver Disablement SLA:    Target: 1 hour | Actual: 0.5 hours avg

PROVISIONING METRICS (Last 30 Days)
New Hires Provisioned:     187
  Auto-Provisioned:        174 (93.0%)
  Manual Intervention:     13 (7.0%)
Role Changes Processed:    89
Terminations Processed:    43
  Within 1-Hour SLA:       41 (95.3%)

ROLE GOVERNANCE
Defined Roles:             127
Birthright Roles:          48
Average Entitlements/Role: 12.3
Role Overlap > 70%:        8 pairs (consolidation recommended)

ORPHANED ACCOUNTS
Detected:                  23
  Critical:                2 (privileged accounts)
  High:                    8
  Medium:                  13
Remediated (30 days):      19
Outstanding:               4

ACCESS REQUESTS
Submitted:                 342
Auto-Approved (Birthright):87 (25.4%)
Approved:                  231 (67.5%)
Denied:                    24 (7.0%)
Average Approval Time:     6.2 hours
SOD Violations Flagged:    12
```
