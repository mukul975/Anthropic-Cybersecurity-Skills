---
name: performing-entitlement-review-with-sailpoint-iiq
description: >
  Performs entitlement review and access certification campaigns using SailPoint IdentityIQ
  including manager certifications, targeted entitlement reviews, role-based access validation,
  SOD violation remediation, and automated revocation workflows.
  Activates for requests involving access reviews, entitlement certifications, SailPoint IIQ
  governance, or periodic user access recertification.
domain: cybersecurity
subdomain: identity-access-management
tags: [SailPoint, IdentityIQ, access-review, entitlement-certification, IGA, access-governance]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Entitlement Review with SailPoint IdentityIQ

## When to Use

- Quarterly or annual access certification campaigns are required for compliance (SOX, HIPAA, PCI-DSS)
- Organization needs automated manager-based access reviews for all direct reports
- Targeted entitlement reviews are needed for sensitive applications or high-privilege roles
- Separation of Duties (SOD) violations must be identified and remediated
- Orphaned accounts and excessive entitlements need to be discovered and cleaned up
- Audit findings require evidence of periodic access review and remediation tracking

**Do not use** for real-time access control decisions; IdentityIQ certifications are periodic review processes designed for governance and compliance validation.

## Prerequisites

- SailPoint IdentityIQ 8.2+ deployed with database backend (Oracle, MySQL, or SQL Server)
- Application connectors configured for all in-scope systems (Active Directory, LDAP, databases, SaaS applications)
- Identity cubes aggregated with current entitlement data from all connected sources
- Email server configured for certification notifications
- Manager hierarchy defined in the identity model
- Business roles and entitlement glossary populated for reviewer context

## Workflow

### Step 1: Define Certification Campaign Strategy

Plan the certification scope and reviewer assignments:

```java
// SailPoint IdentityIQ BeanShell - Campaign Configuration
import sailpoint.object.*;
import sailpoint.api.*;
import java.util.*;

// Define campaign schedule for quarterly manager certifications
CertificationSchedule schedule = new CertificationSchedule();
schedule.setName("Q1-2026-Manager-Access-Review");
schedule.setDescription("Quarterly manager certification for all active employees");
schedule.setType(Certification.Type.Manager);

// Configure campaign scope
CertificationDefinition certDef = new CertificationDefinition();
certDef.setName("Q1 Manager Certification");
certDef.setOwner(context.getObjectByName(Identity.class, "cert-admin"));

// Set certification options
certDef.setCertifierSelectionType(CertificationDefinition.CertifierSelectionType.Manager);
certDef.setIncludeEntitlements(true);
certDef.setIncludeRoles(true);
certDef.setIncludeAccounts(true);
certDef.setIncludeAdditionalEntitlements(true);

// Exclude service accounts from manager reviews
Filter exclusionFilter = Filter.ne("type", "service");
certDef.setExclusionFilter(exclusionFilter);

// Configure notification settings
certDef.setNotificationEnabled(true);
certDef.setReminderFrequency(7); // days
certDef.setEscalationEnabled(true);
certDef.setEscalationDays(14);
certDef.setEscalationRecipient("security-governance-team");

// Set active period
certDef.setActivePeriodDays(30);
certDef.setAutoCloseEnabled(true);
certDef.setDefaultRevoke(true); // Revoke if not reviewed

context.saveObject(certDef);
context.commitTransaction();
```

### Step 2: Configure Targeted Entitlement Certification

Set up focused reviews for high-risk applications and privileged entitlements:

```java
// Targeted certification for privileged access review
import sailpoint.object.*;
import sailpoint.api.*;

CertificationDefinition targetedCert = new CertificationDefinition();
targetedCert.setName("Privileged Access Targeted Review");
targetedCert.setType(Certification.Type.ApplicationOwner);

// Scope to specific high-risk applications
List applicationNames = new ArrayList();
applicationNames.add("Active Directory");
applicationNames.add("AWS IAM");
applicationNames.add("Oracle EBS");
applicationNames.add("SAP GRC");
applicationNames.add("CyberArk Vault");
targetedCert.setApplicationNames(applicationNames);

// Filter for privileged entitlements only
String entitlementFilter = "entitlement.classification == \"Privileged\" " +
    "|| entitlement.riskScore > 800 " +
    "|| entitlement.name.contains(\"Admin\") " +
    "|| entitlement.name.contains(\"Root\") " +
    "|| entitlement.name.contains(\"DBA\")";
targetedCert.setEntitlementFilter(entitlementFilter);

// Assign application owners as certifiers
targetedCert.setCertifierSelectionType(
    CertificationDefinition.CertifierSelectionType.ApplicationOwner
);

// Configure approval workflow
targetedCert.setApprovalRequired(true);
targetedCert.setSignOffRequired(true);
targetedCert.setReasonRequired(true);

// Enable SOD policy check during certification
targetedCert.setCheckSodPolicies(true);
targetedCert.setSodPolicyAction(CertificationDefinition.SodPolicyAction.Flag);

context.saveObject(targetedCert);
context.commitTransaction();
```

### Step 3: Implement SOD Policy Checks Within Certifications

Define Separation of Duties policies that flag violations during reviews:

```java
// Create SOD policy for financial system access conflicts
import sailpoint.object.*;
import sailpoint.object.Policy;

Policy sodPolicy = new Policy();
sodPolicy.setName("Financial SOD - AP/AR Conflict");
sodPolicy.setType(Policy.TYPE_SOD);
sodPolicy.setDescription("Prevents users from having both Accounts Payable " +
    "and Accounts Receivable access simultaneously");
sodPolicy.setViolationOwner(
    context.getObjectByName(Identity.class, "compliance-team")
);

// Define conflicting entitlements
SODConstraint constraint = new SODConstraint();
constraint.setName("AP-AR Separation");

// Left side: Accounts Payable entitlements
PolicyConstraint leftSide = new PolicyConstraint();
leftSide.setApplication("SAP ERP");
leftSide.addEntitlement("SAP_AP_PROCESSOR");
leftSide.addEntitlement("SAP_AP_APPROVER");
leftSide.addEntitlement("SAP_AP_ADMIN");
constraint.setLeftConstraint(leftSide);

// Right side: Accounts Receivable entitlements
PolicyConstraint rightSide = new PolicyConstraint();
rightSide.setApplication("SAP ERP");
rightSide.addEntitlement("SAP_AR_PROCESSOR");
rightSide.addEntitlement("SAP_AR_APPROVER");
rightSide.addEntitlement("SAP_AR_ADMIN");
constraint.setRightConstraint(rightSide);

// Set violation severity and remediation
constraint.setViolationSeverity("High");
constraint.setCompensatingControl("Dual approval required for transactions > $10,000");

sodPolicy.addConstraint(constraint);
context.saveObject(sodPolicy);
context.commitTransaction();
```

### Step 4: Configure Revocation and Remediation Workflows

Automate access removal when certifiers revoke entitlements:

```java
// Configure automatic provisioning for revoked entitlements
import sailpoint.object.*;
import sailpoint.api.*;

// Create remediation workflow
Workflow remediationWorkflow = new Workflow();
remediationWorkflow.setName("Certification Revocation Workflow");
remediationWorkflow.setType(Workflow.Type.CertificationRemediation);

// Step 1: Create provisioning plan for revocation
Step createPlan = new Step();
createPlan.setName("Create Revocation Plan");
createPlan.setScript(
    "import sailpoint.object.ProvisioningPlan;\n" +
    "import sailpoint.object.ProvisioningPlan.AccountRequest;\n" +
    "import sailpoint.object.ProvisioningPlan.AttributeRequest;\n\n" +
    "ProvisioningPlan plan = new ProvisioningPlan();\n" +
    "plan.setIdentity(identity);\n" +
    "AccountRequest acctReq = new AccountRequest();\n" +
    "acctReq.setApplication(applicationName);\n" +
    "acctReq.setOperation(AccountRequest.Operation.Modify);\n" +
    "AttributeRequest attrReq = new AttributeRequest();\n" +
    "attrReq.setName(entitlementAttribute);\n" +
    "attrReq.setValue(entitlementValue);\n" +
    "attrReq.setOperation(ProvisioningPlan.Operation.Remove);\n" +
    "acctReq.add(attrReq);\n" +
    "plan.add(acctReq);\n" +
    "return plan;"
);

// Step 2: Execute provisioning with retry logic
Step executeProvisioning = new Step();
executeProvisioning.setName("Execute Revocation");
executeProvisioning.setScript(
    "import sailpoint.api.Provisioner;\n" +
    "Provisioner provisioner = new Provisioner(context);\n" +
    "provisioner.setNoTriggers(false);\n" +
    "ProvisioningResult result = provisioner.execute(plan);\n" +
    "if (result.isCommitted()) {\n" +
    "    auditEvent(\"Entitlement revoked successfully\", identity, plan);\n" +
    "} else {\n" +
    "    openWorkItem(\"Manual revocation required\", identity, plan);\n" +
    "}"
);

// Step 3: Send notification to user and manager
Step notification = new Step();
notification.setName("Send Revocation Notification");
notification.setScript(
    "import sailpoint.tools.EmailTemplate;\n" +
    "EmailTemplate template = context.getObjectByName(\n" +
    "    EmailTemplate.class, \"Access Revocation Notification\");\n" +
    "Map args = new HashMap();\n" +
    "args.put(\"identityName\", identity.getDisplayName());\n" +
    "args.put(\"applicationName\", applicationName);\n" +
    "args.put(\"entitlementName\", entitlementValue);\n" +
    "args.put(\"certifierName\", certifier.getDisplayName());\n" +
    "args.put(\"revocationReason\", decisionReason);\n" +
    "context.sendEmailNotification(template, args);"
);

context.saveObject(remediationWorkflow);
context.commitTransaction();
```

### Step 5: Monitor Campaign Progress and Compliance Metrics

Track certification completion and generate compliance evidence:

```java
// Campaign monitoring and reporting script
import sailpoint.object.*;
import sailpoint.api.*;
import java.util.*;

// Get all active certification campaigns
QueryOptions qo = new QueryOptions();
qo.addFilter(Filter.eq("phase", Certification.Phase.Active));
Iterator certIterator = context.search(Certification.class, qo);

while (certIterator.hasNext()) {
    Certification cert = certIterator.next();

    System.out.println("Campaign: " + cert.getName());
    System.out.println("  Type: " + cert.getType());
    System.out.println("  Phase: " + cert.getPhase());
    System.out.println("  Due Date: " + cert.getExpiration());

    // Get completion statistics
    CertificationStats stats = cert.getStatistics();
    int totalItems = stats.getTotalEntities();
    int completedItems = stats.getCompletedEntities();
    int pendingItems = totalItems - completedItems;
    double completionPct = (completedItems * 100.0) / totalItems;

    System.out.println("  Total Items: " + totalItems);
    System.out.println("  Completed: " + completedItems + " (" +
        String.format("%.1f", completionPct) + "%)");
    System.out.println("  Pending: " + pendingItems);

    // Decision breakdown
    int approved = stats.getApprovedCount();
    int revoked = stats.getRevokedCount();
    int mitigated = stats.getMitigatedCount();
    int delegated = stats.getDelegatedCount();

    System.out.println("  Decisions:");
    System.out.println("    Approved: " + approved);
    System.out.println("    Revoked: " + revoked);
    System.out.println("    Mitigated: " + mitigated);
    System.out.println("    Delegated: " + delegated);

    // Identify overdue certifiers
    List certifiers = cert.getCertifiers();
    for (Object certObj : certifiers) {
        CertificationEntity entity = (CertificationEntity) certObj;
        if (!entity.isCompleted() && cert.isOverdue()) {
            System.out.println("  [OVERDUE] Certifier: " +
                entity.getCertifier().getDisplayName());
        }
    }
    System.out.println();
}
```

### Step 6: Generate Audit Evidence and Reports

Export certification results for auditor review:

```java
// Generate audit report for completed certifications
import sailpoint.object.*;
import sailpoint.api.*;
import sailpoint.tools.Util;

// Query completed certifications for the audit period
QueryOptions qo = new QueryOptions();
qo.addFilter(Filter.eq("phase", Certification.Phase.End));
qo.addFilter(Filter.ge("signed", Util.stringToDate("2026-01-01")));
qo.addFilter(Filter.le("signed", Util.stringToDate("2026-03-31")));

List results = context.getObjects(Certification.class, qo);

StringBuilder auditReport = new StringBuilder();
auditReport.append("ACCESS CERTIFICATION AUDIT REPORT\n");
auditReport.append("Period: Q1 2026\n");
auditReport.append("Generated: " + new Date() + "\n");
auditReport.append("=".repeat(50) + "\n\n");

int totalCampaigns = 0;
int totalDecisions = 0;
int totalRevocations = 0;

for (Certification cert : results) {
    totalCampaigns++;
    CertificationStats stats = cert.getStatistics();

    auditReport.append("Campaign: " + cert.getName() + "\n");
    auditReport.append("  Certifier: " + cert.getCertifiers().size() + " reviewers\n");
    auditReport.append("  Items Reviewed: " + stats.getTotalEntities() + "\n");
    auditReport.append("  Approved: " + stats.getApprovedCount() + "\n");
    auditReport.append("  Revoked: " + stats.getRevokedCount() + "\n");
    auditReport.append("  Completed: " + cert.getSigned() + "\n");
    auditReport.append("  Sign-off: " + (cert.isSignedOff() ? "YES" : "NO") + "\n\n");

    totalDecisions += stats.getTotalEntities();
    totalRevocations += stats.getRevokedCount();
}

auditReport.append("SUMMARY\n");
auditReport.append("Total Campaigns: " + totalCampaigns + "\n");
auditReport.append("Total Decisions: " + totalDecisions + "\n");
auditReport.append("Total Revocations: " + totalRevocations + "\n");
auditReport.append("Revocation Rate: " +
    String.format("%.1f%%", (totalRevocations * 100.0) / totalDecisions));

System.out.println(auditReport.toString());
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Certification Campaign** | An organized review process where designated certifiers validate whether users should retain their current access entitlements across one or more applications |
| **Access Review** | Individual review unit within a campaign where a certifier examines and makes approve/revoke decisions on specific user entitlements |
| **Entitlement** | A specific permission, group membership, role, or access right granted to an identity on a target application |
| **Certifier** | The reviewer responsible for making access decisions, typically a manager, application owner, or data owner |
| **Revocation** | Decision to remove an entitlement from a user, triggering a provisioning request to the target application for access removal |
| **SOD Violation** | Separation of Duties conflict where a user holds entitlements from two or more conflicting access groups that create a segregation risk |
| **Remediation** | Automated or manual process of removing revoked access from target systems following certification decisions |

## Tools & Systems

- **SailPoint IdentityIQ**: Enterprise identity governance platform providing access certifications, lifecycle management, and compliance reporting
- **IdentityIQ Compliance Manager**: Module for running certification campaigns, tracking reviewer progress, and generating compliance evidence
- **SailPoint REST API**: Programmatic interface for automating certification campaigns, querying status, and extracting audit data
- **IdentityIQ Report Builder**: Built-in reporting engine for generating access review statistics, SOD violation summaries, and trend analysis

## Common Scenarios

### Scenario: SOX Compliance Quarterly Access Review

**Context**: A publicly traded company must demonstrate quarterly access reviews for all financial applications per SOX Section 404. The previous manual review process took 6 weeks and produced inconsistent results.

**Approach**:
1. Define application scope: SAP ERP, Oracle Financials, banking platforms, and treasury systems
2. Configure manager certifications with 30-day active period for general access review
3. Create targeted entitlement certifications for privileged financial roles with application owner as certifier
4. Enable SOD policy checks to flag AP/AR, GL posting/approval, and user admin/transaction conflicts
5. Configure automatic reminders at 7, 14, and 21 days with escalation to compliance team at day 25
6. Set default-revoke for items not reviewed by campaign end to enforce completion accountability
7. Generate signed certification reports with decision audit trail for external auditors
8. Track revocation completion to ensure all denied access is actually removed from target systems

**Pitfalls**:
- Not pre-populating entitlement descriptions causes certifiers to approve everything they do not understand
- Setting campaigns too short (under 21 days) results in rubber-stamping and low-quality reviews
- Not validating that revocations are actually provisioned to target systems (approve on paper, still active in system)
- Missing service accounts from review scope when they have access to financial systems

## Output Format

```
ACCESS CERTIFICATION CAMPAIGN REPORT
=======================================
Campaign:          Q1-2026 Manager Access Review
Type:              Manager Certification
Period:            2026-01-15 to 2026-02-14
Status:            COMPLETED

COVERAGE
Identities Reviewed:    2,847
Applications In Scope:  34
Total Entitlements:     18,392

DECISION SUMMARY
Approved:              16,841 (91.6%)
Revoked:                1,203 (6.5%)
Mitigated:                 198 (1.1%)
Delegated:                 150 (0.8%)

REVOCATION STATUS
Provisioned:            1,089 / 1,203 (90.5%)
Pending:                   87
Failed:                    27 (manual work items created)

SOD VIOLATIONS
Flagged:                   43
Remediated:                31
Compensating Controls:     12

CERTIFIER COMPLIANCE
On-Time Completion:     89.3%
Required Escalation:    14 certifiers
Average Review Time:    3.2 minutes per item

SIGN-OFF
Campaign Signed:        2026-02-14 by compliance-admin
Audit Evidence:         Exported to /reports/Q1-2026-cert-evidence.pdf
```
