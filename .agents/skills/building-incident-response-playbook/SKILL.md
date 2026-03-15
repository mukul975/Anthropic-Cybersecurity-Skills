---
name: building-incident-response-playbook
description: >
  Designs and documents structured incident response playbooks that define step-by-step
  procedures for specific incident types aligned with NIST SP 800-61r3 and SANS PICERL
  frameworks. Covers playbook structure, decision trees, escalation criteria, RACI matrices,
  and integration with SOAR platforms. Activates for requests involving IR playbook creation,
  incident response procedure documentation, response runbook development, or SOAR playbook
  design.
domain: cybersecurity
subdomain: incident-response
tags: [IR-playbook, runbook, NIST-800-61, SOAR-integration, response-procedures]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Building Incident Response Playbooks

## When to Use

- Establishing or maturing an incident response program from scratch
- Documenting procedures for a new incident type after a novel attack
- Automating response workflows in a SOAR platform (Cortex XSOAR, Splunk SOAR)
- Preparing for compliance audits requiring documented IR procedures (SOC 2, PCI-DSS, HIPAA)
- Conducting a gap analysis of existing IR capabilities against specific threat scenarios

**Do not use** for one-time ad hoc investigations; playbooks are reusable procedure documents, not case-specific reports.

## Prerequisites

- Organizational risk assessment identifying top incident scenarios by likelihood and impact
- NIST SP 800-61r3 or SANS PICERL framework adopted as the organizational IR standard
- Asset inventory with business criticality ratings and data classification
- RACI chart defining roles: Incident Commander, SOC analysts, system administrators, legal, communications
- Existing detection capabilities inventory (SIEM rules, EDR detections, IDS signatures)
- SOAR platform access if building automated playbooks

## Workflow

### Step 1: Select and Scope the Incident Type

Define the specific scenario the playbook will address:

- Identify the top incident types based on organizational risk assessment and historical data
- Scope each playbook to a single incident type for clarity (do not combine unrelated scenarios)
- Define trigger conditions that activate the playbook

Common playbook types:
```
Priority Playbooks (build first):
1. Ransomware incident response
2. Phishing/credential compromise
3. Business email compromise
4. Malware infection
5. Data breach/exfiltration
6. DDoS attack
7. Insider threat
8. Account takeover
9. Web application compromise
10. Cloud infrastructure compromise
```

### Step 2: Define the Playbook Structure

Every playbook should follow a consistent structure:

```
PLAYBOOK TEMPLATE
━━━━━━━━━━━━━━━━
1. Playbook Metadata
   - Name, version, owner, last review date
   - Trigger conditions
   - Severity criteria

2. RACI Matrix
   - Who is Responsible, Accountable, Consulted, Informed for each step

3. Detection & Triage
   - How the incident is detected
   - Initial triage checklist
   - Severity classification criteria

4. Containment
   - Short-term containment actions
   - Long-term containment actions
   - Evidence preservation requirements

5. Eradication
   - Root cause identification
   - Malware/threat removal steps
   - Verification procedures

6. Recovery
   - System restoration steps
   - Validation criteria
   - Monitoring requirements post-recovery

7. Post-Incident
   - Lessons learned meeting trigger
   - Report template
   - Detection improvement actions

8. Communication
   - Internal notification matrix
   - External notification requirements (regulators, customers, law enforcement)
   - Status update cadence

9. Appendices
   - Tool-specific procedures
   - Contact lists
   - Evidence collection checklists
```

### Step 3: Write Decision Trees and Escalation Criteria

Define clear decision points with binary outcomes:

```
Detection Alert Received
├── Is the alert a true positive?
│   ├── YES → Classify severity
│   │   ├── P1 (Critical) → Page incident commander, begin containment immediately
│   │   ├── P2 (High) → Notify IR lead, begin investigation within 30 min
│   │   ├── P3 (Medium) → Queue for investigation within 4 hours
│   │   └── P4 (Low) → Document and investigate within 24 hours
│   └── NO → Document as false positive, tune detection rule
└── Cannot determine → Escalate to Tier 2 for deeper analysis
```

Escalation triggers:
- Any P1 incident: Immediate escalation to IR lead and CISO
- Data exfiltration confirmed: Legal counsel and privacy officer notified
- Customer data involved: Customer notification process activated
- Third-party involvement: Vendor security contact engaged
- Law enforcement needed: General counsel authorizes before contact

### Step 4: Define Specific Technical Procedures

Write tool-specific instructions for each step (not generic guidance):

```
CONTAINMENT - Endpoint Isolation via CrowdStrike:
1. Open Falcon Console > Hosts > Search for affected hostname
2. Click on the host > Host Details
3. Click "Contain Host" button in upper right
4. Confirm isolation (host will only communicate with CrowdStrike cloud)
5. Document containment action in incident ticket with timestamp
6. Verify containment: Host should show "Contained" status badge

CONTAINMENT - Block C2 Domain at DNS:
1. SSH to DNS server: ssh admin@dns-primary.corp.local
2. Add to block zone: echo "zone evil.com { type master; file /etc/bind/db.sinkhole; };" >> /etc/bind/named.conf.local
3. Reload DNS: rndc reload
4. Verify: dig @dns-primary evil.com (should resolve to sinkhole IP 10.0.0.99)
5. Document blocked domain in incident ticket
```

### Step 5: Integrate with SOAR Platform

Convert manual playbook steps into automated workflows:

- Map each playbook step to a SOAR action (API call, script, human decision point)
- Define automation boundaries (what runs automatically vs. what requires analyst approval)
- Build enrichment automations for the triage phase
- Create containment automations with approval gates for high-impact actions
- Configure notification automations for stakeholder communication

### Step 6: Test and Maintain the Playbook

Validate the playbook through exercises and maintain currency:

- Conduct tabletop exercises with the IR team walking through the playbook
- Perform live-fire exercises simulating the incident type in a test environment
- Review and update after every real incident that uses the playbook
- Schedule quarterly reviews for accuracy of contact lists, tool procedures, and escalation paths
- Track playbook metrics: mean time to contain, mean time to resolve, false positive rate

## Key Concepts

| Term | Definition |
|------|------------|
| **Playbook** | Documented, repeatable set of procedures for responding to a specific incident type |
| **Runbook** | More granular than a playbook; step-by-step technical instructions for a specific task within a playbook |
| **RACI Matrix** | Responsibility assignment chart defining who is Responsible, Accountable, Consulted, and Informed for each activity |
| **Decision Tree** | Flowchart-based logic defining the response path based on binary conditions at each decision point |
| **Escalation Criteria** | Predefined conditions that trigger notification of higher-level personnel or external parties |
| **SOAR Playbook** | Automated workflow in a Security Orchestration, Automation, and Response platform executing playbook steps |

## Tools & Systems

- **Cortex XSOAR**: SOAR platform with visual playbook editor, 700+ integrations, and collaborative War Room
- **Splunk SOAR**: SOAR platform integrated with Splunk ES, drag-and-drop playbook builder with 2,800+ automated actions
- **TheHive**: Open-source incident response platform with case templates that function as playbook frameworks
- **Confluence / GitLab Wiki**: Documentation platforms for maintaining human-readable playbook documents with version control
- **Tines**: No-code security automation platform for building playbook workflows without programming

## Common Scenarios

### Scenario: Building a Phishing Response Playbook from Scratch

**Context**: An organization with a 5-person SOC has no documented phishing response procedure. Analysts handle phishing reports inconsistently.

**Approach**:
1. Interview SOC analysts to document their current ad hoc process
2. Define the trigger: user reports phishing email via abuse@ mailbox or phishing button
3. Write triage steps: extract email headers, check sender reputation, analyze URLs/attachments in sandbox
4. Define containment: quarantine email from all mailboxes, block sender domain, reset passwords if credentials entered
5. Build SOAR automation: auto-extract IOCs from reported email, enrich via VirusTotal, create case in TheHive
6. Test with simulated phishing email and measure response time improvement

**Pitfalls**:
- Writing overly generic procedures that don't reference specific tool interfaces or commands
- Not including the communication plan for notifying users who received the phishing email
- Forgetting to define the criteria for when a phishing report becomes a full incident investigation
- Not versioning the playbook or scheduling regular review cycles

## Output Format

```
INCIDENT RESPONSE PLAYBOOK
============================
Playbook Name:    Phishing Incident Response
Version:          2.1
Owner:            SOC Manager
Last Reviewed:    2025-11-01
Next Review:      2026-02-01
Trigger:          Phishing email reported via abuse@corp.com or phish button

RACI MATRIX
Activity                    | SOC L1 | SOC L2 | IR Lead | Legal | Comms
Initial Triage              |   R    |   C    |   I     |       |
Email Analysis              |   R    |   A    |   I     |       |
Containment                 |        |   R    |   A     |   I   |
Credential Reset            |        |   R    |   A     |       |
User Notification           |        |   C    |   A     |       |   R
Regulatory Notification     |        |        |   C     |   R   |   A
Lessons Learned             |   C    |   C    |   R     |   I   |   I

PROCEDURE STEPS
[Detailed steps with tool-specific instructions]

DECISION TREE
[Flowchart logic]

ESCALATION MATRIX
[Conditions and contacts]

METRICS
Target MTTA: 15 minutes
Target MTTC: 1 hour
Target MTTR: 4 hours
```
