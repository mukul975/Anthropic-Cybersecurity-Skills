---
name: performing-soc-tabletop-exercise
description: >
  Performs tabletop exercises for SOC teams simulating security incidents through discussion-based
  scenarios to test incident response procedures, communication workflows, and decision-making
  under pressure without impacting production systems. Use when organizations need to validate
  IR playbooks, train analysts, or meet compliance requirements for incident response testing.
domain: cybersecurity
subdomain: soc-operations
tags: [soc, tabletop, exercise, incident-response, training, nist, playbook-validation]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing SOC Tabletop Exercise

## When to Use

Use this skill when:
- Annual or semi-annual incident response testing is required (NIST, ISO 27001, PCI DSS compliance)
- New SOC analysts need exposure to major incident scenarios in a controlled environment
- Updated playbooks need validation before next real incident
- Cross-functional coordination (SOC, IT, Legal, PR, Executive) needs rehearsal
- Post-incident reviews reveal gaps requiring scenario-based training

**Do not use** as a replacement for technical purple team exercises — tabletop exercises test processes and decision-making, not technical detection capabilities.

## Prerequisites

- Exercise facilitator with incident response experience
- Participant list: SOC analysts (Tier 1-3), SOC manager, IT operations, Legal, HR, Communications
- Conference room or video call with screen sharing capability
- Printed or digital scenario injects with timed release schedule
- Evaluation scorecard for assessing participant responses
- Existing incident response plan and playbooks for reference during exercise

## Workflow

### Step 1: Design Exercise Scenario

Create a realistic multi-phase scenario with escalating complexity:

```yaml
tabletop_exercise:
  title: "Operation Dark Harvest — Ransomware Attack Scenario"
  exercise_id: TTX-2024-Q1
  date: 2024-03-22
  duration: 3 hours (09:00-12:00)
  classification: TLP:AMBER (internal use only)

  objectives:
    1: "Test SOC team's ability to detect and triage ransomware indicators"
    2: "Validate escalation procedures from Tier 1 to incident commander"
    3: "Assess cross-functional communication with Legal, PR, and Executive leadership"
    4: "Evaluate containment decision-making under time pressure"
    5: "Test backup recovery procedures and business continuity activation"

  participants:
    - role: SOC Tier 1 Analyst (2 participants)
    - role: SOC Tier 2 Analyst (2 participants)
    - role: SOC Manager / Incident Commander
    - role: IT Operations Lead
    - role: CISO (or delegate)
    - role: Legal Counsel
    - role: Communications / PR
    - role: Business Unit Leader (Finance)

  scenario_background: >
    Your organization is a mid-size financial services company with 2,500 employees.
    The SOC operates 24/7 with 6 analysts per shift using Splunk ES and CrowdStrike Falcon.
    It is Friday afternoon at 3:45 PM. The weekend IT skeleton crew starts at 5 PM.
```

### Step 2: Create Timed Injects

Design scenario injects released at scheduled intervals:

```yaml
injects:

  inject_1:
    time: "T+0 (3:45 PM)"
    title: "Initial Alert"
    content: >
      Splunk ES generates a notable event: "Shadow Copy Deletion Detected"
      on FILESERVER-03 (10.0.10.50, Finance Department file server).
      The alert shows: vssadmin.exe delete shadows /all /quiet
      Source user: svc_backup (service account)
      This is the first alert from this host today.
    questions:
      - "What is your initial assessment of this alert?"
      - "What additional data would you query in Splunk?"
      - "Is this a Tier 1 triage item or immediate escalation?"

  inject_2:
    time: "T+10 minutes"
    title: "Escalating Indicators"
    content: >
      While investigating the first alert, two more alerts fire:
      1. "Mass File Modification Detected" — 2,847 files renamed with .locked extension
         on FILESERVER-03 within 5 minutes
      2. "Suspicious PowerShell Encoded Command" on WORKSTATION-118 (10.0.5.118)
         — same svc_backup account used
      CrowdStrike shows process tree: explorer.exe > cmd.exe > powershell.exe -enc [base64]
    questions:
      - "What is your updated assessment? What incident severity would you assign?"
      - "What immediate containment actions would you take?"
      - "Who needs to be notified at this point?"
      - "How do you determine if this is confined to these two hosts?"

  inject_3:
    time: "T+25 minutes"
    title: "Scope Expansion"
    content: >
      Enterprise-wide Splunk search reveals:
      - 7 additional hosts showing .locked file extensions
      - All affected hosts are in the Finance VLAN (10.0.10.0/24)
      - svc_backup account was used to RDP to all affected hosts starting at 3:30 PM
      - A ransom note "README_UNLOCK.txt" found on all affected hosts
      - Ransom note demands 50 BTC, includes Tor payment portal link
      - IT reports the svc_backup password was changed 2 days ago (not by IT team)
    questions:
      - "This is now a confirmed ransomware incident. What is your incident classification?"
      - "Walk through your containment strategy — what do you isolate and in what order?"
      - "Should you shut down the Finance VLAN entirely? What are the trade-offs?"
      - "When and how do you notify executive leadership?"

  inject_4:
    time: "T+45 minutes"
    title: "Business Impact and External Pressure"
    content: >
      The CFO calls the SOC Manager directly:
      "We are closing the quarter-end books this weekend. Finance absolutely needs
      access to FILESERVER-03 by Monday morning or we miss SEC filing deadlines."
      Additionally:
      - Legal asks if customer PII was on any affected servers
      - PR reports a journalist called asking about "cybersecurity issues at [company]"
      - The ransom note deadline is 48 hours
      - IT reports last verified backup of FILESERVER-03 is from Wednesday (3 days old)
    questions:
      - "How do you balance containment security with business pressure from the CFO?"
      - "What is your recommendation on ransom payment? Who makes this decision?"
      - "What information does Legal need to assess breach notification obligations?"
      - "How do you handle the media inquiry?"
      - "Can you recover from the 3-day-old backup? What data is lost?"

  inject_5:
    time: "T+70 minutes"
    title: "Forensic Discovery"
    content: >
      Tier 3 forensic analysis reveals:
      - Initial access was via compromised VPN credentials (svc_backup)
      - Credentials were found in a dark web dump from a third-party vendor breach
      - Attacker had access for 5 days before deploying ransomware
      - Evidence of data exfiltration: 15GB uploaded to Mega.nz over 3 days
      - Exfiltrated data includes customer PII (SSN, account numbers) for 12,000 clients
      - The ransomware variant is identified as LockBit 3.0
    questions:
      - "How does confirmed data exfiltration change your response?"
      - "What are the regulatory notification requirements? (SEC, state breach laws)"
      - "What is the timeline for customer notification?"
      - "Should you engage external IR firm? Law enforcement?"
      - "How do you handle the vendor who was the source of the credential compromise?"

  inject_6:
    time: "T+90 minutes"
    title: "Recovery Decision Point"
    content: >
      You are now 6 hours into the incident. Status:
      - All 9 affected hosts isolated
      - Finance VLAN segmented from corporate network
      - LockBit C2 domain blocked at firewall and DNS
      - No decryptor available for LockBit 3.0
      - Wednesday backup verified clean but 3 days of data missing
      - CEO asks for a full situation briefing in 30 minutes
    questions:
      - "Prepare a 5-minute executive briefing. What do you include?"
      - "What is your recovery plan and estimated timeline?"
      - "What monitoring will you put in place during and after recovery?"
      - "What immediate security improvements would you recommend?"
```

### Step 3: Facilitate the Exercise

**Facilitator Guide:**

```
EXERCISE FACILITATION PROTOCOL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. OPENING (10 min)
   - State exercise objectives and ground rules
   - Emphasize: "No wrong answers — this is about testing process, not individuals"
   - Remind participants this is a simulation — no actual systems are affected
   - Identify the exercise observer/scribe

2. INJECT DELIVERY (110 min)
   - Present each inject on screen, allow 2 min reading time
   - Ask guided questions to each role group
   - Allow discussion but keep on timeline
   - Inject additional pressure/complications as needed
   - Record decisions, rationale, and gaps identified

3. DISCUSSION RULES
   - Participants respond in-character (their actual role)
   - Reference actual playbooks and procedures when available
   - If participants are unsure, that IS the finding
   - Facilitator may add "hot injects" if discussion stalls

4. CLOSING (40 min)
   - Hot wash: Each participant shares one thing that went well, one gap
   - Facilitator summarizes key findings
   - Identify top 5 action items with owners and due dates
```

### Step 4: Evaluate Participant Responses

Score responses against expected outcomes:

```yaml
evaluation_criteria:

  detection_and_triage:
    expected: "Immediately recognize shadow copy deletion as ransomware precursor"
    scoring:
      excellent: "Correctly identified within 2 minutes, initiated proper escalation"
      adequate: "Identified after discussion, correct escalation path"
      needs_improvement: "Did not recognize significance, delayed escalation"

  containment_decision:
    expected: "Isolate affected hosts via EDR, segment Finance VLAN, preserve evidence"
    scoring:
      excellent: "Immediate isolation, correct priority order, evidence preservation"
      adequate: "Isolation performed but delayed or incomplete prioritization"
      needs_improvement: "Considered powering off hosts (destroys evidence) or delayed isolation"

  communication:
    expected: "Timely notification chain: SOC Manager -> CISO -> Legal -> Executive"
    scoring:
      excellent: "Proper notification within defined SLAs, clear and concise briefings"
      adequate: "Notifications made but slightly delayed or incomplete"
      needs_improvement: "Key stakeholders not notified, unclear communication"

  business_continuity:
    expected: "Balance security containment with business recovery needs"
    scoring:
      excellent: "Realistic recovery timeline communicated, alternative workarounds proposed"
      adequate: "Recovery discussed but timeline unclear"
      needs_improvement: "Overcommitted on timeline or ignored business impact"
```

### Step 5: Generate After-Action Report

```yaml
after_action_report:
  exercise: TTX-2024-Q1 "Operation Dark Harvest"
  date: 2024-03-22
  participants: 10
  duration: 3 hours

  executive_summary: >
    The tabletop exercise tested the organization's ransomware response capabilities
    across detection, containment, communication, and recovery phases. The SOC team
    demonstrated strong technical triage skills but gaps were identified in cross-
    functional communication and backup recovery procedures.

  strengths:
    - SOC analysts correctly identified ransomware indicators within first inject
    - Containment decision-making was swift and technically sound
    - Legal team was well-prepared on breach notification requirements
    - IT operations had clear understanding of backup recovery procedures

  gaps_identified:
    - gap_1:
        finding: "No documented procedure for notifying CISO after-hours"
        risk: High
        action: "Update escalation contacts with personal phone numbers and backup contacts"
        owner: SOC Manager
        due_date: 2024-04-05

    - gap_2:
        finding: "Backup recovery testing has not been performed in 6 months"
        risk: Critical
        action: "Schedule quarterly backup restoration drill"
        owner: IT Operations Lead
        due_date: 2024-04-15

    - gap_3:
        finding: "No pre-approved media holding statement for cyber incidents"
        risk: Medium
        action: "Draft and approve 3 holding statement templates with Legal"
        owner: Communications Lead
        due_date: 2024-04-10

    - gap_4:
        finding: "Service account (svc_backup) had Domain Admin privileges unnecessarily"
        risk: Critical
        action: "Audit all service accounts, implement least privilege"
        owner: IT Security
        due_date: 2024-04-01

    - gap_5:
        finding: "Unclear decision authority for ransom payment"
        risk: High
        action: "Document ransom payment decision tree with CEO/Board approval requirement"
        owner: CISO
        due_date: 2024-04-15

  metrics:
    overall_score: "72/100 (Adequate)"
    detection: "85/100 (Excellent)"
    containment: "80/100 (Good)"
    communication: "60/100 (Needs Improvement)"
    recovery: "65/100 (Needs Improvement)"

  next_exercise: "TTX-2024-Q2 — Data Breach / Insider Threat Scenario (June 2024)"
```

### Step 6: Track Remediation and Follow-Up

```spl
--- Track action items from tabletop exercise
| inputlookup ttx_action_items.csv
| eval days_remaining = round((strptime(due_date, "%Y-%m-%d") - now()) / 86400)
| eval status_flag = case(
    status="Completed", "GREEN",
    days_remaining < 0, "RED — OVERDUE",
    days_remaining < 7, "YELLOW — DUE SOON",
    1=1, "GREEN"
  )
| sort - status_flag, days_remaining
| table gap_id, finding, owner, due_date, days_remaining, status, status_flag
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Tabletop Exercise** | Discussion-based simulation where participants walk through incident scenarios without executing technical actions |
| **Inject** | Scenario update introducing new information, complications, or decisions for participants to address |
| **Hot Wash** | Immediate post-exercise debrief where participants share observations and initial lessons learned |
| **After-Action Report (AAR)** | Formal document capturing exercise findings, gaps, strengths, and remediation action items |
| **Facilitator** | Exercise leader who presents injects, guides discussion, and ensures objectives are met |
| **Decision Point** | Moment in the scenario requiring participants to choose between options with trade-offs |

## Tools & Systems

- **FEMA HSEEP**: Homeland Security Exercise and Evaluation Program providing exercise planning methodology
- **Tabletop Exercise Framework (NIST SP 800-84)**: NIST guide for planning and conducting IT security exercises
- **Immersive Labs**: Platform for cybersecurity crisis simulation and tabletop exercise management
- **Infection Monkey**: Open-source breach simulation for technical validation of tabletop findings
- **Archer**: GRC platform for tracking exercise findings and remediation action items

## Common Scenarios

- **Ransomware Attack**: Multi-phase scenario testing detection, containment, ransom decision, and recovery
- **Data Breach**: Customer PII exposure testing notification requirements, legal obligations, and PR response
- **Supply Chain Compromise**: Third-party vendor breach impacting organizational systems and data
- **Insider Threat**: Employee data theft scenario testing HR, Legal, and security team coordination
- **Business Email Compromise**: CEO fraud wire transfer attempt testing financial controls and verification procedures

## Output Format

```
TABLETOP EXERCISE SUMMARY — TTX-2024-Q1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scenario:     Operation Dark Harvest (Ransomware)
Date:         2024-03-22 (09:00-12:00 UTC)
Participants: 10 (SOC: 5, IT: 1, Legal: 1, Comms: 1, Exec: 2)
Duration:     3 hours (6 injects delivered)

SCORES:
  Detection & Triage:    85/100  Excellent
  Containment:           80/100  Good
  Communication:         60/100  Needs Improvement
  Recovery Planning:     65/100  Needs Improvement
  Overall:               72/100  Adequate

KEY FINDINGS:
  [+] Strong: Ransomware indicators correctly identified immediately
  [+] Strong: EDR isolation procedure well understood
  [-] Gap: No after-hours CISO notification procedure
  [-] Gap: Backup recovery untested for 6 months
  [-] Gap: No pre-approved media statement templates
  [-] Gap: Service account over-privileged (Domain Admin)
  [-] Gap: Ransom payment decision authority undefined

ACTION ITEMS: 5 (Critical: 2, High: 2, Medium: 1)
NEXT EXERCISE: TTX-2024-Q2 (June 2024) — Insider Threat Scenario
```
