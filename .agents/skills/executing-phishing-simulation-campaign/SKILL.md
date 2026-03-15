---
name: executing-phishing-simulation-campaign
description: >
  Executes authorized phishing simulation campaigns to assess an organization's susceptibility
  to email-based social engineering attacks. The tester designs realistic phishing scenarios,
  builds credential harvesting infrastructure, sends targeted phishing emails, and tracks
  open rates, click-through rates, and credential submission rates to measure human security
  awareness. Activates for requests involving phishing simulation, social engineering assessment,
  email security testing, or security awareness measurement.
domain: cybersecurity
subdomain: penetration-testing
tags: [phishing-simulation, social-engineering, GoPhish, email-security, security-awareness]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Executing Phishing Simulation Campaign

## When to Use

- Measuring employee susceptibility to phishing attacks as part of a security awareness program
- Testing the effectiveness of email security controls (secure email gateway, DMARC, SPF, DKIM)
- Conducting the social engineering component of a red team exercise to gain initial access
- Establishing a baseline for phishing susceptibility before deploying security awareness training
- Validating that incident response procedures work when employees report suspicious emails

**Do not use** without explicit written authorization from the organization's leadership, for actual credential theft beyond the authorized scope, for targeting individuals personally rather than professionally, or for sending phishing emails that could cause psychological harm or legal liability.

## Prerequisites

- Written authorization from executive leadership specifying the campaign scope, target groups, and escalation procedures
- Coordination with the IT/security team to whitelist the sending infrastructure (or test whether it bypasses controls, depending on scope)
- GoPhish or equivalent phishing platform configured with a sending domain, SMTP relay, and landing page infrastructure
- Phishing domain registered and configured with SPF, DKIM, and DMARC records to maximize deliverability
- Employee email list from HR, organized by department for targeted campaigns
- Incident response team briefed on the campaign timeline and escalation procedures

## Workflow

### Step 1: Campaign Planning and Pretext Development

Design realistic phishing scenarios based on threats relevant to the target organization:

- **Pretext selection**: Choose scenarios that mirror real-world attacks:
  - IT support: Password expiration notice requiring immediate action
  - HR department: Benefits enrollment, policy acknowledgment, W-2/tax document
  - Executive impersonation: Urgent request from CEO/CFO to review a document
  - Vendor/supplier: Invoice requiring review, delivery notification
  - Cloud services: Microsoft 365 shared document, Google Drive access, Zoom meeting invitation
- **Target segmentation**: Divide employees into groups by department, role, or access level. High-value targets (finance, IT admin, executives) may receive more sophisticated pretexts.
- **Timing**: Schedule sends during business hours, preferably Tuesday-Thursday when email engagement is highest. Avoid holidays, mass layoff periods, or other sensitive times.
- **Success metrics**: Define what constitutes campaign success: email open rate, link click rate, credential submission rate, report rate (employees who report the phish to IT)

### Step 2: Infrastructure Setup

Configure the phishing infrastructure:

- **Domain registration**: Register a domain that resembles the target organization's domain (typosquatting, homograph, or brand-adjacent). Examples: `target-corp.com`, `targetcorp-portal.com`, `targetsupport.net`
- **SSL certificate**: Obtain a TLS certificate for the phishing domain (Let's Encrypt) to display the padlock icon
- **GoPhish configuration**:
  - Set up the GoPhish server on a VPS with the phishing domain
  - Configure the SMTP sending profile with the phishing domain's mail server
  - Create the email template with tracking pixel and link to the landing page
  - Build the credential harvesting landing page that mirrors the target's login portal
  - Import the target email list and create user groups
- **Email authentication**: Configure SPF, DKIM, and DMARC records for the phishing domain to pass email authentication checks and improve delivery rates
- **Test delivery**: Send test emails to a controlled inbox to verify rendering, link tracking, and landing page functionality

### Step 3: Campaign Execution

Launch the phishing campaign:

- Send emails in batches to avoid triggering rate limits or spam filters (e.g., 50 emails per hour)
- Monitor GoPhish dashboard in real-time for delivery failures, bounces, and early interactions
- Track metrics as they come in: emails sent, emails opened (tracking pixel fired), links clicked, credentials submitted
- If the IT security team or SOC detects the campaign (if this is part of the test), document the detection time and response actions
- Maintain an emergency stop procedure: if an employee becomes distressed or the campaign creates unintended consequences, pause immediately
- Run the campaign for 48-72 hours before closing the landing page, as most interactions occur within the first 24 hours

### Step 4: Credential Capture and Access Demonstration

Process captured credentials to demonstrate impact (if authorized):

- Review all captured credentials in GoPhish. Do not test credentials against real systems unless explicitly authorized.
- If authorized for full exploitation: test captured credentials against the organization's actual login portal (VPN, OWA, SSO)
- Document any accounts that were successfully compromised, what data they could access, and whether MFA was present
- If MFA blocks access, document that MFA prevented the compromise and recommend maintaining MFA enforcement
- Identify patterns in credential submissions: which departments, roles, or locations are most susceptible

### Step 5: Analysis and Reporting

Analyze campaign results and produce the assessment report:

- **Metrics analysis**:
  - Email delivery rate: percentage of emails that reached inboxes
  - Open rate: percentage of recipients who opened the email
  - Click rate: percentage who clicked the phishing link
  - Submission rate: percentage who submitted credentials
  - Report rate: percentage who reported the email to IT security
- **Departmental comparison**: Compare susceptibility rates across departments to identify groups needing targeted training
- **Email security effectiveness**: Document whether the phishing emails bypassed the secure email gateway, whether DMARC/SPF prevented delivery, and whether link scanning tools detected the phishing URL
- **Recommendations**: Provide actionable recommendations including security awareness training topics, technical controls improvements, and policy changes

## Key Concepts

| Term | Definition |
|------|------------|
| **Pretext** | The fabricated scenario and social context used to persuade the target to take a desired action such as clicking a link or entering credentials |
| **Credential Harvesting** | Collecting usernames and passwords through fake login pages that mimic legitimate services |
| **GoPhish** | Open-source phishing simulation platform that manages email templates, landing pages, target groups, and campaign tracking |
| **Spear Phishing** | Targeted phishing directed at specific individuals using personalized information gathered through reconnaissance |
| **Typosquatting** | Registering domains that are visually similar to legitimate domains through character substitution, addition, or omission |
| **Security Awareness** | Training programs designed to educate employees about social engineering threats and proper reporting procedures |
| **DMARC** | Domain-based Message Authentication, Reporting, and Conformance; email authentication protocol that prevents unauthorized use of a domain for sending email |

## Tools & Systems

- **GoPhish**: Open-source phishing simulation framework providing campaign management, email templates, landing pages, and detailed analytics
- **Evilginx2**: Advanced phishing framework capable of capturing session tokens and bypassing multi-factor authentication through reverse proxy technique
- **King Phisher**: Phishing campaign toolkit with advanced features including two-factor authentication testing and geolocation tracking
- **SET (Social Engineering Toolkit)**: Framework for social engineering attacks including phishing, credential harvesting, and payload delivery

## Common Scenarios

### Scenario: Enterprise Phishing Simulation for Security Awareness Baseline

**Context**: A 2,000-employee company has never conducted a phishing simulation. The CISO wants to establish a baseline susceptibility rate before deploying a new security awareness training program. The campaign should test all employees using a realistic but not overly sophisticated pretext.

**Approach**:
1. Develop a Microsoft 365 password expiration pretext: "Your password expires in 24 hours. Click here to update."
2. Register `m365-targetcorp.com`, set up GoPhish, and build a landing page cloning the Microsoft 365 login portal
3. Import all 2,000 employee emails and schedule sends in batches of 100 over 20 hours
4. Campaign results after 72 hours: 1,847 delivered (92.4%), 1,243 opened (67.3%), 487 clicked (26.4%), 312 submitted credentials (16.9%), 23 reported to IT (1.2%)
5. Analysis reveals Finance (28% submission) and Marketing (24% submission) have the highest susceptibility; IT department has the lowest (4%)
6. Recommend targeted training for high-susceptibility departments, phishing report button deployment, and quarterly simulation cadence

**Pitfalls**:
- Using overly aggressive or threatening pretexts that cause employee anxiety or legal issues
- Not coordinating with HR and legal before launching the campaign, risking employee relations problems
- Sending all emails simultaneously, overwhelming the email server or triggering bulk-send detection
- Focusing only on click and submission rates while ignoring the critically low report rate (1.2%)

## Output Format

```
## Phishing Simulation Campaign Report

**Campaign Name**: Q4 2025 Baseline Phishing Assessment
**Pretext**: Microsoft 365 Password Expiration Notice
**Campaign Duration**: November 15-18, 2025
**Target Population**: 2,000 employees (all departments)

### Campaign Metrics
| Metric | Count | Rate |
|--------|-------|------|
| Emails Sent | 2,000 | 100% |
| Emails Delivered | 1,847 | 92.4% |
| Emails Opened | 1,243 | 67.3% |
| Links Clicked | 487 | 26.4% |
| Credentials Submitted | 312 | 16.9% |
| Reported to IT | 23 | 1.2% |

### Department Breakdown
| Department | Employees | Clicked | Submitted | Reported |
|------------|-----------|---------|-----------|----------|
| Finance    | 120       | 38.3%   | 28.3%     | 0.8%     |
| Marketing  | 85        | 35.3%   | 24.7%     | 1.2%     |
| Engineering| 300       | 15.0%   | 8.3%      | 3.7%     |
| IT         | 45        | 8.9%    | 4.4%      | 11.1%    |

### Key Findings
1. Baseline credential submission rate of 16.9% exceeds industry average (12%)
2. Report rate of 1.2% indicates employees are not trained to report suspicious emails
3. Finance department is the highest-risk group with 28.3% credential submission rate
4. Email security gateway did not flag the phishing domain despite being registered 48 hours prior

### Recommendations
1. Deploy mandatory security awareness training with emphasis on phishing identification
2. Install a phishing report button in email clients and train all employees on its use
3. Implement DMARC enforcement (p=reject) and enhanced email filtering rules
4. Conduct targeted training for Finance and Marketing departments
5. Schedule quarterly phishing simulations to track improvement
```
