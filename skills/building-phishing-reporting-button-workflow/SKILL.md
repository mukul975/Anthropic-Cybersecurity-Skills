---
name: building-phishing-reporting-button-workflow
description: Implement a phishing report button in email clients with automated triage workflow that analyzes user-reported suspicious emails and provides feedback to reporters.
domain: cybersecurity
subdomain: phishing-defense
tags: [phishing-reporting, email-security, incident-response, security-awareness, outlook, microsoft-365, soar]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Building Phishing Reporting Button Workflow

## Overview
A phishing reporting button empowers users to flag suspicious emails directly from their email client, creating a critical feedback loop between end users and the security operations center. Microsoft's built-in Report button is now the recommended approach, replacing the deprecated Report Message and Report Phishing add-ins. When combined with automated triage using SOAR platforms, reported emails can be classified, IOCs extracted, and remediation actions taken within minutes. Organizations with effective phishing reporting programs see 70%+ report rates in phishing simulations.

## Prerequisites
- Microsoft 365 or Google Workspace with administrative access
- SOAR platform or automation capability (Microsoft Sentinel, Splunk SOAR, Cortex XSOAR)
- Dedicated reporting mailbox for phishing submissions
- Email security gateway with message retraction capability
- Security awareness training platform for feedback loop

## Implementation Steps

### Step 1: Deploy Phishing Report Button
- Enable Microsoft built-in Report button via Security & Compliance Center
- Configure user reported settings: route to reporting mailbox and Microsoft
- For third-party: deploy KnowBe4 Phish Alert Button or Cofense Reporter
- Verify button appears in Outlook desktop, web, and mobile clients
- Configure report options: Report Phishing, Report Junk, Report Not Junk

### Step 2: Build Automated Triage Pipeline
- Configure reporting mailbox monitored by SOAR platform
- Auto-extract IOCs from reported emails: URLs, attachments, sender info, headers
- Submit URLs to VirusTotal, URLScan.io for reputation check
- Submit attachments to sandbox for dynamic analysis
- Check sender against known threat intelligence feeds
- Auto-classify: confirmed phishing, spam, simulation, legitimate

### Step 3: Implement Response Actions
- Confirmed phishing: auto-retract from all inboxes, block sender domain
- Confirmed spam: move to junk for all recipients
- Simulation email: mark as correctly reported, credit user
- Legitimate email: return to inbox, notify reporter
- Generate IOC report for threat intelligence team

### Step 4: Create Feedback Loop
- Send automated thank-you response to reporter within 5 minutes
- Include classification result when analysis completes
- Track reporter accuracy and engagement metrics
- Recognize top reporters in monthly security newsletter
- Feed reporting metrics into security awareness training program

### Step 5: Measure and Optimize
- Track mean time to triage (target: under 10 minutes automated)
- Monitor report volume trends and false positive rates
- Measure user reporting rate in phishing simulations
- Report on confirmed threats caught by user reports vs. gateway
- Optimize automation rules based on classification accuracy

## Tools & Resources
- **Microsoft Report Button**: Built-in Outlook phishing reporting
- **Cofense Reporter + Triage**: Enterprise phishing reporting and automated analysis
- **KnowBe4 Phish Alert Button**: Integrated reporting with simulation platform
- **Microsoft Sentinel**: SOAR automation for triage workflow
- **Proofpoint CLEAR**: Closed-loop email analysis and response

## Validation
- Report button visible and functional across all Outlook platforms
- Reported email arrives in dedicated mailbox within 60 seconds
- Automated triage classifies test phishing email correctly
- Auto-retraction removes confirmed phishing from all inboxes
- Reporter receives feedback notification with classification
- Metrics dashboard shows report volume and accuracy trends
