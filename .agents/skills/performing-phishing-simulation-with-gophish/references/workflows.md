# Workflows: Phishing Simulation with GoPhish

## Workflow 1: End-to-End Campaign Execution

```
Phase 1: Authorization & Planning
  |
  +-- Obtain written authorization from management
  +-- Define campaign objectives and success criteria
  +-- Select target groups (by department, role, risk level)
  +-- Choose phishing scenario (credential harvest, link click, attachment)
  +-- Set campaign timeline
  |
Phase 2: Infrastructure Setup
  |
  +-- Deploy GoPhish server (Docker or bare metal)
  +-- Configure SSL/TLS certificate for landing page
  +-- Set up SMTP sending profile
  +-- Whitelist GoPhish IP in email gateway
  +-- Configure DNS for phishing domain
  +-- Test email deliverability
  |
Phase 3: Content Creation
  |
  +-- Design email template with GoPhish variables
  +-- Create or clone landing page
  +-- Set up redirect to training page
  +-- Configure credential capture (if authorized)
  +-- Test with internal team first
  |
Phase 4: Target Preparation
  |
  +-- Import user list (CSV: first,last,email,position)
  +-- Segment into groups if needed
  +-- Verify email addresses are valid
  |
Phase 5: Campaign Launch
  |
  +-- Set send schedule (staggered over hours/days)
  +-- Launch campaign
  +-- Monitor real-time dashboard
  +-- Handle any delivery issues
  |
Phase 6: Analysis & Reporting
  |
  +-- Wait for campaign duration to complete
  +-- Export results via API
  +-- Generate analytics report
  +-- Present findings to stakeholders
  +-- Identify high-risk groups for targeted training
```

## Workflow 2: Progressive Difficulty Model

```
Quarter 1: Easy to Detect
  +-- Generic greeting, spelling errors
  +-- Unrelated external domain
  +-- Obvious call to action
  +-- Expected: < 20% click rate
  |
Quarter 2: Moderate Difficulty
  +-- Personalized with name/department
  +-- Look-alike domain
  +-- Relevant pretext (IT maintenance, HR policy)
  +-- Expected: < 15% click rate
  |
Quarter 3: Difficult
  +-- Highly targeted content
  +-- Convincing sender spoofing
  +-- Timely pretext (tax season, annual review)
  +-- Expected: < 10% click rate
  |
Quarter 4: Advanced
  +-- Spear-phishing with OSINT
  +-- Multi-step pretext
  +-- Mimics real vendor communication
  +-- Expected: < 5% click rate
```

## Workflow 3: Automated Campaign via API

```
[Python Script] --> GoPhish API
  |
  +-- POST /api/smtp/ (create sending profile)
  +-- POST /api/templates/ (create email template)
  +-- POST /api/pages/ (create landing page)
  +-- POST /api/groups/ (import target users)
  +-- POST /api/campaigns/ (launch campaign)
  |
  [Wait for campaign duration]
  |
  +-- GET /api/campaigns/{id}/summary
  +-- GET /api/campaigns/{id}/results
  |
  [Generate report with metrics]
  |
  +-- Calculate: open rate, click rate, submit rate, report rate
  +-- Compare against baseline and industry benchmarks
  +-- Export to PDF/HTML report
```

## Workflow 4: Post-Campaign Remediation

```
Campaign Results Available
  |
  v
[Identify users who submitted credentials]
  |
  +-- Immediately: Force password reset
  +-- Within 24h: Send targeted training content
  +-- Within 1 week: Manager notification (aggregate only)
  |
  v
[Identify users who clicked but did not submit]
  |
  +-- Send phishing awareness micro-training
  +-- Include specific red flags they missed
  |
  v
[Identify users who reported the email]
  |
  +-- Send positive reinforcement
  +-- Recognize in security champions program
  |
  v
[Aggregate department-level metrics]
  |
  +-- Present to leadership
  +-- Identify highest-risk departments
  +-- Plan targeted training interventions
  +-- Schedule next campaign
```
