# Malware Incident Communication Workflows

## Workflow 1: Initial Notification Chain

```
START: Malware Incident Confirmed
  |
  v
[Classify Severity]
  |-- P1: Critical (ransomware, wiper, widespread)
  |-- P2: High (targeted, data exfiltration)
  |-- P3: Medium (contained infection)
  |-- P4: Low (single endpoint, quickly resolved)
  |
  v
[Send Initial Notification]
  |-- Use appropriate template for severity
  |-- Send via secure out-of-band channel for P1/P2
  |-- Include: What happened, current impact, actions taken
  |
  v
[Establish Communication Cadence]
  |-- P1: Every 2 hours or on significant changes
  |-- P2: Every 4 hours
  |-- P3: Every 8 hours
  |-- P4: Daily summary
  |
  v
[Track Notifications Sent]
  |-- Log all communications
  |-- Record recipients and timestamps
  |-- Document approval chain
  |
  v
END: Communication Cadence Established
```

## Workflow 2: Regulatory Notification Decision

```
START: Incident Scope Determined
  |
  v
[Personal Data Involved?]
  |-- No --> Document decision, continue monitoring
  |-- Yes --> Assess regulatory requirements
  |
  v
[Determine Applicable Regulations]
  |-- GDPR: EU resident data?
  |-- HIPAA: Protected health information?
  |-- PCI DSS: Payment card data?
  |-- State laws: US state breach notification?
  |-- SEC: Material to publicly traded company?
  |
  v
[Prepare Regulatory Notification]
  |-- Legal review of notification content
  |-- Determine notification timeline
  |-- Identify regulatory contact points
  |
  v
[Submit Notification]
  |-- Send within required timeframe
  |-- Document submission confirmation
  |-- Track response from regulators
  |
  v
END: Regulatory Obligations Met
```

## Workflow 3: Customer Communication

```
START: Customer Notification Required
  |
  v
[Draft Customer Notification]
  |-- Use customer notification template
  |-- Include: What, when, impact, actions, resources
  |-- Avoid technical jargon
  |
  v
[Legal and PR Review]
  |-- Legal counsel approval
  |-- PR/Communications review
  |-- Executive sign-off
  |
  v
[Prepare Support Resources]
  |-- Set up dedicated hotline
  |-- Create FAQ page
  |-- Brief customer support team
  |-- Prepare credit monitoring (if applicable)
  |
  v
[Send Notification]
  |-- Email to affected customers
  |-- Website notice
  |-- Media statement (if needed)
  |
  v
END: Customer Notification Complete
```
