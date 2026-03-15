# Standards and References - Vulnerability SLA Breach Alerting

## Primary Standards

### NIST SP 800-40 Rev 4
- **Title**: Guide to Enterprise Patch Management Planning
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-40/rev-4/final
- **Relevance**: Defines organizational patch management lifecycle and remediation timelines

### CISA Binding Operational Directive 22-01
- **Title**: Reducing the Significant Risk of Known Exploited Vulnerabilities
- **URL**: https://www.cisa.gov/binding-operational-directive-22-01
- **SLA Mandate**: Federal agencies must remediate KEV-listed vulnerabilities within specified timeframes (typically 14 days for new additions)

### PCI DSS v4.0 Requirement 6.3
- **Title**: Security Vulnerabilities Are Identified and Addressed
- **URL**: https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf
- **SLA Requirement**: Critical and high-severity vulnerabilities must be patched within 30 days of release; risk-ranked approach for all others

### SOC 2 Type II - CC7.1
- **Title**: Detection and Monitoring of Security Events
- **Relevance**: Requires evidence of vulnerability management program with defined remediation timelines and tracking

### ISO 27001:2022 - Control A.8.8
- **Title**: Management of Technical Vulnerabilities
- **Relevance**: Requires timely identification and remediation of technical vulnerabilities with defined response timelines

## Industry SLA Benchmarks

### SANS Vulnerability Management Maturity
- **Critical**: 24-48 hours
- **High**: 7-30 days
- **Medium**: 30-90 days
- **Low**: 90-180 days

### CIS Controls v8 - Control 7
- **Title**: Continuous Vulnerability Management
- **URL**: https://www.cisecurity.org/controls/continuous-vulnerability-management
- **Implementation Group 1**: Remediate detected vulnerabilities monthly
- **Implementation Group 2**: Automated remediation tracking with SLA enforcement
- **Implementation Group 3**: Real-time SLA monitoring with automated escalation

## Integration APIs

### PagerDuty Events API v2
- **URL**: https://developer.pagerduty.com/api-reference/a7d81b0e9200f-send-an-event-to-pager-duty
- **Endpoint**: https://events.pagerduty.com/v2/enqueue

### Slack Incoming Webhooks
- **URL**: https://api.slack.com/messaging/webhooks
- **Rate Limit**: 1 message per second per webhook

### Microsoft Teams Incoming Webhook
- **URL**: https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook

### Jira REST API
- **URL**: https://developer.atlassian.com/cloud/jira/platform/rest/v3/
- **Relevance**: Create and track remediation tickets with SLA metadata
