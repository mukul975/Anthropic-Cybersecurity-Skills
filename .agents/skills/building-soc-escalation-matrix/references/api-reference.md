# API Reference: SOC Escalation Matrix

## Priority Tiers
| Tier | Response SLA | Update SLA | Resolution SLA |
|------|-------------|------------|----------------|
| P1 Critical | 15 min | 1 hour | 4 hours |
| P2 High | 30 min | 2 hours | 8 hours |
| P3 Medium | 1 hour | 4 hours | 24 hours |
| P4 Low | 4 hours | 8 hours | 72 hours |

## Alert Categories
| Category | Default Priority | Auto-Escalate Triggers |
|----------|-----------------|----------------------|
| Malware | P2 | ransomware, wiper, apt |
| Phishing | P3 | executive_target, credential_harvested |
| Unauthorized Access | P2 | admin_account, domain_controller |
| Data Exfiltration | P1 | pii, financial, classified |
| Insider Threat | P2 | privileged_user, data_staging |

## Escalation Chain
```
P1: SOC Analyst → SOC Lead → IR Manager → CISO
P2: SOC Analyst → SOC Lead → IR Manager
P3: SOC Analyst → SOC Lead
P4: SOC Analyst
```

## Notification Channels
| Tier | Channels |
|------|----------|
| P1 | Slack #critical-alerts, PagerDuty, Email CISO, SMS |
| P2 | Slack #soc-alerts, PagerDuty, Email IR Manager |
| P3 | Slack #soc-alerts, Email SOC Lead |
| P4 | Slack #soc-triage |

## PagerDuty Incident API
```
POST https://events.pagerduty.com/v2/enqueue
{
  "routing_key": "SERVICE_KEY",
  "event_action": "trigger",
  "payload": {
    "summary": "P1 Alert: Data exfiltration detected",
    "severity": "critical",
    "source": "SOC SIEM"
  }
}
```

## Slack Webhook Notification
```
POST https://hooks.slack.com/services/T.../B.../xxx
{
  "channel": "#critical-alerts",
  "text": "P1 Incident: ..."
}
```

## Auto-Escalation Rules
| Condition | Action |
|-----------|--------|
| Response SLA exceeded | Escalate to next in chain |
| >= 3 correlated alerts | Increase priority by 1 |
| VIP user affected | Auto-escalate to P1 |
| Critical asset impacted | Increase priority by 1 |
