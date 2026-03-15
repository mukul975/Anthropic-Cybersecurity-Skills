# Phishing Simulation Campaign Plan Template

## Campaign Information
- **Campaign Name**: [e.g., Q1-2026 Password Reset Simulation]
- **Campaign Owner**: [Security Awareness Team Lead]
- **Authorization Date**: [YYYY-MM-DD]
- **Authorized By**: [CISO / VP of Security]
- **Campaign Period**: [Start Date] to [End Date]

## Authorization Checklist
- [ ] Written authorization from executive management
- [ ] Legal review completed
- [ ] HR notification and approval
- [ ] IT operations notified (email gateway whitelisting)
- [ ] Privacy impact assessment completed
- [ ] Data handling procedures documented

## Campaign Objectives
| Objective | Target Metric |
|---|---|
| Measure click susceptibility | Click rate < 10% |
| Measure credential submission | Submit rate < 5% |
| Measure reporting behavior | Report rate > 50% |
| Identify high-risk departments | Department-level breakdown |

## Scenario Design
- **Pretext**: [Password reset / IT maintenance / HR policy update]
- **Sender**: [it-support@company-domain.com]
- **Subject Line**: [Urgent: Password Expiration Notice]
- **Call to Action**: [Click link to reset password]
- **Landing Page**: [Fake login page mimicking internal portal]
- **Post-Interaction**: [Redirect to training page]

## Target Audience
| Group | Count | Department | Difficulty Level |
|---|---|---|---|
| Group A | | | |
| Group B | | | |

## GoPhish Configuration
### Sending Profile
```json
{
  "name": "Campaign SMTP Profile",
  "host": "smtp.server.com:587",
  "from_address": "IT Support <it-support@domain.com>",
  "username": "service-account",
  "ignore_cert_errors": false
}
```

### Email Template Variables
- `{{.FirstName}}` - Recipient first name
- `{{.LastName}}` - Recipient last name
- `{{.Position}}` - Recipient job title
- `{{.Email}}` - Recipient email
- `{{.From}}` - Sender address
- `{{.URL}}` - Phishing URL (tracked)
- `{{.Tracker}}` - Tracking pixel
- `{{.TrackingURL}}` - Full tracking URL
- `{{.RId}}` - Unique recipient ID

## Success Criteria
| Metric | Poor | Fair | Good | Excellent |
|---|---|---|---|---|
| Click Rate | >25% | 15-25% | 5-15% | <5% |
| Submit Rate | >15% | 8-15% | 3-8% | <3% |
| Report Rate | <10% | 10-30% | 30-60% | >60% |

## Post-Campaign Actions
- [ ] Generate campaign report
- [ ] Force password reset for credential submitters
- [ ] Send targeted training to clickers
- [ ] Send positive reinforcement to reporters
- [ ] Present aggregate findings to leadership
- [ ] Update training curriculum based on results
- [ ] Plan next campaign with adjusted difficulty
