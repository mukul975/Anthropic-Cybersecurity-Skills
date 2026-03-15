# BEC Detection and Response Template

## VIP Protection List
| Name | Title | Email Domain | Protected Since |
|---|---|---|---|
| | CEO | | |
| | CFO | | |
| | CTO | | |

## BEC Detection Rules Deployed
| Rule | Condition | Action | Status |
|---|---|---|---|
| VIP name spoofing | External email with VIP display name | Quarantine + Alert | Active |
| Financial + Urgency | Wire transfer keywords + urgency | Tag + Alert | Active |
| Reply-To mismatch | Reply-To domain differs from From | Tag + Log | Active |
| Gift card request | Gift card keywords from "executive" | Quarantine | Active |
| Vendor payment change | Bank detail change language | Tag + Finance alert | Active |

## Financial Controls
- [ ] Dual authorization for transfers > $[threshold]
- [ ] Out-of-band verification for payment detail changes
- [ ] Vendor payment change requires callback on known number
- [ ] Gift card purchases require in-person manager approval

## BEC Incident Response Contacts
| Role | Name | Phone | Email |
|---|---|---|---|
| SOC Lead | | | |
| Finance Controller | | | |
| Bank Fraud Department | | | |
| FBI IC3 (filing) | N/A | N/A | ic3.gov |
| Legal Counsel | | | |
