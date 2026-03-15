# Mimecast Targeted Threat Protection Deployment Template

## TTP Policy Configuration
| Module | Status | Mode | Scope |
|---|---|---|---|
| URL Protect | | Rewrite + Pre-delivery Hold | All inbound |
| Attachment Protect | | Dynamic sandbox | All inbound |
| Impersonation Protect (Default) | | Hit 3 | All inbound |
| Impersonation Protect (VIP) | | Hit 1 | VIP senders |
| Internal Email Protect | | URL + Attachment scan | Journaled |

## VIP List for Impersonation Protect
| Name | Title | Email | Domain |
|---|---|---|---|
| | CEO | | |
| | CFO | | |
| | CTO | | |
| | VP Finance | | |
| | General Counsel | | |

## Deployment Phases
- [ ] Phase 1: Configure URL Protect (pilot group)
- [ ] Phase 2: Configure Attachment Protect (pilot group)
- [ ] Phase 3: Configure Impersonation Protect with VIP list
- [ ] Phase 4: Enable Internal Email Protect via journaling
- [ ] Phase 5: Roll out to all users
- [ ] Phase 6: Tune policies based on false positive feedback

## Validation Checklist
- [ ] URL Protect rewrites links in test email
- [ ] URL Pre-delivery Hold stops weaponized link
- [ ] Attachment Protect sandboxes EICAR test file
- [ ] Impersonation Protect flags test BEC email
- [ ] Internal Email Protect detects test internal phishing
- [ ] Threat Dashboard shows detection metrics
