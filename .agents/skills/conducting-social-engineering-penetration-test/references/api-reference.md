# Social Engineering Penetration Test — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| requests | `pip install requests` | GoPhish REST API client |
| gophish | `pip install gophish` | Official GoPhish Python client |

## GoPhish API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/campaigns/` | List all campaigns |
| GET | `/api/campaigns/{id}/results` | Campaign results and metrics |
| POST | `/api/campaigns/` | Create new campaign |
| POST | `/api/templates/` | Create email template |
| POST | `/api/groups/` | Create target group |
| POST | `/api/smtp/` | Create sending profile |
| POST | `/api/pages/` | Create landing page |

## Campaign Metrics

| Metric | Formula |
|--------|---------|
| Open Rate | emails_opened / emails_sent x 100 |
| Click Rate | links_clicked / emails_sent x 100 |
| Submit Rate | data_submitted / emails_sent x 100 |
| Report Rate | reported / emails_sent x 100 |

## Social Engineering Vectors

| Vector | Tools |
|--------|-------|
| Email Phishing | GoPhish, King Phisher |
| Vishing | Pretext scripts, VoIP tools |
| Physical | Badge cloning, tailgating |
| USB Drops | Rubber Ducky, USB armory |

## External References

- [GoPhish API Documentation](https://docs.getgophish.com/api-documentation/)
- [SANS Social Engineering Framework](https://www.social-engineer.org/framework/)
- [MITRE ATT&CK Phishing T1566](https://attack.mitre.org/techniques/T1566/)
