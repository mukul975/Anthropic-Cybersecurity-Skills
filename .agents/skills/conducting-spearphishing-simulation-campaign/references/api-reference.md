# Spearphishing Simulation Campaign — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| requests | `pip install requests` | GoPhish REST API client |
| gophish | `pip install gophish` | Official GoPhish Python SDK |
| jinja2 | `pip install Jinja2` | Email template rendering |

## GoPhish API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/campaigns/` | Launch new phishing campaign |
| GET | `/api/campaigns/{id}/summary` | Campaign results summary |
| GET | `/api/campaigns/{id}/results` | Detailed per-target results |
| POST | `/api/templates/` | Create email template |
| POST | `/api/pages/` | Create credential capture landing page |
| POST | `/api/groups/` | Create target recipient group |

## GoPhish Template Variables

| Variable | Description |
|----------|-------------|
| `{{.FirstName}}` | Target's first name |
| `{{.LastName}}` | Target's last name |
| `{{.Email}}` | Target's email address |
| `{{.Position}}` | Target's job title |
| `{{.From}}` | Sender display name |
| `{{.URL}}` | Tracking/phishing link |

## Campaign Metrics

| Metric | Description | Industry Avg |
|--------|-------------|-------------|
| Open Rate | Percentage who opened email | 30-40% |
| Click Rate | Percentage who clicked link | 10-20% |
| Submit Rate | Percentage who entered data | 5-10% |
| Report Rate | Percentage who reported to IT | 5-15% |

## External References

- [GoPhish User Guide](https://docs.getgophish.com/)
- [GoPhish API Docs](https://docs.getgophish.com/api-documentation/)
- [MITRE T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
