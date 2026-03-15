# API Reference: GoPhish Phishing Simulation

## Python gophish Library

### Constructor
```python
from gophish import Gophish
api = Gophish(api_key, host="https://localhost:3333", verify=False)
```

### Campaigns
```python
api.campaigns.get()                    # List all campaigns
api.campaigns.get(campaign_id=1)       # Get specific campaign
api.campaigns.post(campaign)           # Create and launch campaign
api.campaigns.summary(campaign_id=1)   # Get campaign summary
api.campaigns.delete(campaign_id=1)    # Delete campaign
```

### Templates
```python
api.templates.get()                    # List templates
api.templates.post(template)           # Create template
Template(name="...", subject="...", html="<html>...</html>", text="...")
```

### Groups
```python
api.groups.get()                       # List groups
api.groups.post(group)                 # Create group
Group(name="...", targets=[User(first_name="", last_name="", email="")])
```

### SMTP Profiles
```python
api.smtp.get()
api.smtp.post(smtp)
SMTP(name="...", from_address="...", host="smtp:587", username="", password="")
```

### Landing Pages
```python
api.pages.get()
api.pages.post(page)
Page(name="...", html="...", capture_credentials=True, redirect_url="")
```

## Campaign Model
```python
Campaign(
    name="Q1 Test",
    template=Template(name="Existing Template"),
    page=Page(name="Existing Page"),
    smtp=SMTP(name="Existing Profile"),
    groups=[Group(name="Existing Group")],
    url="https://phish.example.com",
    launch_date="2024-01-15T09:00:00+00:00"  # ISO8601
)
```

## Result Statuses
| Status | Meaning |
|--------|---------|
| Email Sent | Email delivered |
| Email Opened | Tracking pixel loaded |
| Clicked Link | Phishing URL clicked |
| Submitted Data | Credentials entered |
| Reported | User reported phishing |
