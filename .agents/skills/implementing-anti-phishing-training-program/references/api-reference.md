# API Reference: Implementing Anti-Phishing Training Program

## KnowBe4 API

```python
import requests

headers = {"Authorization": "Bearer <API_KEY>"}
base = "https://us.api.knowbe4.com/v1"

# List users
users = requests.get(f"{base}/users", headers=headers).json()

# Get phishing campaign results
campaigns = requests.get(f"{base}/phishing/campaigns", headers=headers).json()

# Get training enrollments
enrollments = requests.get(f"{base}/training/enrollments", headers=headers).json()
```

## Key Metrics

| Metric | Target | Calculation |
|--------|--------|-------------|
| Click Rate | < 15% | Clicked / Total Recipients |
| Submit Rate | < 5% | Submitted Creds / Total |
| Report Rate | > 70% | Reported / Total Recipients |
| Completion Rate | > 90% | Completed / Enrolled |

## pandas Simulation Analysis

```python
import pandas as pd
df = pd.read_csv("simulation_results.csv", parse_dates=["timestamp"])

# Department click rates
dept = df.groupby("department").agg(
    click_rate=("clicked", "mean"),
    report_rate=("reported", "mean"),
)

# Monthly trend
monthly = df.set_index("timestamp").resample("M")["clicked"].mean()
```

## SANS Maturity Model Levels

| Level | Name | Description |
|-------|------|-------------|
| 1 | Non-existent | No program |
| 2 | Compliance | Annual checkbox |
| 3 | Awareness | Engaging, regular |
| 4 | Sustainment | Culture change |
| 5 | Metrics | Risk-based optimization |

## GoPhish (Open-Source Alternative)

```bash
# Launch campaign
curl -X POST https://gophish:3333/api/campaigns \
  -H "Authorization: <API_KEY>" \
  -d '{"name":"Q1-2025","template":{"name":"IT Alert"},"groups":[{"name":"All Staff"}]}'
```

### References

- KnowBe4 API: https://developer.knowbe4.com/
- GoPhish: https://getgophish.com/
- SANS Security Awareness: https://www.sans.org/security-awareness-training/
