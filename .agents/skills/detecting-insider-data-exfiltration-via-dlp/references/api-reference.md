# API Reference: Detecting Insider Data Exfiltration via DLP

## Pandas Behavioral Analytics

```python
import pandas as pd

df = pd.read_csv("activity.csv", parse_dates=["timestamp"])
# Columns: timestamp, user, action, file_path, bytes_transferred, destination

# Daily volume baseline per user
daily = df.groupby(["user", df["timestamp"].dt.date])["bytes_transferred"].sum()
baseline = daily.groupby("user").agg(["mean", "std"])

# Off-hours detection
df["hour"] = df["timestamp"].dt.hour
off_hours = df[(df["hour"] < 6) | (df["hour"] >= 22)]

# Bulk download detection
df.set_index("timestamp").groupby("user").resample("1h").size()
```

## Exfiltration Indicators

| Indicator | Threshold | Severity |
|-----------|-----------|----------|
| Volume > 3x baseline | Per user daily avg | HIGH |
| Volume > 5x baseline | Per user daily avg | CRITICAL |
| Off-hours events | > 10 per user | HIGH |
| Bulk downloads | > 50 files/hour | CRITICAL |
| USB transfers | Any volume | HIGH |
| Sensitive file access | Pattern match | HIGH |

## Sensitive File Patterns

```python
patterns = [
    r"\.pem$", r"\.key$", r"\.env$",
    r"credentials", r"password", r"\.kdbx$",
    r"financial", r"payroll", r"customer.*data"
]
```

## Microsoft Purview DLP API

```python
import requests
headers = {"Authorization": "Bearer <token>"}
resp = requests.get(
    "https://graph.microsoft.com/v1.0/security/alerts_v2",
    headers=headers,
    params={"$filter": "category eq 'DataLossPrevention'"}
)
```

### References

- Microsoft Purview DLP: https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp
- pandas: https://pandas.pydata.org/docs/
- UEBA: https://www.gartner.com/en/information-technology/glossary/user-entity-behavior-analytics
