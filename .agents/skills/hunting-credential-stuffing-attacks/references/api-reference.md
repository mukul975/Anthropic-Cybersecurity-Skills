# API Reference: Hunting Credential Stuffing Attacks

## Pandas Authentication Log Analysis

```python
import pandas as pd

df = pd.read_csv("auth_logs.csv", parse_dates=["timestamp"])
# Columns: timestamp, username, source_ip, status, user_agent

# Failed logins per IP
df[df["status"] == "failed"].groupby("source_ip")["username"].nunique()

# Failed logins per account (distributed attack)
df[df["status"] == "failed"].groupby("username")["source_ip"].nunique()

# Login velocity (attempts per minute)
df.set_index("timestamp").resample("1min").count()
```

## Detection Thresholds

| Indicator | Threshold | Attack Type |
|-----------|-----------|-------------|
| Unique accounts per IP | > 20 | Credential stuffing |
| Unique IPs per account | > 5 | Distributed attack |
| Attempts/account ratio | ~1 | Password spray |
| Success after N failures | N > 5 | Account compromise |
| Single UA > 30% of failures | > 50 events | Automated tool |

## Splunk SPL Patterns

```spl
--- Credential stuffing detection
index=auth status=failed
| stats dc(username) as accounts, count by src_ip
| where accounts > 20

--- Password spray detection
index=auth status=failed
| stats dc(username) as accounts, count by src_ip
| where accounts > 10 AND count <= accounts * 3
```

### References

- OWASP Credential Stuffing: https://owasp.org/www-community/attacks/Credential_stuffing
- Splunk auth analysis: https://docs.splunk.com/Documentation/ES
- pandas: https://pandas.pydata.org/docs/
