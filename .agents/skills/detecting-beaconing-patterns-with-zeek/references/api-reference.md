# API Reference: Detecting Beaconing Patterns with Zeek

## ZAT (Zeek Analysis Tools)

```python
from zat.log_to_dataframe import LogToDataFrame
from zat import zeek_log_reader
from zat.utils import dataframe_to_matrix

# Load conn.log into DataFrame
log_to_df = LogToDataFrame()
conn_df = log_to_df.create_dataframe('/path/to/conn.log')

# Select specific columns
conn_df = log_to_df.create_dataframe('conn.log',
    usecols=['id.orig_h', 'id.resp_h', 'id.resp_p', 'ts', 'duration'])

# Read rows as dicts (streaming)
reader = zeek_log_reader.ZeekLogReader('conn.log')
for row in reader.readrows():
    print(row)

# Tail mode (live monitoring)
reader = zeek_log_reader.ZeekLogReader('conn.log', tail=True)
for row in reader.readrows():
    process(row)

# Convert to matrix for ML
to_matrix = dataframe_to_matrix.DataFrameToMatrix()
matrix = to_matrix.fit_transform(conn_df[features])
```

## Beaconing Detection Math

```python
import numpy as np

intervals = times.diff().dt.total_seconds().dropna().values
std_dev = np.std(intervals)
mean_val = np.mean(intervals)
cv = std_dev / mean_val  # Coefficient of Variation
# cv < 0.3 = likely beacon (low jitter relative to interval)
```

## Key Zeek Log Fields

| Log | Key Fields |
|-----|-----------|
| conn.log | `id.orig_h`, `id.resp_h`, `id.resp_p`, `ts`, `duration`, `orig_bytes` |
| dns.log | `id.orig_h`, `query`, `qtype_name`, `answers`, `ts` |
| ssl.log | `id.orig_h`, `server_name`, `ja3`, `ja3s`, `ts` |

## Anomaly Detection with ZAT + scikit-learn

```python
from sklearn.ensemble import IsolationForest
odd_clf = IsolationForest(contamination=0.35)
odd_clf.fit(zeek_matrix)
anomalies = conn_df[odd_clf.predict(zeek_matrix) == -1]
```

### References

- ZAT: https://github.com/SuperCowPowers/zat
- ZAT examples: https://supercowpowers.github.io/zat/examples.html
- zat on PyPI: https://pypi.org/project/zat/
