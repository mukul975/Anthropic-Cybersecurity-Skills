# API Reference — Performing False Positive Reduction in SIEM

## Libraries Used
- **csv**: Parse SIEM alert export files (Splunk, QRadar, Sentinel)
- **collections.Counter**: Aggregate alert patterns by rule, source, severity

## CLI Interface
```
python agent.py analyze --csv alerts.csv [--threshold 5]
python agent.py tune --csv alerts.csv
python agent.py simulate --csv alerts.csv [--disable-rules "Rule A" "Rule B"] [--whitelist-sources 10.0.0.1]
```

## Core Functions

### `analyze_alerts(csv_file, threshold)` — Identify false positive patterns
Parses alert CSV, calculates per-rule FP rates, identifies noisy rules exceeding threshold.
Returns: total alerts, FP count/rate, noisy rules ranked by FP rate, top FP sources.

### `generate_tuning_recommendations(csv_file)` — Create tuning action plan
Maps FP rates to actions: DISABLE (>=90%), ADD_WHITELIST (>=70%), TUNE_THRESHOLD (>=50%), REVIEW (<50%).

### `simulate_tuning_impact(csv_file, rules_to_disable, sources_to_whitelist)` — Model tuning changes
Calculates alert volume reduction and new FP rate after applying proposed rule disables and source whitelists.

## Expected CSV Columns
- `rule_name` / `Rule` / `alert_name`: Detection rule identifier
- `src_ip` / `source_ip` / `Source`: Source IP address
- `status` / `Status` / `disposition`: Alert disposition (false_positive, fp, closed_fp, benign)
- `severity` / `Severity`: Alert severity level

## FP Status Keywords
`false_positive`, `fp`, `closed_fp`, `benign`

## Dependencies
No external packages — Python standard library only.
