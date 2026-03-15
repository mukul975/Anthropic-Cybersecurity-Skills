# API Reference: SOC Metrics and KPI Tracking Agent

## Overview

Automates collection of SOC performance metrics (MTTD, MTTR, alert quality, analyst productivity) from Splunk ES and generates consolidated reports.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | Splunk REST API communication |

## CLI Usage

```bash
python agent.py --splunk-url https://splunk:8089 --username admin --password <pass> --output report.json
```

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--splunk-url` | No | `https://localhost:8089` | Splunk management URL |
| `--username` | No | `admin` | Splunk username |
| `--password` | Yes | - | Splunk password |
| `--output` | No | `soc_metrics_report.json` | Output file path |

## Key Functions

### `authenticate_splunk(base_url, username, password)`
Authenticates to the Splunk REST API and returns authorization headers with session key.

### `run_splunk_search(base_url, headers, query, earliest, latest)`
Executes a Splunk SPL search, polls for completion, and returns parsed JSON results.

### `collect_mttd_metrics(base_url, headers)`
Queries Splunk ES notable events to calculate Mean Time to Detect by urgency level.

### `collect_mttr_metrics(base_url, headers)`
Queries resolved incidents to calculate Mean Time to Respond by urgency level.

### `collect_alert_quality(base_url, headers)`
Calculates true positive rate, false positive rate, and signal-to-noise ratio.

### `collect_analyst_productivity(base_url, headers)`
Measures per-analyst alerts resolved per day and average triage time.

### `generate_report(mttd, mttr, quality, productivity)`
Formats all collected metrics into a human-readable SOC performance report.

## Output Schema

```json
{
  "generated_at": "ISO-8601 timestamp",
  "mttd_metrics": [{"urgency": "...", "avg_mttd_min": "..."}],
  "mttr_metrics": [{"urgency": "...", "avg_mttr_hours": "..."}],
  "alert_quality": [{"total": "...", "tp_rate": "...", "fp_rate": "..."}],
  "analyst_productivity": [{"owner": "...", "alerts_per_day": "..."}]
}
```

## Splunk API Endpoints Used

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/services/auth/login` | POST | Authentication |
| `/services/search/jobs` | POST | Create search job |
| `/services/search/jobs/{sid}` | GET | Poll search status |
| `/services/search/jobs/{sid}/results` | GET | Retrieve results |
