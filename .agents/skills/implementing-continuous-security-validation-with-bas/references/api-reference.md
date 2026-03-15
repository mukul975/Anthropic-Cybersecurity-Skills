# API Reference: Breach and Attack Simulation Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP client for SIEM detection validation |

## CLI Usage

```bash
python scripts/agent.py \
  --target 10.0.1.50 \
  --siem-url https://siem.example.com \
  --siem-key YOUR_KEY \
  --output-dir /reports/
```

## Functions

### `simulate_technique(technique, target) -> dict`
Simulates a MITRE ATT&CK technique and records detection/blocked status.

### `check_siem_detection(siem_url, api_key, technique_id, time_window) -> dict`
Queries SIEM API for alerts matching the simulated technique within time window.

### `compute_detection_coverage(results) -> dict`
Calculates overall detection rate and per-tactic coverage breakdown.

### `generate_report(target, siem_url, siem_key) -> dict`
Runs 7 ATT&CK technique simulations and generates detection gap report.

## ATT&CK Techniques Tested

| ID | Name | Tactic |
|----|------|--------|
| T1566.001 | Spearphishing Attachment | Initial Access |
| T1059.001 | PowerShell | Execution |
| T1003.001 | LSASS Memory | Credential Access |
| T1021.002 | SMB Admin Shares | Lateral Movement |
| T1486 | Data Encrypted for Impact | Impact |
| T1071.001 | Web Protocols | C2 |
| T1048.003 | Exfiltration Over Unencrypted | Exfiltration |

## Output Schema

```json
{
  "coverage": {"total_tests": 7, "detected": 5, "missed": 2, "detection_rate_pct": 71.4},
  "gaps": [{"technique_id": "T1003.001", "technique_name": "LSASS Memory"}],
  "recommendations": ["Create detection rule for T1003.001"]
}
```
