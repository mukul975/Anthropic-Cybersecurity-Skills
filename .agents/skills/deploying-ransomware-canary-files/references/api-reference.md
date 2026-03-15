# API Reference: Deploying Ransomware Canary Files

## Canary File Deployment

| Function | Parameters | Returns |
|----------|-----------|---------|
| `deploy_canary_files(target_dirs, custom_files)` | List of directories, optional custom file dict | Manifest with deployed file paths and hashes |
| `compute_sha256(filepath)` | File path string | SHA-256 hex digest |
| `compute_entropy(filepath)` | File path string | Shannon entropy float (0-8) |

## Monitoring Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `start_monitoring(manifest_path, config)` | Path to manifest JSON, alert config dict | Blocks until interrupted |
| `verify_canary_integrity(manifest_path)` | Path to manifest JSON | Dict with intact/modified/missing counts |
| `simulate_ransomware_test(manifest_path)` | Path to manifest JSON | List of test results |

## CanaryFileHandler Events

| Event | Handler Method | Trigger |
|-------|---------------|---------|
| File modified | `on_modified(event)` | Content change detected |
| File deleted | `on_deleted(event)` | Canary file removed |
| File renamed | `on_moved(event)` | Canary file renamed or moved |
| New file created | `on_created(event)` | Ransom note detection in monitored dirs |

## Alert Channels

| Channel | Function | Required Config |
|---------|----------|-----------------|
| Slack | `send_slack_alert(data, webhook_url)` | `slack_webhook` URL |
| Email | `send_email_alert(data, host, port, sender, recipients)` | SMTP server details |
| Syslog | `send_syslog_alert(data, server, port)` | Syslog server address |
| File | Automatic | Writes to `canary_alerts.jsonl` |

## Ransomware Extension Detection

| Extensions Monitored |
|---------------------|
| `.encrypted`, `.locked`, `.lockbit`, `.crypt`, `.enc` |
| `.ransom`, `.pay`, `.aes`, `.rsa`, `.cry` |
| `.ryk`, `.revil`, `.conti`, `.hive`, `.black`, `.basta` |

## CLI Usage

```bash
# Deploy canary files
python agent.py --action deploy --dirs /srv/shares /home/admin/Documents

# Monitor canary files with Slack alerts
python agent.py --action monitor --slack-webhook https://hooks.slack.com/...

# Verify canary file integrity
python agent.py --action verify

# Test detection pipeline
python agent.py --action test
```

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `watchdog` | >=3.0 | Filesystem event monitoring |
| `requests` | >=2.28 | Slack webhook integration |
| `psutil` | >=5.9 | Process information gathering |
| `hashlib` | stdlib | SHA-256 file hashing |
| `smtplib` | stdlib | SMTP email alerts |

## References

- Elastic Security Labs: Ransomware Canary Files: https://www.elastic.co/security-labs/ransomware-in-the-honeypot-how-we-capture-keys
- Huntress Ransomware Canaries: https://support.huntress.io/hc/en-us/articles/4404005167763
- Python Watchdog Documentation: https://python-watchdog.readthedocs.io/
- CISA #StopRansomware Guide: https://www.cisa.gov/stopransomware/ransomware-guide
