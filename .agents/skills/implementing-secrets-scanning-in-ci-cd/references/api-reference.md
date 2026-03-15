# Secrets Scanning API Reference

## Gitleaks CLI

### Subcommands
```bash
gitleaks git    # Scan git repositories
gitleaks dir    # Scan directories or files
gitleaks stdin  # Detect secrets from stdin
```

### Key Flags
| Flag | Description |
|------|-------------|
| `--source, -s` | Path to source directory or repository |
| `--config, -c` | Path to .gitleaks.toml config file |
| `--report-format, -f` | Output format: json, csv, junit, sarif, template |
| `--report-path, -r` | File path to write report |
| `--exit-code` | Exit code when leaks found (default: 1) |
| `--redact` | Redact secrets from output (0-100%, default: 100) |
| `--baseline-path, -b` | Path to baseline report to ignore known findings |
| `--no-banner` | Suppress banner output |
| `--verbose, -v` | Show verbose scan details |
| `--log-level, -l` | Log level: trace, debug, info, warn, error, fatal |
| `--max-target-megabytes` | Skip files larger than specified MB |
| `--enable-rule` | Only enable specific rule IDs |
| `--gitleaks-ignore-path, -i` | Path to .gitleaksignore file |

### Pre-commit Hook
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks
```

### Protect Staged Files
```bash
gitleaks protect --staged --report-format json --report-path staged-report.json
```

## TruffleHog CLI

### Subcommands
```bash
trufflehog git <repo-url>            # Scan git repository
trufflehog filesystem <path>         # Scan local filesystem
trufflehog github --org=<org>        # Scan GitHub org
trufflehog gitlab --token=<token>    # Scan GitLab instance
trufflehog s3 --bucket=<name>        # Scan S3 bucket
trufflehog docker --image=<img>      # Scan Docker image
```

### Key Flags
| Flag | Description |
|------|-------------|
| `--json, -j` | Output in JSON format (one object per line) |
| `--no-verification` | Skip live secret verification |
| `--concurrency` | Number of concurrent workers (default: 20) |
| `--results` | Filter: verified, unknown, unverified, filtered_unverified |
| `--force-skip-binaries` | Skip binary files during scan |
| `--force-skip-archives` | Skip archive files during scan |
| `--include-paths` | Path to file with include path patterns |
| `--exclude-paths` | Path to file with exclude path patterns |
| `--log-level` | Verbosity: 0 (info) to 5 (trace) |

## GitHub Secret Scanning API

### List Alerts
```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://api.github.com/repos/{owner}/{repo}/secret-scanning/alerts
```

### Update Alert State
```bash
curl -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  https://api.github.com/repos/{owner}/{repo}/secret-scanning/alerts/{alert_number} \
  -d '{"state": "resolved", "resolution": "revoked"}'
```

## GitHub Actions Integration

```yaml
- name: Gitleaks Scan
  uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

- name: TruffleHog Scan
  uses: trufflesecurity/trufflehog@main
  with:
    extra_args: --results verified,unknown
```
