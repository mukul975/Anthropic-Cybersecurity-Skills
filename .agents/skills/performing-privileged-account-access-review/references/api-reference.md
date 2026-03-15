# Privileged Account Access Review — API Reference

## CSV Input Format

The agent consumes a CSV file with these columns:

| Column | Type | Description |
|--------|------|-------------|
| `username` | string | Account identifier (SAMAccountName or UPN) |
| `owner` | string | Assigned account owner / manager |
| `roles` | string | Semicolon-separated privilege roles |
| `last_used` | string | ISO date `YYYY-MM-DD` of last interactive logon |
| `last_certified` | string | ISO date `YYYY-MM-DD` of most recent access review |
| `account_type` | string | `human`, `service`, or `shared` |

## Checks Performed

### Stale Account Detection
Flags accounts whose `last_used` date exceeds a configurable threshold (default 90 days). Accounts without a `last_used` value are automatically flagged as high severity.

### Shared Account Detection
Matches `username` against common shared-account patterns: `admin`, `root`, `service`, `svc_`, `shared`, `generic`, `temp`. Flags accounts matching these patterns that lack an assigned `owner`.

### Excessive Privilege Detection
Compares the `roles` field against high-risk role names: Domain Admin, Enterprise Admin, Schema Admin, Global Admin, Super Admin, Root. Any match triggers a critical finding.

### Recertification Compliance
Compares `last_certified` against a configurable interval (default 180 days). Accounts never certified are flagged as critical.

## Output Schema

```json
{
  "report": "privileged_account_access_review",
  "generated_at": "ISO-8601 timestamp",
  "total_accounts": 150,
  "total_findings": 12,
  "severity_summary": {"critical": 3, "high": 7, "medium": 2},
  "findings": [
    {
      "account": "svc_backup",
      "issue": "shared_account_no_owner",
      "severity": "critical",
      "detail": "Appears shared (matches 'svc_') with no assigned owner"
    }
  ]
}
```

## Compliance Frameworks

- **NIST SP 800-53 AC-2**: Account Management — periodic review of privileged accounts
- **CIS Controls v8 5.3**: Disable dormant accounts after 45 days of inactivity
- **PCI DSS 8.1.4**: Remove/disable inactive user accounts within 90 days
- **SOX Section 404**: Internal controls over financial reporting require access reviews
- **ISO 27001 A.9.2.5**: Review of user access rights at planned intervals

## CLI Usage

```bash
python agent.py --input accounts.csv --stale-days 90 --cert-days 180 --output report.json
```
