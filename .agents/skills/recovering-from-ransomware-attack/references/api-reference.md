# API Reference: Recovering from Ransomware Attack

## Recovery Priority Order

| Priority | Systems | Why First |
|----------|---------|-----------|
| 1 | Domain Controllers | All auth depends on AD |
| 2 | DNS/DHCP | Network functionality |
| 3 | Authentication (SSO/MFA) | User access |
| 4 | Email | Communication |
| 5 | Database Servers | Business data |
| 6 | Application Servers | Business operations |
| 7 | File Servers | Data access |
| 8 | Workstations | End user devices |

## KRBTGT Reset Procedure

| Step | Command | Note |
|------|---------|------|
| 1 | `Reset-KrbtgtPassword` | First reset |
| 2 | Wait 12 hours | Allow replication |
| 3 | `Reset-KrbtgtPassword` | Second reset |
| 4 | `dcdiag /v` | Validate DC health |

## Backup Verification Commands

| Command | Description |
|---------|-------------|
| `veeamcli verify` | Verify Veeam backup integrity |
| `wbadmin get versions` | List Windows Server backups |
| `aws s3api head-object` | Check S3 backup metadata |

## 3-2-1-1-0 Backup Strategy

| Component | Description |
|-----------|-------------|
| 3 copies | Production + 2 backups |
| 2 media types | Disk + tape/cloud |
| 1 offsite | Geographically separate |
| 1 offline | Air-gapped or immutable |
| 0 errors | Verified with restore tests |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `json` | stdlib | Recovery tracking |
| `datetime` | stdlib | Timeline documentation |
| `pathlib` | stdlib | Backup path verification |

## References

- CISA Ransomware Guide: https://www.cisa.gov/stopransomware/ransomware-guide
- NIST SP 1800-26: https://www.nccoe.nist.gov/data-integrity-recovering-ransomware
- NoMoreRansom: https://www.nomoreransom.org/
