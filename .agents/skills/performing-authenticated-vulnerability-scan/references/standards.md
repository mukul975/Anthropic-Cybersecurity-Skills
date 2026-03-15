# Standards and References - Authenticated Vulnerability Scanning

## Industry Standards
- **NIST SP 800-115**: Technical Guide to Information Security Testing and Assessment
- **NIST SP 800-53 RA-5**: Vulnerability Scanning (requires credentialed scanning for compliance)
- **CIS Controls v8 Control 7.5**: Perform automated vulnerability scans of internal assets on a quarterly basis using authenticated scanning
- **PCI DSS v4.0 Req 11.3.1**: Internal vulnerability scans must use authenticated scanning
- **DISA STIG**: Requires credentialed scanning for compliance validation

## Credential Management Standards
- **NIST SP 800-63B**: Digital Identity Guidelines - Authentication and Lifecycle Management
- **CIS Controls v8 Control 5**: Account Management
- **OWASP Credential Storage Cheat Sheet**: Secure credential handling best practices

## Scanner Documentation
- Nessus Credentialed Checks: https://docs.tenable.com/nessus/Content/CredentialedChecks.htm
- Qualys Authenticated Scanning: https://www.qualys.com/docs/qualys-scanning-best-practices.pdf
- OpenVAS Credential Management: https://docs.greenbone.net/
- Rapid7 InsightVM Credentials: https://docs.rapid7.com/insightvm/managing-shared-credentials/

## Verification Plugins (Nessus)
| Plugin ID | Name | Purpose |
|-----------|------|---------|
| 19506 | Nessus Scan Information | Shows scan metadata and credential status |
| 21745 | OS Security Patch Assessment | Confirms local security checks enabled |
| 117887 | Local Security Checks Enabled | Per-host credential verification |
| 110385 | Nessus Credentialed Check | Detailed credential success/failure |
| 10394 | Microsoft Windows SMB Log In Possible | Windows SMB auth verification |
| 10180 | Ping the Remote Host | Host reachability confirmation |

## Minimum Privileges Required
| Platform | Minimum Privilege | Notes |
|----------|------------------|-------|
| Linux | Root or sudo user | Sudo with NOPASSWD for specific commands |
| Windows | Local Administrator | Or domain account with local admin GPO |
| Cisco IOS | Privilege 15 | Enable mode access required |
| SNMP | Read-only (v3 authPriv) | SNMPv3 with encryption |
| Oracle DB | SELECT ANY DICTIONARY | Minimum for audit queries |
| PostgreSQL | pg_read_all_settings | Read-only role sufficient |
