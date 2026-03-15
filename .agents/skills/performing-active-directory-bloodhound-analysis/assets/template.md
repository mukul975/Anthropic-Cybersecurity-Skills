# BloodHound Analysis Report Template

## Engagement Details

| Field | Value |
|---|---|
| Engagement ID | [ID] |
| Domain | [domain.local] |
| Collection Date | YYYY-MM-DD |
| Collector | SharpHound v2.x |
| Analyst | [Name] |

## Domain Statistics

| Metric | Count |
|---|---|
| Users | XXX |
| Enabled Users | XXX |
| Computers | XXX |
| Groups | XXX |
| Domain Admins | XX |
| OUs | XX |
| GPOs | XX |
| Trusts | XX |

## High-Risk Findings Summary

| # | Finding | Severity | Count | MITRE |
|---|---|---|---|---|
| 1 | Kerberoastable Accounts | Critical | XX | T1558.003 |
| 2 | Unconstrained Delegation (non-DC) | Critical | XX | T1558.001 |
| 3 | AS-REP Roastable Accounts | High | XX | T1558.004 |
| 4 | Constrained Delegation Abuse | High | XX | T1550.003 |
| 5 | Excessive ACL Permissions | High | XX | T1484 |
| 6 | Domain Users = Local Admin | High | XX | T1078.002 |
| 7 | Stale Admin Sessions | Medium | XX | T1550.002 |

## Attack Paths Identified

### Path 1: Kerberoasting to Domain Admin

```
[Owned User]
  -> Kerberoast SVC_SQL@CORP.LOCAL (T1558.003)
  -> Crack hash offline (hashcat -m 13100)
  -> SVC_SQL AdminTo SQL01 (T1078.002)
  -> SQL01 HasSession DA_ADMIN (T1033)
  -> Dump LSASS on SQL01 (T1003.001)
  -> Domain Admin achieved
```

**Feasibility:** High - Service account uses weak password
**Detection Risk:** Low - Kerberoasting generates minimal logs by default

### Path 2: ACL Abuse Chain

```
[Owned User]
  -> GenericAll on HELPDESK_ADMIN (T1484)
  -> ForceChangePassword on HELPDESK_ADMIN
  -> HELPDESK_ADMIN MemberOf IT_ADMINS
  -> IT_ADMINS AdminTo DC01
  -> Domain Admin achieved
```

**Feasibility:** Medium - Requires interaction with target account
**Detection Risk:** Medium - Password reset generates Event ID 4724

### Path 3: Delegation Abuse

```
[Owned User]
  -> AdminTo WEB01 (unconstrained delegation)
  -> Deploy Rubeus monitor on WEB01
  -> Coerce DC01 auth via PetitPotam (T1187)
  -> Capture DC01$ TGT
  -> Pass the Ticket to DC01 (T1550.003)
  -> DCSync (T1003.006)
  -> Domain Admin achieved
```

**Feasibility:** High - Unconstrained delegation on non-DC
**Detection Risk:** High - PetitPotam coercion may trigger alerts

## Kerberoastable Accounts

| Account | SPN | Privileged | Password Age | Risk |
|---|---|---|---|---|
| SVC_SQL@CORP.LOCAL | MSSQLSvc/SQL01:1433 | Yes (AdminCount) | 365 days | Critical |
| SVC_WEB@CORP.LOCAL | HTTP/WEB01 | No | 180 days | High |
| SVC_BACKUP@CORP.LOCAL | HOST/BACKUP01 | Yes (Backup Ops) | 730 days | Critical |

## Unconstrained Delegation

| Computer | OS | Domain Controller | Risk |
|---|---|---|---|
| WEB01.CORP.LOCAL | Server 2019 | No | Critical |
| PRINT01.CORP.LOCAL | Server 2016 | No | Critical |

## ACL Misconfigurations

| Source | Edge | Target | Risk |
|---|---|---|---|
| HELPDESK@CORP.LOCAL | GenericAll | IT_ADMINS@CORP.LOCAL | High |
| SVC_DEPLOY@CORP.LOCAL | WriteDACL | SERVER_ADMINS@CORP.LOCAL | High |
| HR_USERS@CORP.LOCAL | AddMember | VPN_USERS@CORP.LOCAL | Medium |

## Remediation Priorities

### Immediate (0-7 days)
1. Remove unconstrained delegation from WEB01, PRINT01
2. Reset passwords on Kerberoastable privileged accounts (25+ chars)
3. Remove GenericAll permission from HELPDESK on IT_ADMINS

### Short-Term (7-30 days)
1. Migrate service accounts to Group Managed Service Accounts (gMSA)
2. Enable AES-only Kerberos encryption for service accounts
3. Add privileged accounts to Protected Users group
4. Implement LAPS for local administrator passwords

### Long-Term (30-90 days)
1. Implement Active Directory Tier Model
2. Deploy Privileged Access Workstations (PAWs)
3. Enable Advanced Audit Policy for Kerberos events
4. Conduct quarterly BloodHound assessments
