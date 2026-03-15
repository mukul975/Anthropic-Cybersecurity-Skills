# DCSync Attack Report Template

## Target Domain

| Field | Value |
|-------|-------|
| Domain | |
| Domain SID | |
| DC Target | |
| Attack Source Account | |
| Tool Used | Mimikatz / secretsdump.py |

## Extracted Credentials

| Account | Type | NT Hash | Cleartext | Persistence Value |
|---------|------|---------|-----------|-------------------|
| krbtgt | Service | | No | Golden Ticket |
| Administrator | DA | | No | Direct DA access |

## Persistence Mechanisms

| Mechanism | Status | Details |
|-----------|--------|---------|
| Golden Ticket | Created / Not Created | |
| DCSync Rights Granted | Yes / No | Account: |
| Silver Tickets | Created / Not Created | Services: |

## Remediation

| Action | Priority |
|--------|----------|
| Double KRBTGT password reset (with 10h gap) | Critical |
| Audit accounts with replication rights | Critical |
| Enable Event 4662 logging for replication GUIDs | High |
| Deploy DRSUAPI traffic monitoring | High |
