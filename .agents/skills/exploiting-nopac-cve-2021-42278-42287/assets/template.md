# noPac Exploitation Report Template

## Target Information

| Field | Value |
|-------|-------|
| Domain | |
| DC Hostname | |
| DC IP | |
| Initial User | |
| MachineAccountQuota | |
| Patch Level | KB5008380 / KB5008602 |

## Exploitation Steps

| Step | Action | Result | Timestamp |
|------|--------|--------|-----------|
| 1 | Vulnerability scan | Vulnerable / Not Vulnerable | |
| 2 | Machine account creation | Success / Failed | |
| 3 | sAMAccountName spoofing | Success / Failed | |
| 4 | TGT request | Ticket obtained / Failed | |
| 5 | S4U2self impersonation | DA ticket / Failed | |
| 6 | DCSync | Hashes dumped / Failed | |

## Remediation

| Action | Priority | Status |
|--------|----------|--------|
| Apply KB5008380 | Critical | |
| Apply KB5008602 | Critical | |
| Set MachineAccountQuota to 0 | High | |
| Monitor Event 4741/4742 | Medium | |
