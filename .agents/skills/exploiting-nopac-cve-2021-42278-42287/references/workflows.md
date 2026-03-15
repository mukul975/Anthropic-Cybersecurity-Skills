# Workflows - noPac Exploitation

## Automated Exploitation Workflow

```
1. Scan → noPac scanner or CrackMapExec module
2. Exploit → noPac.py with --impersonate administrator
3. Access → Semi-interactive shell on DC or DCSync dump
4. Persist → Extract KRBTGT hash for Golden Ticket
```

## Manual Exploitation Workflow

```
1. Create machine account (addcomputer.py)
2. Rename sAMAccountName to DC name without $ (renameMachine.py)
3. Request TGT for spoofed name (getTGT.py)
4. Restore original name (renameMachine.py)
5. S4U2self impersonation (getST.py)
6. Use ticket for DCSync (secretsdump.py -k)
```
