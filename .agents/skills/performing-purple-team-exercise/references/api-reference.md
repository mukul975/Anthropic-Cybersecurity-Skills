# API Reference: Purple Team Exercise

## Atomic Red Team (PowerShell)

```powershell
# Install
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1')
Install-AtomicRedTeam -getAtomics

# Execute technique
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Cleanup after test
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

## MITRE Caldera API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v2/operations` | POST | Start adversary emulation operation |
| `/api/v2/operations/{id}` | GET | Get operation status and results |
| `/api/v2/abilities` | GET | List available ATT&CK abilities |
| `/api/v2/adversaries` | GET | List adversary profiles |

## ATT&CK Techniques Commonly Tested

| ID | Technique | Detection Signal |
|----|-----------|-----------------|
| T1059.001 | PowerShell | Sysmon EventCode 1, PowerShell logging |
| T1053.005 | Scheduled Task | EventCode 4698 |
| T1003.001 | LSASS Access | Sysmon EventCode 10 |
| T1550.002 | Pass-the-Hash | EventCode 4624 with NTLM Type 3 |
| T1021.002 | PsExec | EventCode 7045 (PSEXESVC) |
| T1490 | Shadow Copy Deletion | vssadmin process creation |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `json` | stdlib | Test plan and report management |
| `subprocess` | stdlib | Execute Atomic Red Team tests |
| `datetime` | stdlib | Detection latency measurement |

## References

- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- MITRE Caldera: https://github.com/mitre/caldera
- Vectr: https://vectr.io/
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
