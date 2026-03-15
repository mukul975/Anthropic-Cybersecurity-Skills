---
name: performing-threat-emulation-with-atomic-red-team
description: >
  Executes Atomic Red Team tests for MITRE ATT&CK technique validation using the
  atomic-operator Python framework. Loads test definitions from YAML atomics, runs
  attack simulations, and validates detection coverage. Use when testing SIEM detection
  rules, validating EDR coverage, or conducting purple team exercises.
domain: cybersecurity
subdomain: threat-intelligence
tags: [performing, threat, emulation, with]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Threat Emulation with Atomic Red Team

## Instructions

Use atomic-operator to execute Atomic Red Team tests and validate detection coverage
against MITRE ATT&CK techniques.

```python
from atomic_operator import AtomicOperator

operator = AtomicOperator()
# Run a specific technique test
operator.run(
    technique="T1059.001",  # PowerShell execution
    atomics_path="./atomic-red-team/atomics",
)
```

Key workflow:
1. Clone the atomic-red-team repository for test definitions
2. Select ATT&CK techniques matching your detection rules
3. Execute atomic tests using atomic-operator
4. Check SIEM/EDR for corresponding alerts
5. Document detection gaps and update rules

## Examples

```python
# Parse atomic test YAML definitions
import yaml
with open("atomics/T1059.001/T1059.001.yaml") as f:
    tests = yaml.safe_load(f)
for test in tests.get("atomic_tests", []):
    print(f"Test: {test['name']}")
    print(f"  Platforms: {test.get('supported_platforms', [])}")
```
