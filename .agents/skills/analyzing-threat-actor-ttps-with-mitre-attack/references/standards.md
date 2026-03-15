# Standards and Frameworks Reference

## MITRE ATT&CK Framework

### Matrix Structure
- **Enterprise ATT&CK**: Windows, macOS, Linux, Cloud (AWS, Azure, GCP, SaaS, Office 365), Network, Containers
- **Mobile ATT&CK**: Android, iOS
- **ICS ATT&CK**: Industrial Control Systems

### 14 Enterprise Tactics (Kill Chain Order)
1. **Reconnaissance** (TA0043): Gathering information for planning
2. **Resource Development** (TA0042): Establishing resources for operations
3. **Initial Access** (TA0001): Gaining initial foothold
4. **Execution** (TA0002): Running adversary-controlled code
5. **Persistence** (TA0003): Maintaining access across restarts
6. **Privilege Escalation** (TA0004): Gaining higher-level permissions
7. **Defense Evasion** (TA0005): Avoiding detection
8. **Credential Access** (TA0006): Stealing credentials
9. **Discovery** (TA0007): Understanding the environment
10. **Lateral Movement** (TA0008): Moving through the environment
11. **Collection** (TA0009): Gathering data of interest
12. **Command and Control** (TA0011): Communicating with compromised systems
13. **Exfiltration** (TA0010): Stealing data
14. **Impact** (TA0040): Manipulating, interrupting, or destroying systems

### Technique Naming Convention
- **Technique**: T[NNNN] (e.g., T1059 - Command and Scripting Interpreter)
- **Sub-technique**: T[NNNN].[NNN] (e.g., T1059.001 - PowerShell)
- **Group**: G[NNNN] (e.g., G0016 - APT29)
- **Software**: S[NNNN] (e.g., S0154 - Cobalt Strike)
- **Mitigation**: M[NNNN] (e.g., M1049 - Antivirus/Antimalware)

### Data Sources
ATT&CK v16+ uses structured data sources:
- Process: Process Creation, Process Access, OS API Execution
- File: File Creation, File Modification, File Access
- Network Traffic: Network Connection Creation, Network Traffic Flow
- Command: Command Execution
- Module: Module Load
- Windows Registry: Windows Registry Key Modification

## STIX 2.1 Representation

### Attack Pattern (SDO)
Maps to ATT&CK techniques:
```json
{
  "type": "attack-pattern",
  "id": "attack-pattern--uuid",
  "name": "Spearphishing Attachment",
  "external_references": [
    {"source_name": "mitre-attack", "external_id": "T1566.001"}
  ],
  "kill_chain_phases": [
    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
  ]
}
```

### Intrusion Set (SDO)
Maps to ATT&CK groups:
```json
{
  "type": "intrusion-set",
  "name": "APT29",
  "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM"],
  "goals": ["espionage"],
  "resource_level": "government"
}
```

## ATT&CK Navigator Layer Specification

### Layer Version 4.5 Schema
- `name`: Layer display name
- `domain`: enterprise-attack, mobile-attack, ics-attack
- `techniques[]`: Array of technique annotations
  - `techniqueID`: ATT&CK ID
  - `score`: Numeric score (0-100)
  - `color`: Hex color override
  - `comment`: Analyst notes
  - `enabled`: Show/hide technique
  - `metadata[]`: Key-value pairs for additional context

## References
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [ATT&CK STIX Data Repository](https://github.com/mitre/cti)
- [Navigator Layer Format](https://github.com/mitre-attack/attack-navigator/blob/master/layers/LAYERFORMATv4_5.md)
- [ATT&CK Design and Philosophy](https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf)
