# Standards and References - WMIExec Lateral Movement

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|-------------|------|--------|
| T1047 | Windows Management Instrumentation | Execution |
| T1021.003 | Remote Services: DCOM | Lateral Movement |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | Lateral Movement |
| T1059.001 | PowerShell | Execution |
| T1570 | Lateral Tool Transfer | Lateral Movement |

## Tools

- Impacket wmiexec.py: https://github.com/fortra/impacket
- CrackMapExec: https://github.com/byt3bl33d3r/CrackMapExec
- SharpWMI: https://github.com/GhostPack/SharpWMI

## Detection Resources

- Windows WMI Activity Log: Microsoft-Windows-WMI-Activity/Operational
- Event 5857: WMI provider loaded
- Event 5860/5861: WMI registration events
- Sysmon Event 19/20/21: WMI filter/consumer/binding creation
