# Standards & References - Recovering from Ransomware Attack

## Frameworks
- NIST SP 800-61r3: Computer Security Incident Handling Guide (Recover phase)
- NIST IR 8374: Ransomware Risk Management - Recovery section
- CISA #StopRansomware Guide: Recovery checklist
- CIS Controls v8: Control 11 (Data Recovery)
- NIST CSF 2.0: Recover function (RC.RP, RC.CO)

## AD Recovery
- Microsoft: AD Forest Recovery Guide - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-guide
- DSInternals: https://github.com/MichaelGrafnetter/DSInternals
- krbtgt reset guidance: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-resetting-the-krbtgt-password

## MITRE ATT&CK (Recovery Validation)
- T1053: Scheduled Task/Job (persistence to check)
- T1543: Create or Modify System Process (persistence to check)
- T1547: Boot or Logon Autostart Execution (persistence to check)
- T1558.001: Golden Ticket (must reset krbtgt)
- T1098: Account Manipulation (check for backdoor accounts)
