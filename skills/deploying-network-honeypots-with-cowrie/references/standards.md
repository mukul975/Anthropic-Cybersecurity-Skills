\# Framework Mappings: Deploying Network Honeypots with Cowrie



\## MITRE ATT\&CK v19.1

\- \*\*TA0001 - Initial Access\*\*

&#x20; - \[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/): Catches automated password-spraying and credential stuffing against SSH/Telnet services.

&#x20; - \[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/): Intercepts login attempts using default or weak system credentials.

\- \*\*TA0002 - Execution\*\*

&#x20; - \[T1059.004 - Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/): Records interactive Linux shell execution inside the emulated fake environment.

\- \*\*TA0011 - Command and Control\*\*

&#x20; - \[T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/): Intercepts and isolates malicious binaries and scripts downloaded via `curl`, `wget`, or SFTP/SCP.



\## NIST CSF 2.0

\- \*\*Detect (DE)\*\*

&#x20; - \*\*DE.CM-01\*\*: Networks and network services are monitored to find potentially adverse events.

&#x20; - \*\*DE.AE-02\*\*: Anomaly detection logic and decoy triggers are integrated into security operational workflows.

\- \*\*Identify (ID)\*\*

&#x20; - \*\*ID.RA-03\*\*: Threat intelligence regarding adversary TTPs, attack origins, and payloads is collected and analyzed.



\## MITRE D3FEND v1.3

\- \*\*D3-DEC (Decoy Environment)\*\*: Establishing network decoy traps and deceptive virtual environments to attract and expose adversary activities.



\## NIST AI RMF 1.0

\- \*N/A (Non-AI specialized infrastructure control)\*



\## MITRE ATLAS v5.4

\- \*N/A (Non-AI specialized infrastructure control)\*

