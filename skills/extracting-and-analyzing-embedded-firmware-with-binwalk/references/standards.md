Create `skills/extracting-and-analyzing-embedded-firmware-with-binwalk/references/standards.md` and add the following:



```markdown

\# Framework Mappings: Extracting and Analyzing Embedded Firmware with Binwalk



\## MITRE ATT\&CK v19.1

\- \*\*TA0001 - Initial Access\*\*

&#x20; - \[T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/): Identifies pre-installed vulnerabilities or backdoors in vendor-provided firmware images.

\- \*\*TA0006 - Credential Access\*\*

&#x20; - \[T1552.001 - Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/): Extracts hardcoded credentials, default root passwords, and private SSH keys from embedded filesystems.

\- \*\*TA0003 - Persistence\*\*

&#x20; - \[T1542.001 - Pre-OS Boot: System Firmware](https://attack.mitre.org/techniques/T1542/001/): Inspects low-level firmware components for persistent malicious implants or modified boot scripts.



\## NIST CSF 2.0

\- \*\*Identify (ID)\*\*

&#x20; - \*\*ID.RA-01\*\*: Vulnerabilities in hardware, software, and firmware assets are identified and documented.

\- \*\*Protect (PR)\*\*

&#x20; - \*\*PR.DS-01\*\*: Data-at-rest protection and hardcoded secret exposure are evaluated across embedded hardware.

\- \*\*Detect (DE)\*\*

&#x20; - \*\*DE.CM-01\*\*: Hardware assets and underlying software components are monitored for unauthorized modifications.



\## MITRE D3FEND v1.3

\- \*\*D3-FA (Firmware Analysis)\*\*: Extracting and inspecting hardware firmware binaries to analyze security controls, embedded filesystems, and vulnerability exposures.



\## NIST AI RMF 1.0

\- \*N/A (Non-AI specialized hardware control)\*



\## MITRE ATLAS v5.4

\- \*N/A (Non-AI specialized hardware control)\*

