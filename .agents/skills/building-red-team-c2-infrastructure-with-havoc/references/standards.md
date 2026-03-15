# Standards and References: Havoc C2 Infrastructure

## MITRE ATT&CK Techniques

### Resource Development (TA0042)
- **T1583.001** - Acquire Infrastructure: Domains
- **T1583.003** - Acquire Infrastructure: Virtual Private Server
- **T1583.006** - Acquire Infrastructure: Web Services
- **T1587.001** - Develop Capabilities: Malware
- **T1587.003** - Develop Capabilities: Digital Certificates
- **T1608.001** - Stage Capabilities: Upload Malware
- **T1608.005** - Stage Capabilities: Link Target

### Command and Control (TA0011)
- **T1071.001** - Application Layer Protocol: Web Protocols (HTTP/HTTPS)
- **T1573.001** - Encrypted Channel: Symmetric Cryptography
- **T1573.002** - Encrypted Channel: Asymmetric Cryptography
- **T1090.001** - Proxy: Internal Proxy
- **T1090.002** - Proxy: External Proxy
- **T1090.004** - Proxy: Domain Fronting
- **T1105** - Ingress Tool Transfer
- **T1132.001** - Data Encoding: Standard Encoding
- **T1001** - Data Obfuscation
- **T1568.002** - Dynamic Resolution: Domain Generation Algorithms
- **T1571** - Non-Standard Port
- **T1572** - Protocol Tunneling

### Defense Evasion (TA0005)
- **T1055** - Process Injection
- **T1055.012** - Process Hollowing
- **T1620** - Reflective Code Loading
- **T1027** - Obfuscated Files or Information
- **T1497** - Virtualization/Sandbox Evasion
- **T1140** - Deobfuscate/Decode Files or Information

### Execution (TA0002)
- **T1059.001** - PowerShell
- **T1106** - Native API
- **T1129** - Shared Modules

## NIST References

- **NIST SP 800-115** - Section 4.3: Penetration Testing (authorized C2 usage)
- **NIST SP 800-53 Rev. 5** - CA-8: Penetration Testing controls
- **NIST SP 800-53 Rev. 5** - SI-4: Information System Monitoring (detection of C2)

## Havoc-Specific Detection Signatures

| Detection | Source | Rule |
|---|---|---|
| Default Havoc HTTP Headers | Network IDS | `alert http any any -> any any (msg:"Havoc C2 Default Headers"; content:"X-Havoc"; sid:1000001;)` |
| Demon Sleep Patterns | EDR | Periodic beaconing with consistent intervals +/- jitter |
| Named Pipe Patterns | Sysmon | EventID 17/18 with `\\.\pipe\` matching Havoc defaults |
| Default Teamserver Port | Firewall | TCP 40056 outbound |

## Compliance Context

Havoc C2 usage is only authorized under:
- Signed Rules of Engagement (RoE) documents
- Authorized penetration testing under PCI DSS 11.4, SOC 2 CC7.1
- TIBER-EU / CBEST threat-led penetration testing frameworks
- Bug bounty programs with explicit C2 authorization
