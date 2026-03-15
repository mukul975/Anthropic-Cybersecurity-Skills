# Standards and References - AD Vulnerability Assessment

## Primary Standards

### MITRE ATT&CK - Active Directory Techniques
- **URL**: https://attack.mitre.org/
- **Key Techniques**:
  - T1558.003 - Kerberoasting
  - T1558.004 - AS-REP Roasting
  - T1557.001 - LLMNR/NBT-NS Poisoning
  - T1484.001 - Group Policy Modification
  - T1134.005 - SID-History Injection
  - T1003.006 - DCSync

### CIS Benchmark for Active Directory
- **URL**: https://www.cisecurity.org/benchmark/active_directory
- **Relevance**: Provides prescriptive hardening guidance for AD configuration

### Microsoft Security Compliance Toolkit
- **URL**: https://www.microsoft.com/en-us/download/details.aspx?id=55319
- **Relevance**: Baseline GPO settings for domain controllers and member servers

### NIST SP 800-63B
- **Title**: Digital Identity Guidelines - Authentication and Lifecycle Management
- **URL**: https://pages.nist.gov/800-63-3/sp800-63b.html
- **Relevance**: Password policy requirements applicable to AD accounts

### NSA Active Directory Security Guidance
- **Title**: Detecting and Preventing Active Directory Attacks
- **Relevance**: NSA recommendations for securing AD against common attack techniques

## Tools

| Tool | License | URL |
|------|---------|-----|
| PingCastle | Open Source (Netwrix) | https://github.com/netwrix/pingcastle |
| BloodHound CE | Apache 2.0 | https://github.com/SpecterOps/BloodHound |
| SharpHound | Apache 2.0 | https://github.com/SpecterOps/BloodHound |
| Purple Knight | Free Community | https://www.purple-knight.com/ |
| ADRecon | MIT | https://github.com/adrecon/ADRecon |
| Testimo | MIT | https://github.com/EvotecIT/Testimo |
