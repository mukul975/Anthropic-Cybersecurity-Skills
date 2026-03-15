# Standards and References: Zerologon CVE-2020-1472

## MITRE ATT&CK Techniques
- **T1068** - Exploitation for Privilege Escalation
- **T1210** - Exploitation of Remote Services
- **T1003.006** - OS Credential Dumping: DCSync
- **T1078.002** - Valid Accounts: Domain Accounts
- **T1557** - Adversary-in-the-Middle (Netlogon session hijacking)

## CVE Details
- **CVE ID**: CVE-2020-1472
- **CVSS v3.1 Score**: 10.0 (Critical)
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
- **CWE**: CWE-330 (Use of Insufficiently Random Values)
- **Affected Protocol**: MS-NRPC (Netlogon Remote Protocol)
- **Patch**: KB4571694 (August 11, 2020)
- **Enforcement**: February 9, 2021 update

## NIST References
- **NIST NVD**: https://nvd.nist.gov/vuln/detail/CVE-2020-1472
- **NIST SP 800-53** - SI-2: Flaw Remediation
- **NIST SP 800-53** - SI-5: Security Alerts, Advisories, and Directives

## CISA References
- **CISA Emergency Directive 20-04**: Required federal agencies to patch by September 21, 2020
- **CISA Alert AA20-283A**: APT actors chaining Zerologon with other vulnerabilities

## Known Exploitation in the Wild
- **APT Groups**: Multiple nation-state actors observed exploiting Zerologon
- **Ransomware**: Ryuk, Conti operators used Zerologon for domain takeover
- **Timeline**: PoC published September 14, 2020; in-the-wild exploitation within 2 weeks
