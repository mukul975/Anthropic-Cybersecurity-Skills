# Device Posture Assessment - Standards & References

## NIST SP 800-207: Zero Trust Architecture
- **Section 2, Tenet 5**: "The enterprise monitors and measures the integrity and security posture of all owned and associated assets"
- **Section 3.3**: Agent/Gateway Model includes device health as access input
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-207/final

## CISA Zero Trust Maturity Model v2.0 - Device Pillar
- **Traditional**: Limited visibility into device health
- **Initial**: Compliance enforcement via MDM
- **Advanced**: Continuous monitoring with automated remediation
- **Optimal**: Real-time posture integrated into every access decision
- **URL**: https://www.cisa.gov/zero-trust-maturity-model

## NIST SP 800-124r2: Guidelines for Managing Mobile Device Security
- **Section 3.2**: Device compliance checking requirements
- **Section 4.1**: MDM security capabilities for posture enforcement
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-124/rev-2/final

## CrowdStrike ZTA Documentation
- **ZTA Overview**: https://www.crowdstrike.com/products/zero-trust-protection/
- **ZTA API**: https://falcon.crowdstrike.com/documentation/156/zero-trust-assessment-apis
- **ZTA Scoring Methodology**: OS signals + sensor configuration signals

## Microsoft Intune Compliance
- **Compliance Policies**: https://learn.microsoft.com/en-us/mem/intune/protect/device-compliance-get-started
- **Conditional Access Integration**: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant
- **Device Health Attestation**: https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/protect-high-value-assets-by-controlling-the-health-of-windows-10-based-devices

## Jamf Pro Compliance
- **Smart Groups**: https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/Smart_Groups.html
- **Compliance Reporter**: https://learn.jamf.com/en-US/bundle/jamf-compliance-editor-documentation/page/Jamf_Compliance_Editor.html

## HIPAA Security Rule (45 CFR 164.312)
- **(a)(1)**: Access control - device posture as access control mechanism
- **(d)**: Device and media controls - encryption and integrity requirements
