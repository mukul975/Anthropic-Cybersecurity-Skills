# Device Posture Assessment Implementation Workflow

## Phase 1: Baseline Assessment (Week 1)

### 1.1 Inventory Current State
1. Export all managed devices from Intune/Jamf/SCCM
2. Identify unmanaged devices accessing corporate resources
3. Document OS distribution, patch levels, and encryption status
4. Measure current compliance rate before enforcement

### 1.2 Define Posture Requirements
1. Establish minimum requirements per device tier:
   - **Tier 1 (Basic)**: OS updated within 90 days, screen lock enabled
   - **Tier 2 (Standard)**: Disk encryption, firewall, antivirus, OS within 60 days
   - **Tier 3 (Enhanced)**: EDR running, ZTA score >= 70, OS within 30 days, TPM/Secure Boot
   - **Tier 4 (Critical)**: ZTA score >= 90, fully managed, patched within 7 days
2. Map application sensitivity to required posture tier
3. Define grace periods for remediation (24h standard, 4h for critical)

## Phase 2: MDM Policy Configuration (Week 2-3)

### 2.1 Intune Compliance Policies
1. Create Windows compliance policy: BitLocker, Secure Boot, TPM, Defender, OS version
2. Create macOS compliance policy: FileVault, Gatekeeper, SIP, Firewall
3. Create iOS/Android compliance policy: Encryption, PIN, jailbreak detection
4. Configure non-compliance actions: email notification, mark non-compliant, block after grace
5. Assign policies to device groups

### 2.2 Jamf Pro Configuration
1. Create smart groups for compliant/non-compliant macOS devices
2. Configure compliance criteria: FileVault, SIP, Gatekeeper, OS version
3. Set up automated remediation scripts for common issues
4. Configure compliance reporting to Jamf Protect or SIEM

## Phase 3: EDR Integration (Week 3-4)

### 3.1 CrowdStrike ZTA Setup
1. Enable Zero Trust Assessment module in Falcon console
2. Configure ZTA score thresholds per access tier
3. Set up API integration for ZTNA platform (Zscaler, Cloudflare, Okta)
4. Create host groups for ZTA monitoring
5. Build dashboard for ZTA score distribution

### 3.2 Microsoft Defender for Endpoint
1. Enable device risk assessment in Defender Security Center
2. Configure risk levels: Low, Medium, High, Critical
3. Integrate with Intune compliance via Defender connector
4. Set up conditional access policy consuming device risk signal

## Phase 4: Conditional Access Configuration (Week 4-5)

### 4.1 Entra ID Conditional Access
1. Create policy: Require compliant device for all cloud apps
2. Create policy: Block high-risk devices from sensitive apps
3. Create policy: Require MFA + compliant device for admin portals
4. Configure break-glass exclusions for emergency access
5. Start in report-only mode, then switch to enforcement

### 4.2 Okta Device Trust
1. Configure device trust integration with MDM platforms
2. Create device assurance policies with CrowdStrike integration
3. Set up authentication policies requiring device trust
4. Test with enrolled and non-enrolled devices

## Phase 5: Monitoring and Remediation (Ongoing)

1. Build compliance dashboard showing real-time posture across fleet
2. Configure alerts for posture drift (encryption disabled, EDR stopped)
3. Automate remediation: push encryption enablement, deploy patches
4. Generate weekly compliance reports for security leadership
5. Conduct monthly review of posture requirements vs. threat landscape
