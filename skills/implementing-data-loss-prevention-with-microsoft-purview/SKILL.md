---
name: implementing-data-loss-prevention-with-microsoft-purview
description: 'Implements data loss prevention policies using Microsoft Purview to
  protect sensitive information across Exchange Online, SharePoint, OneDrive, Teams,
  endpoint devices, and Power BI. The analyst configures sensitivity labels with encryption
  and content marking, creates DLP policies using built-in and custom sensitive information
  types with regex patterns, deploys endpoint DLP rules to control file operations
  on Windows and macOS devices, and monitors policy effectiveness through Activity
  Explorer and DLP alert management. Uses PowerShell cmdlets and the Microsoft Graph
  API for programmatic policy management. Activates for requests involving DLP policy
  creation, sensitivity label configuration, data classification, endpoint data protection,
  or Microsoft Purview compliance administration.

  '
domain: cybersecurity
subdomain: data-protection
tags:
- DLP
- Microsoft-Purview
- sensitivity-labels
- endpoint-DLP
- data-classification
- compliance
version: 1.0.0
author: mukul975
license: Apache-2.0
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
- GV.PO-01
mitre_attack:
- T1486
- T1530
- T1537
- T1048
- T1573
---
# Implementing Data Loss Prevention with Microsoft Purview

## When to Use

- Deploying DLP policies to prevent sensitive data (PII, PHI, PCI, intellectual property) from leaving the organization through email, cloud storage, chat, or endpoint file operations
- Configuring sensitivity labels with encryption, content marking, and auto-labeling to classify documents and emails by confidentiality level
- Creating custom sensitive information types with regex patterns to detect organization-specific data formats (employee IDs, project codes, internal account numbers)
- Deploying endpoint DLP to control copy-to-USB, print, upload-to-cloud, and copy-to-clipboard actions for labeled or sensitive content on managed devices
- Investigating DLP incidents through Activity Explorer to analyze policy match events, user activity patterns, and false positive rates for policy tuning

**Do not use** without appropriate Microsoft 365 E5, E5 Compliance, or E5 Information Protection licensing. Do not deploy DLP policies directly to production enforcement mode without a simulation period. Do not configure endpoint DLP without coordinating with the endpoint management team responsible for device onboarding.

## Prerequisites

- Microsoft 365 E5 or E5 Compliance / E5 Information Protection add-on license assigned to target users
- Global Administrator, Compliance Administrator, or Compliance Data Administrator role in the Microsoft Purview portal
- Exchange Online PowerShell module (ExchangeOnlineManagement v3.x) and Security & Compliance PowerShell for policy automation
- Devices onboarded to Microsoft Purview endpoint DLP through Microsoft Intune or Configuration Manager (Windows 10/11 21H2+, macOS 12+)
- Data classification scan completed or content explorer populated to understand existing sensitive data distribution
- Stakeholder agreement on sensitivity label taxonomy (classification levels, encryption requirements, scope)

## Workflow

### Step 1: Design the Sensitivity Label Taxonomy

Define the classification hierarchy that maps to organizational data handling requirements:

- **Establish label tiers**: Create a label hierarchy reflecting data sensitivity levels. A standard enterprise taxonomy includes:
  ```
  Public           -> No protection, external sharing allowed
  General          -> No encryption, internal watermark "GENERAL"
  Confidential     -> Encryption (all employees), header/footer marking
    ├─ Confidential - All Employees
    ├─ Confidential - Finance
    └─ Confidential - HR
  Highly Confidential -> Encryption (specific users/groups), watermark, no forwarding
    ├─ Highly Confidential - Project X
    └─ Highly Confidential - Board Only
  ```
- **Define protection settings per label**: For each label, configure encryption scope (all employees, specific groups, or custom permissions), content marking (headers, footers, watermarks), and auto-labeling conditions:
  ```powershell
  # Connect to Security & Compliance PowerShell
  Connect-IPPSSession -UserPrincipalName admin@contoso.com

  # Create parent label
  New-Label -DisplayName "Confidential" `
    -Name "Confidential" `
    -Tooltip "Business data that could cause damage if disclosed to unauthorized parties" `
    -Comment "Apply to internal business documents, financial reports, and customer data"

  # Create sub-label with encryption
  New-Label -DisplayName "Confidential - Finance" `
    -Name "Confidential-Finance" `
    -ParentId (Get-Label -Identity "Confidential").Guid `
    -Tooltip "Financial data restricted to Finance department" `
    -EncryptionEnabled $true `
    -EncryptionProtectionType "Template" `
    -EncryptionRightsDefinitions "finance-group@contoso.com:VIEW,VIEWRIGHTSDATA,DOCEDIT,EDIT,PRINT,EXTRACT,OBJMODEL" `
    -ContentType "File, Email"
  ```
- **Configure content marking**: Apply visual indicators that persist with the document:
  ```powershell
  Set-Label -Identity "Confidential-Finance" `
    -HeaderEnabled $true `
    -HeaderText "CONFIDENTIAL - FINANCE" `
    -HeaderFontSize 10 `
    -HeaderFontColor "#FF0000" `
    -HeaderAlignment "Center" `
    -FooterEnabled $true `
    -FooterText "This document contains confidential financial information" `
    -WatermarkEnabled $true `
    -WatermarkText "CONFIDENTIAL" `
    -WatermarkFontSize 36
  ```
- **Publish labels via label policy**: Labels must be published to users through a label policy that defines which users see the labels and whether a default label or mandatory labeling is enforced:
  ```powershell
  New-LabelPolicy -Name "Corporate Label Policy" `
    -Labels "Public","General","Confidential","Confidential-Finance",
            "Confidential-HR","HighlyConfidential","HighlyConfidential-ProjectX" `
    -ExchangeLocation "All" `
    -ModernGroupLocation "All" `
    -Comment "Standard corporate sensitivity labels"

  # Require justification for label downgrade
  Set-LabelPolicy -Identity "Corporate Label Policy" `
    -AdvancedSettings @{RequireDowngradeJustification="True";
                        DefaultLabelId="General"}
  ```

### Step 2: Create DLP Policies with Sensitive Information Types

Configure DLP policies that detect and protect sensitive content across Microsoft 365 workloads:

- **Create a DLP policy using built-in sensitive information types**: Microsoft Purview includes 300+ built-in SITs for credit card numbers, Social Security numbers, passport numbers, and health records. Create a policy targeting financial data:
  ```powershell
  # Create DLP policy scoped to Exchange, SharePoint, OneDrive
  New-DlpCompliancePolicy -Name "Financial Data Protection" `
    -ExchangeLocation "All" `
    -SharePointLocation "All" `
    -OneDriveLocation "All" `
    -TeamsLocation "All" `
    -Mode "TestWithNotifications" `
    -Comment "Protects credit card numbers, bank account numbers, and financial identifiers"

  # Create rule for high-volume credit card detection
  New-DlpComplianceRule -Name "Block Bulk Credit Card Sharing" `
    -Policy "Financial Data Protection" `
    -ContentContainsSensitiveInformation @{
      Name = "Credit Card Number";
      MinCount = 5;
      MinConfidence = 85
    } `
    -BlockAccess $true `
    -BlockAccessScope "All" `
    -NotifyUser "SiteAdmin","LastModifier" `
    -NotifyUserType "NotSet" `
    -GenerateIncidentReport "SiteAdmin" `
    -IncidentReportContent "All" `
    -ReportSeverityLevel "High"

  # Create rule for low-volume with user override
  New-DlpComplianceRule -Name "Warn on Credit Card Sharing" `
    -Policy "Financial Data Protection" `
    -ContentContainsSensitiveInformation @{
      Name = "Credit Card Number";
      MinCount = 1;
      MaxCount = 4;
      MinConfidence = 75
    } `
    -NotifyUser "LastModifier" `
    -NotifyUserType "NotSet" `
    -GenerateAlert "Low" `
    -NotifyOverride "WithJustification"
  ```
- **Create custom sensitive information types with regex**: Define organization-specific patterns for data that built-in SITs do not cover:
  ```powershell
  # Create custom SIT for employee ID format (EMP-XXXXXX)
  $rulePackXml = @"
  <RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
    <RulePack id="$(New-Guid)">
      <Version major="1" minor="0" build="0" revision="0"/>
      <Publisher id="$(New-Guid)"/>
    </RulePack>
    <Rules>
      <Entity id="$(New-Guid)" patternsProximity="300"
              recommendedConfidence="85">
        <Pattern confidenceLevel="85">
          <IdMatch idRef="EmployeeId_Regex"/>
        </Pattern>
        <Pattern confidenceLevel="95">
          <IdMatch idRef="EmployeeId_Regex"/>
          <Match idRef="EmployeeId_Keyword"/>
        </Pattern>
      </Entity>
      <Regex id="EmployeeId_Regex">EMP-[0-9]{6}</Regex>
      <Keyword id="EmployeeId_Keyword">
        <Group matchStyle="word">
          <Term>employee</Term>
          <Term>employee id</Term>
          <Term>emp id</Term>
          <Term>staff number</Term>
        </Group>
      </Keyword>
      <LocalizedStrings>
        <Resource idRef="EmployeeId_Regex">
          <Name default="true" langcode="en-us">Contoso Employee ID</Name>
          <Description default="true" langcode="en-us">
            Detects Contoso employee IDs in format EMP-XXXXXX
          </Description>
        </Resource>
      </LocalizedStrings>
    </Rules>
  </RulePackage>
  "@

  # Save and import the rule package
  $rulePackXml | Out-File -FilePath "EmployeeID_SIT.xml" -Encoding utf8
  New-DlpSensitiveInformationTypeRulePackage -FileData (
    [System.IO.File]::ReadAllBytes("EmployeeID_SIT.xml")
  )
  ```
- **Use sensitivity labels as DLP conditions**: Create policies that apply different restrictions based on the label applied to the content:
  ```powershell
  New-DlpCompliancePolicy -Name "Highly Confidential Sharing Control" `
    -ExchangeLocation "All" `
    -SharePointLocation "All" `
    -OneDriveLocation "All" `
    -Mode "Enable"

  New-DlpComplianceRule -Name "Block External Sharing of HC Content" `
    -Policy "Highly Confidential Sharing Control" `
    -ContentContainsSensitiveInformation $null `
    -ContentPropertyContainsWords "MSIP_Label_$(
      (Get-Label -Identity 'HighlyConfidential').Guid
    )_Enabled=True" `
    -BlockAccess $true `
    -BlockAccessScope "NotInOrganization" `
    -NotifyUser "LastModifier" `
    -GenerateIncidentReport "SiteAdmin" `
    -ReportSeverityLevel "High"
  ```

### Step 3: Deploy Endpoint DLP Rules

Extend DLP protection to managed Windows and macOS endpoints to control file operations:

- **Verify device onboarding**: Confirm devices are onboarded to Microsoft Purview endpoint DLP through Microsoft Intune or the local onboarding script:
  ```powershell
  # Check onboarding status via Intune Graph API
  # GET https://graph.microsoft.com/beta/deviceManagement/managedDevices
  # Filter for complianceState and dlpOnboardingStatus

  # Local verification on Windows endpoint
  # Check registry key:
  # HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status
  # OnboardingState should be 1
  ```
- **Configure endpoint DLP settings**: Define global settings that control which applications and file types endpoint DLP monitors:
  ```powershell
  # Configure unallowed apps (browsers, cloud sync clients)
  Set-PolicyConfig -EndpointDlpGlobalSettings `
    -UnallowedApps @(
      @{Name="Chrome"; Executable="chrome.exe"},
      @{Name="Firefox"; Executable="firefox.exe"},
      @{Name="PersonalDropbox"; Executable="Dropbox.exe"}
    )

  # Configure unallowed Bluetooth apps
  Set-PolicyConfig -EndpointDlpGlobalSettings `
    -UnallowedBluetoothApps @(
      @{Name="BluetoothFileTransfer"; Executable="fsquirt.exe"}
    )

  # Configure network share groups
  Set-PolicyConfig -EndpointDlpGlobalSettings `
    -NetworkShareGroups @(
      @{
        Name = "Authorized Shares";
        NetworkPaths = @("\\server01\approved$", "\\server02\secure$")
      }
    )

  # Configure sensitive service domains (allowed cloud destinations)
  Set-PolicyConfig -EndpointDlpGlobalSettings `
    -SensitiveServiceDomains @(
      @{
        Name = "Approved Cloud Storage";
        Domains = @("sharepoint.com", "onedrive.com")
        MatchType = "Allow"
      },
      @{
        Name = "Blocked Cloud Storage";
        Domains = @("dropbox.com", "box.com", "drive.google.com")
        MatchType = "Block"
      }
    )
  ```
- **Create endpoint-specific DLP rules**: Define rules that control copy-to-USB, print, upload, and clipboard operations for sensitive content:
  ```powershell
  # Add endpoint location to existing policy
  Set-DlpCompliancePolicy -Identity "Financial Data Protection" `
    -EndpointDlpLocation "All"

  # Create endpoint-specific rule
  New-DlpComplianceRule -Name "Block USB Copy of Financial Data" `
    -Policy "Financial Data Protection" `
    -ContentContainsSensitiveInformation @{
      Name = "Credit Card Number";
      MinCount = 1;
      MinConfidence = 85
    } `
    -EndpointDlpRestrictions @(
      @{Setting="CopyToRemovableMedia"; Value="Block"},
      @{Setting="CopyToNetworkShare"; Value="Audit"},
      @{Setting="CopyToClipboard"; Value="Block"},
      @{Setting="Print"; Value="Warn"},
      @{Setting="UploadToCloudService"; Value="Block"},
      @{Setting="UnallowedBluetoothApp"; Value="Block"}
    ) `
    -NotifyUser "LastModifier" `
    -GenerateIncidentReport "SiteAdmin"
  ```
- **Configure printer groups and USB device exceptions**: Allow specific printers and approved USB devices while blocking unauthorized removable media:
  ```powershell
  # Define authorized USB devices by vendor/product ID
  Set-PolicyConfig -EndpointDlpGlobalSettings `
    -RemovableMediaGroups @(
      @{
        Name = "Approved Encrypted USBs";
        Devices = @(
          @{VendorId="0781"; ProductId="5583"; SerialNumber="*"}  # SanDisk Extreme
        )
      }
    )

  # Define authorized printers
  Set-PolicyConfig -EndpointDlpGlobalSettings `
    -PrinterGroups @(
      @{
        Name = "Corporate Printers";
        Printers = @(
          @{PrinterName="*Corporate*"; PrinterType="Corporate"},
          @{PrinterName="PDF Printer"; PrinterType="Print to PDF"}
        )
      }
    )
  ```

### Step 4: Configure Auto-Labeling Policies

Deploy service-side auto-labeling to automatically classify content at rest and in transit:

- **Create auto-labeling policy for email**: Automatically label inbound and outbound emails containing sensitive information:
  ```powershell
  New-AutoSensitivityLabelPolicy -Name "Auto-Label Financial Emails" `
    -ExchangeLocation "All" `
    -Mode "TestWithNotifications" `
    -Comment "Automatically labels emails containing financial data as Confidential-Finance"

  New-AutoSensitivityLabelRule -Name "Financial SIT Match" `
    -Policy "Auto-Label Financial Emails" `
    -SensitiveInformationType @{
      Name = "Credit Card Number";
      MinCount = 1;
      MinConfidence = 85
    },@{
      Name = "U.S. Bank Account Number";
      MinCount = 1;
      MinConfidence = 85
    } `
    -WorkloadDomain "Exchange" `
    -ApplySensitivityLabel "Confidential-Finance"
  ```
- **Create auto-labeling policy for SharePoint and OneDrive**: Label existing files at rest that match sensitive information patterns:
  ```powershell
  New-AutoSensitivityLabelPolicy -Name "Auto-Label SP Financial Docs" `
    -SharePointLocation "https://contoso.sharepoint.com/sites/finance" `
    -OneDriveLocation "All" `
    -Mode "TestWithNotifications"

  New-AutoSensitivityLabelRule -Name "Financial Docs SIT Match" `
    -Policy "Auto-Label SP Financial Docs" `
    -SensitiveInformationType @{
      Name = "Credit Card Number"; MinCount = 1; MinConfidence = 85
    } `
    -WorkloadDomain "SharePoint" `
    -ApplySensitivityLabel "Confidential-Finance"
  ```
- **Simulate before enforcing**: Always run auto-labeling in simulation mode first. Review the simulation results in the Microsoft Purview portal under Information Protection > Auto-labeling. The simulation shows estimated matches per location and sample content matches for validation. Only switch to enforcement mode after confirming accuracy:
  ```powershell
  # Check simulation results
  Get-AutoSensitivityLabelPolicy -Identity "Auto-Label Financial Emails" |
    Select-Object Name, Mode, WhenCreated, DistributionStatus

  # Switch to enforcement after validation
  Set-AutoSensitivityLabelPolicy -Identity "Auto-Label Financial Emails" `
    -Mode "Enable"
  ```

### Step 5: Monitor with Activity Explorer and Manage DLP Alerts

Use Activity Explorer and the DLP alerts dashboard to monitor policy effectiveness and investigate incidents:

- **Access Activity Explorer**: Navigate to Microsoft Purview portal > Data Classification > Activity Explorer. Filter by activity type "DLPRuleMatch" to see all DLP policy matches. Key columns include:
  - Activity timestamp and user principal name
  - Sensitive information type matched and confidence level
  - Policy and rule name that triggered
  - Action taken (Audit, Block, Warn with Override)
  - Location (Exchange, SharePoint, OneDrive, Endpoint)
  - File name and site URL
- **Analyze false positive rates**: Export Activity Explorer data filtered by "Override" actions with justification text to identify rules that users frequently override. A high override rate (>20%) indicates the rule may be too aggressive or matching non-sensitive content:
  ```
  Activity Explorer filter:
    Activity type = DLPRuleMatch
    Action = Override
    Date range = Last 30 days
    Policy name = Financial Data Protection

  Export to CSV for analysis of override justifications and
  affected file types to refine SIT confidence thresholds.
  ```
- **Configure DLP alerts**: Set up alert policies in Microsoft Purview > Data Loss Prevention > Alerts to receive notifications for high-severity matches:
  ```powershell
  # DLP alerts are configured within the DLP rule itself
  # Adjust alert volume thresholds on high-traffic rules
  Set-DlpComplianceRule -Identity "Block Bulk Credit Card Sharing" `
    -GenerateAlert "High" `
    -AlertProperties @{
      AggregationType = "SimpleAggregation";
      Threshold = 1;
      TimeWindow = "00:05:00"
    }
  ```
- **Query DLP events via Microsoft Graph API**: Programmatically retrieve DLP alerts and policy match details for integration with SIEM or custom dashboards:
  ```python
  import requests

  # Authenticate with Microsoft Graph (client credentials flow)
  token_url = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
  token_response = requests.post(token_url, data={
      "client_id": client_id,
      "client_secret": client_secret,
      "scope": "https://graph.microsoft.com/.default",
      "grant_type": "client_credentials"
  })
  access_token = token_response.json()["access_token"]

  headers = {"Authorization": f"Bearer {access_token}"}

  # Retrieve DLP alerts
  alerts_url = "https://graph.microsoft.com/v1.0/security/alerts_v2"
  params = {
      "$filter": "serviceSource eq 'microsoftDataLossPrevention'",
      "$top": 50,
      "$orderby": "createdDateTime desc"
  }
  response = requests.get(alerts_url, headers=headers, params=params)
  alerts = response.json().get("value", [])

  for alert in alerts:
      print(f"Alert: {alert['title']}")
      print(f"  Severity: {alert['severity']}")
      print(f"  Status: {alert['status']}")
      print(f"  Created: {alert['createdDateTime']}")
      print(f"  User: {alert.get('userStates', [{}])[0].get('userPrincipalName', 'N/A')}")
  ```
- **Retrieve DLP policy match details for compliance reporting**: Use the unified audit log to extract granular DLP match data including the matched content, SIT type, and confidence level:
  ```powershell
  # Search unified audit log for DLP policy matches
  Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) `
    -EndDate (Get-Date) `
    -RecordType "DLP" `
    -ResultSize 1000 |
    Select-Object CreationDate, UserIds, Operations,
      @{N='PolicyName';E={($_.AuditData | ConvertFrom-Json).PolicyDetails.PolicyName}},
      @{N='RuleName';E={($_.AuditData | ConvertFrom-Json).PolicyDetails.Rules.RuleName}},
      @{N='SITMatched';E={($_.AuditData | ConvertFrom-Json).SensitiveInfoDetections.SensitiveType}} |
    Export-Csv -Path "DLP_Audit_Report.csv" -NoTypeInformation
  ```

## Key Concepts

| Term | Definition |
|------|------------|
| **Sensitivity Label** | A classification tag applied to documents and emails that can enforce encryption, content marking (headers/footers/watermarks), and access restrictions. Labels persist with the content and travel with files when shared externally. |
| **Sensitive Information Type (SIT)** | A pattern-based classifier that detects specific data patterns (credit card numbers, SSNs, custom regex) in content. Each SIT has a confidence level (low/medium/high) determined by primary pattern match plus corroborating evidence (keywords, proximity). |
| **DLP Policy** | A set of rules that detect sensitive information in Microsoft 365 locations (Exchange, SharePoint, OneDrive, Teams, Endpoints) and apply protective actions (audit, warn with override, block) based on the sensitivity of matched content and the sharing context. |
| **Endpoint DLP** | Extension of DLP protection to managed Windows and macOS devices that monitors and controls file operations including copy-to-USB, print, upload-to-cloud, copy-to-clipboard, and access by unallowed applications for files containing sensitive information. |
| **Activity Explorer** | A monitoring dashboard in Microsoft Purview that displays a historical view (up to 30 days) of labeled content activities, DLP policy matches, and user interactions with classified data across all monitored locations. |
| **Auto-Labeling** | Service-side automatic classification that applies sensitivity labels to documents and emails matching specified SIT patterns without requiring user interaction. Runs in simulation mode first to preview matches before enforcement. |
| **Content Marking** | Visual indicators (headers, footers, watermarks) applied by sensitivity labels to documents and emails. Markings persist in the file and are visible when printed or shared, serving as a visual classification reminder. |
| **DLP Alert** | A notification generated when a DLP rule match meets the configured severity threshold. Alerts appear in the Microsoft Purview DLP alerts dashboard and can be routed to Microsoft Sentinel or other SIEM platforms. |

## Tools & Systems

- **Microsoft Purview Compliance Portal**: Web-based administration interface for creating and managing sensitivity labels, DLP policies, auto-labeling rules, and reviewing Activity Explorer data and DLP alerts.
- **Security & Compliance PowerShell**: PowerShell module (Connect-IPPSSession) providing cmdlets for programmatic management of labels (New-Label, Set-Label), label policies (New-LabelPolicy), DLP policies (New-DlpCompliancePolicy, New-DlpComplianceRule), and sensitive information types.
- **Microsoft Graph Security API**: REST API providing programmatic access to DLP alerts (security/alerts_v2), data classification insights, and protection scope evaluation for integrating Purview DLP with custom applications and SIEM platforms.
- **Microsoft Intune**: Endpoint management platform used to onboard Windows and macOS devices to endpoint DLP, deploy configuration profiles, and manage device compliance states.
- **Microsoft Sentinel**: Cloud-native SIEM that ingests DLP alerts and audit logs from Microsoft Purview via the Microsoft 365 Defender data connector for correlation with other security events and automated incident response.
- **Unified Audit Log**: Microsoft 365 audit service recording all DLP policy match events (RecordType "DLP") with detailed match metadata for compliance reporting and forensic investigation.

## Common Scenarios

### Scenario: Protecting Financial Data Across a Multinational Organization

**Context**: A financial services company with 15,000 users across 12 countries needs to prevent credit card numbers, bank account details, and financial statements from being shared externally through email, Teams, SharePoint, and endpoint file operations. The company must comply with PCI-DSS and GDPR.

**Approach**:
1. Design a four-tier sensitivity label taxonomy: Public, Internal, Confidential (with sub-labels for Finance, Legal, HR), and Highly Confidential. Publish labels to all users with "Internal" as the default label and mandatory labeling enabled for email.
2. Create a DLP policy "PCI-DSS Financial Data Protection" scoped to all Exchange, SharePoint, OneDrive, Teams, and Endpoint locations. Configure two rules: a warning rule for 1-4 credit card numbers (notify user, allow override with justification) and a blocking rule for 5+ credit card numbers (block external sharing, generate incident report to compliance team).
3. Deploy endpoint DLP with rules blocking copy-to-USB and upload-to-unapproved-cloud for any file containing credit card numbers or labeled "Confidential - Finance". Allow printing with audit logging. Configure approved USB device exceptions for encrypted corporate drives by vendor/product ID.
4. Create auto-labeling policies that scan existing SharePoint finance sites and OneDrive locations, automatically applying "Confidential - Finance" to documents matching credit card number or bank account number SITs with confidence level 85+.
5. Run all policies in simulation mode for 14 days. Review Activity Explorer for false positive rates, override patterns, and unprotected sensitive content locations. Tune SIT confidence thresholds from 75 to 85 on the credit card SIT after identifying false positives from partial number sequences in meeting notes.
6. Switch to enforcement mode after stakeholder sign-off. Configure DLP alerts with Microsoft Sentinel integration for real-time incident correlation. Schedule monthly Activity Explorer reviews to track policy effectiveness metrics.

**Pitfalls**:
- Deploying DLP policies in enforcement mode without simulation, causing mass blocking of legitimate business communications and user productivity disruption
- Using low confidence thresholds (65) for SITs, generating excessive false positives that erode user trust and lead to policy override fatigue
- Not configuring endpoint DLP exceptions for approved encrypted USB devices, blocking legitimate data transfers to authorized external parties
- Forgetting to publish sensitivity labels via a label policy after creation, resulting in labels being invisible to end users in Office applications
- Not coordinating auto-labeling deployment with document library owners, leading to unexpected label changes on existing content that alter access permissions

### Scenario: Implementing Custom DLP for Intellectual Property Protection

**Context**: A pharmaceutical company needs to prevent research data identified by internal project codes (format: RX-YYYY-NNNN) and compound identifiers from being shared outside the research department. The data appears in lab reports, research presentations, and email communications.

**Approach**:
1. Create a custom sensitive information type using regex `RX-20[2-3][0-9]-[0-9]{4}` with corroborating keywords ("compound", "trial", "formulation", "assay", "efficacy") within 300-character proximity. Set primary pattern at 85% confidence and keyword-corroborated pattern at 95%.
2. Create a second custom SIT for compound identifiers using regex `CPD-[A-Z]{3}-[0-9]{5}` with keywords ("molecule", "synthesis", "pharmacokinetics") for higher confidence matching.
3. Deploy a DLP policy scoped to the Research department's Exchange distribution list, SharePoint research site collection, and research team OneDrive accounts. Block external sharing, block forwarding to non-research internal users, and generate alerts for the research compliance officer.
4. Configure endpoint DLP to prevent copy-to-USB and screen capture of documents containing the custom SITs on research department laptops. Allow printing only to approved secure printers in the research facility.
5. Create a sensitivity label "Highly Confidential - Research" with encryption restricting access to the Research security group. Configure auto-labeling to apply this label to documents matching either custom SIT.
6. Monitor Activity Explorer weekly for 30 days post-deployment. The compliance team identifies that the RX-YYYY-NNNN regex matches historical project codes in archived documents. Refine the regex to `RX-202[4-6]-[0-9]{4}` to target only active project codes and reduce false positives by 60%.

**Pitfalls**:
- Using positional regex anchors (^ and $) in custom SITs, which do not work as expected in Microsoft Purview regex evaluation and cause pattern match failures
- Setting MinCount too low (1) for the project code SIT without keyword corroboration, matching isolated instances in general business correspondence that happen to follow the same format
- Not testing the custom SIT against a representative sample corpus before deploying the DLP policy, missing edge cases in the regex pattern
- Scoping the policy too broadly (entire organization) instead of targeting the research department, causing alerts on legitimate references to project codes in executive summaries

## Output Format

```
## DLP Policy Deployment Report

**Policy Name**: PCI-DSS Financial Data Protection
**Deployment Date**: 2026-03-19
**Current Mode**: Simulation (TestWithNotifications)
**Locations**: Exchange Online, SharePoint Online, OneDrive, Teams, Endpoints

---

### Simulation Results (14-Day Period)

**Total Policy Matches**: 4,287
**Unique Users Affected**: 892
**Unique Files/Messages**: 3,641

| Rule | Matches | Action | Override Rate |
|------|---------|--------|---------------|
| Block Bulk Credit Card Sharing (5+) | 47 | Block | N/A |
| Warn on Credit Card Sharing (1-4) | 4,240 | Warn | 12.3% |

### Sensitive Information Type Breakdown

| SIT | Matches | Avg Confidence | False Positive Est. |
|-----|---------|----------------|---------------------|
| Credit Card Number | 3,891 | 87% | 8.2% |
| U.S. Bank Account Number | 312 | 82% | 15.1% |
| ABA Routing Number | 84 | 79% | 22.6% |

### Recommendations

1. **Enable enforcement** for "Block Bulk Credit Card Sharing" rule -
   47 matches are all true positives involving bulk credit card data in
   spreadsheet attachments.

2. **Increase confidence threshold** for ABA Routing Number from 75 to 85 -
   22.6% false positive rate driven by 9-digit numbers in invoice references
   matching the routing number pattern.

3. **Add file type exception** for password-protected ZIP attachments that
   trigger false positives when the credit card SIT matches encrypted content
   metadata.

4. **Deploy endpoint DLP** in audit mode for 7 additional days before
   enabling block actions on USB copy and cloud upload.

---

### DLP Alert Summary (Last 7 Days)

| Severity | Count | Top Policy | Top User |
|----------|-------|------------|----------|
| High | 12 | Financial Data Protection | j.smith@contoso.com |
| Medium | 89 | IP Protection - Research | r.chen@contoso.com |
| Low | 234 | General PII Protection | (distributed) |

### Activity Explorer Insights

- Peak DLP match activity: Monday 09:00-11:00 UTC (weekly report distribution)
- Top matched location: Finance SharePoint site (62% of all matches)
- Most overridden rule: "Warn on Credit Card Sharing" (523 overrides, 12.3%)
- Override justification analysis: 78% "Business requirement", 15% "False positive",
  7% "Other"
```
