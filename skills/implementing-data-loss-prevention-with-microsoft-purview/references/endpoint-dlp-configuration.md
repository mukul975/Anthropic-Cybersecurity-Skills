# Endpoint DLP Configuration (Step 3 detail)

Full PowerShell for extending DLP protection to managed Windows and macOS endpoints: device onboarding verification, endpoint DLP global settings, endpoint-specific rules, and printer/USB device group definitions.

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

