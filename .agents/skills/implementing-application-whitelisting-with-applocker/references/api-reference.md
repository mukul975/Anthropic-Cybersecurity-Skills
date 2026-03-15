# API Reference: Implementing Application Whitelisting with AppLocker

## PowerShell AppLocker Management

```powershell
# Export current policy
Get-AppLockerPolicy -Effective -Xml | Out-File applocker_policy.xml

# Import policy from XML
Set-AppLockerPolicy -XmlPolicy applocker_policy.xml

# Test if file is allowed
Test-AppLockerPolicy -XmlPolicy policy.xml -Path "C:\app.exe" -User Everyone

# Get AppLocker event logs
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL"
```

## AppLocker Event IDs

| Event ID | Type | Meaning |
|----------|------|---------|
| 8002 | EXE/DLL | Allowed |
| 8003 | EXE/DLL | Blocked |
| 8004 | EXE/DLL | Would block (audit) |
| 8005 | Script | Allowed |
| 8006 | Script | Blocked |
| 8007 | Script | Would block (audit) |

## Rule Collections

| Collection | File Types |
|------------|------------|
| Executable | .exe, .com |
| Windows Installer | .msi, .msp, .mst |
| Script | .ps1, .bat, .cmd, .vbs, .js |
| DLL | .dll, .ocx |
| Packaged App | AppX/MSIX |

## GPO Configuration Path

```
Computer Configuration > Policies > Windows Settings >
  Security Settings > Application Control Policies > AppLocker
```

## Default Rule Paths

```
%PROGRAMFILES%\*     - Allow Everyone
%WINDIR%\*           - Allow Everyone
*                    - Allow BUILTIN\Administrators
```

### References

- AppLocker: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview
- AppLocker PowerShell: https://learn.microsoft.com/en-us/powershell/module/applocker/
