# AppLocker Application Whitelisting Template

## Policy Information

| Field | Value |
|-------|-------|
| Policy Name | |
| Target OS | Windows 10/11 Enterprise |
| Profile | Workstation / Server / Kiosk |
| Enforcement Mode | Audit Only / Enforce |
| GPO Name | |
| Target OU | |
| Last Updated | |

## Approved Application Inventory

| Application | Publisher | Version | Rule Type | Justification |
|------------|----------|---------|-----------|---------------|
| Microsoft Office | Microsoft Corporation | 365 | Publisher | Business productivity |
| Google Chrome | Google LLC | * | Publisher | Approved browser |
| Adobe Acrobat | Adobe Inc. | * | Publisher | PDF processing |
| | | | | |

## Rule Collection Configuration

### Executable Rules (EXE, COM)

| Rule Name | Type | Action | Scope | Conditions |
|-----------|------|--------|-------|------------|
| Default - Windows | Path | Allow | Everyone | %WINDIR%\* |
| Default - Program Files | Path | Allow | Everyone | %PROGRAMFILES%\* |
| Deny - LOLBins | Path | Deny | Standard Users | mshta.exe, wscript.exe, etc. |
| | | | | |

### Script Rules (PS1, BAT, CMD, VBS, JS)

| Rule Name | Type | Action | Scope | Conditions |
|-----------|------|--------|-------|------------|
| Default - Windows scripts | Path | Allow | Everyone | %WINDIR%\* |
| Default - Program Files scripts | Path | Allow | Everyone | %PROGRAMFILES%\* |
| Deny - User profile scripts | Path | Deny | Standard Users | %USERPROFILE%\* |
| | | | | |

### Windows Installer Rules (MSI, MSP, MST)

| Rule Name | Type | Action | Scope | Conditions |
|-----------|------|--------|-------|------------|
| Default - Signed MSI | Publisher | Allow | Everyone | All signed installers |
| | | | | |

## LOLBin Deny List

| Binary | Path | ATT&CK Technique | Risk |
|--------|------|------------------|------|
| mshta.exe | %SYSTEM32% | T1218.005 | HTA execution for code delivery |
| wscript.exe | %SYSTEM32% | T1059.005 | VBScript execution |
| cscript.exe | %SYSTEM32% | T1059.005 | Command-line scripting |
| regsvr32.exe | %SYSTEM32% | T1218.010 | COM scriptlet execution |
| certutil.exe | %SYSTEM32% | T1140 | File download and decode |
| msbuild.exe | .NET Framework | T1127.001 | Inline task execution |

## Audit Results Tracking

| Audit Period | Blocked Events | Legitimate Blocks | Rules Added | Remaining Issues |
|-------------|---------------|-------------------|-------------|-----------------|
| | | | | |

## Exception Register

| Application | Reason for Exception | Compensating Control | Approved By | Review Date |
|------------|---------------------|---------------------|-------------|-------------|
| | | | | |

## Sign-Off

| Role | Name | Date |
|------|------|------|
| Security Engineer | | |
| IT Operations Lead | | |
| Change Manager | | |
