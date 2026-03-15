# Standards and References - T1548 Elevation Control Abuse

## MITRE ATT&CK Sub-Techniques

| Sub-Technique | Platform | Description |
|--------------|----------|-------------|
| T1548.001 | Linux/macOS | Setuid and Setgid binary abuse |
| T1548.002 | Windows | Bypass User Account Control |
| T1548.003 | Linux/macOS | Sudo and Sudo Caching |
| T1548.004 | macOS | Elevated Execution with Prompt |

## Known UAC Bypass Methods (60+ documented)

| Method | Binary | Registry Key | Detection |
|--------|--------|-------------|-----------|
| fodhelper | fodhelper.exe | ms-settings\shell\open\command | Registry + process creation |
| eventvwr | eventvwr.exe | mscfile\shell\open\command | Registry + process creation |
| sdclt | sdclt.exe | exefile\shell\open\command | Registry + process creation |
| computerdefaults | computerdefaults.exe | ms-settings\shell\open\command | Registry + process creation |
| CMSTP | cmstp.exe | N/A (INF file) | Process creation with /s /ni |
| slui | slui.exe | exefile\shell\open\command | Registry + process creation |
| DiskCleanup | cleanmgr.exe | Environment variable hijack | Environment + process |

## UAC-Related Registry Keys to Monitor

| Registry Key | Purpose |
|-------------|---------|
| HKCU\Software\Classes\ms-settings\shell\open\command | fodhelper/computerdefaults bypass |
| HKCU\Software\Classes\mscfile\shell\open\command | eventvwr bypass |
| HKCU\Software\Classes\exefile\shell\open\command | sdclt/slui bypass |
| HKCU\Software\Classes\Folder\shell\open\command | Folder handler bypass |
| HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA | UAC disable |
| HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin | UAC level |

## Detection Events

| Source | Event ID | Description |
|--------|----------|-------------|
| Sysmon | 1 | Auto-elevate process creation |
| Sysmon | 12 | Registry key creation (UAC keys) |
| Sysmon | 13 | Registry value modification |
| Security | 4688 | Process creation with elevation |
| Security | 4657 | Registry value modification audit |
