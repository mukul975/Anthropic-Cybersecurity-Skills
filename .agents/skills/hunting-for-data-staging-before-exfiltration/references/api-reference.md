# Data Staging Detection API Reference

## MITRE ATT&CK T1074 — Data Staged

- **T1074.001** Local Data Staging — Files consolidated on the local system before exfiltration
- **T1074.002** Remote Data Staging — Files staged on a remote system or network share
- **T1560.001** Archive via Utility — Data compressed using 7-Zip, RAR, tar, etc.

## Archive Tool Detection Signatures

### 7-Zip (7z.exe)
```
7z.exe a -pPASSWORD -mhe=on archive.7z C:\Users\target\Documents\*
7z.exe a -v50m split_archive.7z C:\sensitive\data\
```

### WinRAR (rar.exe)
```
rar.exe a -hp"password" -r archive.rar C:\Users\*\Documents\
winrar.exe a -p"pass" -ep1 exfil.rar @filelist.txt
```

### PowerShell Compress-Archive
```powershell
Compress-Archive -Path C:\StagingDir\* -DestinationPath C:\Temp\data.zip
```

### makecab.exe (LOLBin)
```
makecab.exe C:\sensitive\file.docx C:\Temp\file.cab
```

## Sysmon Detection Queries

### Sysmon Event ID 1 — Archive Process Creation
```
EventID=1 AND (Image="*7z.exe" OR Image="*rar.exe" OR Image="*tar*")
  AND CommandLine="*-p*"
```

### Sysmon Event ID 11 — File Create in Staging Directory
```
EventID=11 AND (TargetFilename="*\\Temp\\*.zip" OR TargetFilename="*\\Temp\\*.7z"
  OR TargetFilename="*\\ProgramData\\*.rar")
```

## Splunk SPL Queries

```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(7z|rar|winrar|tar|zip)\.exe$")
| stats count by User, Image, CommandLine, ParentImage
| where count > 3

index=sysmon EventCode=11
| where match(TargetFilename, "(?i)\\\\(temp|programdata|\\$recycle)\\\\.*\.(zip|7z|rar|tar)")
| stats dc(TargetFilename) as unique_files, sum(FileSize) as total_bytes by User
| where total_bytes > 104857600
```

## Elastic KQL Queries

```
process.name: ("7z.exe" or "rar.exe" or "winrar.exe")
  and process.args: ("-p*" or "-hp*" or "-mhe=on")

file.path: (*\\Temp\\*.zip or *\\Temp\\*.7z or *\\ProgramData\\*.rar)
  and event.action: "creation"
```

## Common Staging Directories

| OS | Directories |
|----|-------------|
| Windows | `C:\Windows\Temp`, `C:\Users\Public`, `C:\ProgramData`, `C:\$Recycle.Bin`, `C:\PerfLogs` |
| Linux | `/tmp`, `/var/tmp`, `/dev/shm` |

## Atomic Red Team Test (T1074.001)

```bash
# Simulate local data staging
mkdir /tmp/staging
cp /home/user/Documents/*.pdf /tmp/staging/
tar -czf /tmp/staging/exfil.tar.gz /tmp/staging/*.pdf
```
