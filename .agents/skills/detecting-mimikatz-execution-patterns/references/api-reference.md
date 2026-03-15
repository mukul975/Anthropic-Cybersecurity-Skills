# API Reference: Detecting Mimikatz Execution Patterns

## Mimikatz Command Signatures

| Command | MITRE | Impact |
|---------|-------|--------|
| `sekurlsa::logonpasswords` | T1003.001 | Dump all credentials |
| `lsadump::dcsync` | T1003.006 | DCSync attack |
| `kerberos::golden` | T1558.001 | Golden Ticket |
| `kerberos::ptt` | T1550.003 | Pass-the-Ticket |
| `lsadump::sam` | T1003.002 | SAM dump |
| `misc::skeleton` | T1556.001 | Skeleton Key |

## LSASS Dump Techniques

| Method | Detection Pattern |
|--------|-------------------|
| comsvcs.dll MiniDump | `rundll32.*comsvcs.*MiniDump` |
| ProcDump | `procdump.*-ma.*lsass` |
| SQLDumper | `sqldumper.*lsass` |
| .NET createdump | `createdump.*lsass` |
| PowerShell | `Out-Minidump.*lsass` |

## Sysmon Detection Events

| Event ID | Usage |
|----------|-------|
| 1 | Process Create (mimikatz.exe) |
| 7 | Image Loaded (sekurlsa.dll) |
| 10 | Process Access (LSASS access mask) |

## Splunk SPL Detection

```spl
index=sysmon (EventCode=1 OR EventCode=10)
| where match(CommandLine, "(?i)(sekurlsa|lsadump|kerberos::golden|privilege::debug)")
   OR (TargetImage="*\\lsass.exe" AND GrantedAccess IN ("0x1010","0x1FFFFF"))
| table _time Image CommandLine GrantedAccess Computer
```

## YARA Rule

```yara
rule Mimikatz_Strings {
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide
        $s2 = "lsadump::dcsync" ascii wide
        $s3 = "kerberos::golden" ascii wide
        $s4 = "mimilib" ascii wide
    condition:
        any of them
}
```

## CLI Usage

```bash
python agent.py --evtx-file Sysmon.evtx
python agent.py --text-log process_audit.log
```
