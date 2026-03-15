# API Reference: Malware Eradication

## Windows Process Termination

### taskkill
```cmd
taskkill /F /PID 1234           # Kill by PID
taskkill /F /IM malware.exe     # Kill by name
taskkill /F /T /PID 1234       # Kill process tree
```

### PowerShell
```powershell
Stop-Process -Id 1234 -Force
Get-Process -Name "malware" | Stop-Process -Force
```

## Windows Persistence Cleanup

### Registry Run Keys
```cmd
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v MalwareName /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v MalwareName /f
```

### Scheduled Tasks
```cmd
schtasks /Delete /TN "MalwareTask" /F
schtasks /Query /FO CSV /V /NH
```

### Services
```cmd
sc stop MalwareService
sc delete MalwareService
sc query type= all state= all
```

## Linux Persistence Cleanup

### Crontab
```bash
crontab -l -u root         # List root cron
crontab -r -u root         # Remove all cron (use carefully)
ls -la /etc/cron.d/
ls -la /var/spool/cron/
```

### Systemd Services
```bash
systemctl list-unit-files --type=service
systemctl disable malware.service
systemctl stop malware.service
rm /etc/systemd/system/malware.service
systemctl daemon-reload
```

### Process Kill
```bash
kill -9 <pid>
pkill -f "malware_pattern"
```

## File Quarantine Best Practices

### Hash Before Move
```bash
sha256sum /path/to/malware > /quarantine/hash.txt
```

### Secure Move
```bash
mv /path/to/malware /quarantine/sha256_filename.quarantine
chmod 000 /quarantine/sha256_filename.quarantine
```

## Autoruns (Sysinternals)

### Command Line
```cmd
autorunsc.exe -a * -c -h -s -v -vt
```

### Output Columns
| Column | Description |
|--------|-------------|
| Entry | Autorun name |
| Image Path | Binary location |
| Signer | Code signing info |
| VT Detection | VirusTotal results |

## YARA Scanning for Remaining Artifacts

### Command
```bash
yara -r rules.yar /target/directory
```

### Rule Example
```yara
rule Malware_Remnant {
    strings:
        $s1 = "malware_mutex" ascii
        $s2 = {4D 5A 90 00}
    condition:
        any of them
}
```
