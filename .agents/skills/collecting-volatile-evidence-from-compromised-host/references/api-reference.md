# API Reference: Collecting Volatile Evidence from Compromised Host

## RFC 3227 Order of Volatility
| Priority | Source | Persistence |
|----------|--------|------------|
| 1 | CPU registers, cache | Nanoseconds |
| 2 | Physical memory (RAM) | Power cycle |
| 3 | Network state | Seconds-minutes |
| 4 | Running processes | Minutes |
| 5 | Disk (filesystem) | Persistent |
| 6 | Remote logging / monitoring | Persistent |
| 7 | Physical configuration | Persistent |
| 8 | Archival media | Long-term |

## Memory Acquisition Tools
| Tool | Platform | Command |
|------|----------|---------|
| AVML | Linux | `avml /path/to/output.lime` |
| WinPmem | Windows | `winpmem_mini_x64.exe output.raw` |
| LiME | Linux | `insmod lime.ko "path=/tmp/mem.lime format=lime"` |
| Magnet RAM Capture | Windows | GUI-based acquisition |

## Linux Collection Commands
```bash
# Network connections
ss -tunap > /evidence/netstat.txt

# Process list with tree
ps auxwwf > /evidence/processes.txt

# Open files
lsof -nP > /evidence/open_files.txt

# Network config
ip addr show > /evidence/ifconfig.txt
ip route show > /evidence/routes.txt
ip neigh show > /evidence/arp.txt

# Logged-in users
w > /evidence/users.txt
last -50 > /evidence/last_logins.txt

# Cron jobs
crontab -l > /evidence/crontab.txt
ls -la /etc/cron.d/ >> /evidence/crontab.txt
```

## Windows Collection Commands
```cmd
:: Network connections
netstat -anob > C:\evidence\netstat.txt

:: Process list
tasklist /V /FO CSV > C:\evidence\processes.csv
wmic process get ProcessId,Name,CommandLine /format:csv > C:\evidence\wmic_procs.csv

:: Network config
ipconfig /all > C:\evidence\ipconfig.txt
route print > C:\evidence\routes.txt
arp -a > C:\evidence\arp.txt

:: DNS cache
ipconfig /displaydns > C:\evidence\dns_cache.txt

:: Scheduled tasks
schtasks /query /FO CSV /V > C:\evidence\schtasks.csv

:: Logged-in users
query user > C:\evidence\users.txt
```

## Evidence Integrity
```bash
# Hash collected files
sha256sum /evidence/*.txt > /evidence/checksums.sha256

# Verify later
sha256sum -c /evidence/checksums.sha256
```
