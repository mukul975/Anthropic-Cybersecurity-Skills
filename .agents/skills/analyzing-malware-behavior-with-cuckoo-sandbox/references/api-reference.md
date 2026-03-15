# API Reference: Cuckoo Sandbox

## Cuckoo CLI

### Sample Submission
```bash
cuckoo submit /path/to/sample.exe
cuckoo submit --timeout 300 /path/to/sample.exe
cuckoo submit --machine win10_x64 --package exe sample.exe
cuckoo submit --url "http://malicious-url.com"
```

### Status
```bash
cuckoo status
tail -f /opt/cuckoo/log/cuckoo.log
```

## Cuckoo REST API

### Submit File
```bash
curl -F "file=@sample.exe" -F "timeout=300" \
  http://localhost:8090/tasks/create/file
```
Response: `{"task_id": 1}`

### Submit URL
```bash
curl -F "url=http://malicious.com" -F "timeout=300" \
  http://localhost:8090/tasks/create/url
```

### Check Task Status
```bash
curl http://localhost:8090/tasks/view/<task_id>
```
Status values: `pending`, `running`, `completed`, `reported`

### Get Report
```bash
curl http://localhost:8090/tasks/report/<task_id>
curl http://localhost:8090/tasks/report/<task_id>/json
```

### List Tasks
```bash
curl http://localhost:8090/tasks/list
curl http://localhost:8090/tasks/list?limit=50&offset=0
```

## Report JSON Structure

### Key Paths
| Path | Content |
|------|---------|
| `info.score` | Threat score (0-10) |
| `info.duration` | Analysis duration (seconds) |
| `behavior.processes` | Process tree with API calls |
| `behavior.summary.files` | Created/modified files |
| `behavior.summary.keys` | Modified registry keys |
| `network.dns` | DNS resolutions |
| `network.http` | HTTP requests |
| `network.tcp` | TCP connections |
| `dropped` | Dropped files with hashes |
| `signatures` | Triggered behavioral signatures |

### Signature Severity Levels
| Level | Meaning |
|-------|---------|
| 1 | Informational |
| 2 | Low |
| 3 | Medium |
| 4 | High |
| 5 | Critical |

## Analysis Packages

| Package | File Type |
|---------|-----------|
| `exe` | Windows executables |
| `dll` | DLL files (uses rundll32) |
| `doc` | Word documents |
| `xls` | Excel spreadsheets |
| `pdf` | PDF documents |
| `js` | JavaScript files |
| `vbs` | VBScript files |
| `ps1` | PowerShell scripts |
| `zip` | Archives (auto-extracted) |

## InetSim - Network Simulation

### Syntax
```bash
inetsim --bind-address 192.168.56.1
inetsim --report-dir /var/log/inetsim
```

### Simulated Services
- HTTP/HTTPS (ports 80, 443)
- DNS (port 53)
- SMTP (port 25)
- FTP (port 21)
- IRC (port 6667)

## FakeNet-NG - Network Redirection

### Syntax
```bash
fakenet
fakenet -c custom_config.ini
```

## Volatility Integration

### Syntax
```bash
vol3 -f /opt/cuckoo/storage/analyses/<id>/memory.dmp windows.pslist
vol3 -f /opt/cuckoo/storage/analyses/<id>/memory.dmp windows.malfind
vol3 -f /opt/cuckoo/storage/analyses/<id>/memory.dmp windows.netscan
```
