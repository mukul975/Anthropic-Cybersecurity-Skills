# SpiderFoot OSINT API Reference

## REST API Endpoints

### List Modules
```
GET /api/modules
Response: [{"name": "sfp_dnsresolve", "descr": "...", "group": "Footprint", "provides": [...]}]
```

### Start Scan
```
POST /api/startscan
Content-Type: application/x-www-form-urlencoded

scanname=my-scan&scantarget=example.com&usecase=footprint
Response: {"scanid": "abc123"}
```

### Check Scan Status
```
GET /api/scanstatus/{scan_id}
Response: {"status": "RUNNING"}  # RUNNING, FINISHED, ABORTED, ERROR-FAILED
```

### Get Scan Results
```
GET /api/scanresults/{scan_id}
Response: [{"type": "INTERNET_NAME", "data": "sub.example.com", "module": "sfp_dnsresolve", "source": "example.com"}]
```

### Delete Scan
```
GET /api/scandelete/{scan_id}
```

### List Scans
```
GET /api/scanlist
```

## Scan Use Cases
| Use Case | Description |
|---|---|
| all | All modules (slowest, most comprehensive) |
| footprint | Attack surface mapping: subdomains, IPs, ports |
| investigate | Deep analysis: WHOIS, DNS, reputation checks |
| passive | Passive only: no active probing of target |

## Data Element Types
| Type | Description |
|---|---|
| INTERNET_NAME | Discovered domain/subdomain |
| IP_ADDRESS | IP addresses |
| EMAILADDR | Email addresses |
| LEAKSITE_CONTENT | Leaked credentials/data |
| DNS_TEXT | DNS TXT/MX/NS records |
| LINKED_URL_INTERNAL | URLs on target domain |
| CO_HOSTED_SITE | Sites sharing same IP |
| AFFILIATE_INTERNET_NAME | Related domains |

## CLI Usage (sf.py)
```bash
# Start scan via CLI
python sf.py -s example.com -t INTERNET_NAME,IP_ADDRESS -m sfp_dnsresolve,sfp_portscan_tcp

# Passive footprint
python sf.py -s example.com -u passive

# List modules
python sf.py -M
```

## Agent CLI Usage
```bash
python agent.py --target example.com --use-case footprint --output report.json
python agent.py --target 203.0.113.5 --use-case investigate --timeout 1200
python agent.py --list-modules --server http://spiderfoot:5001
```
