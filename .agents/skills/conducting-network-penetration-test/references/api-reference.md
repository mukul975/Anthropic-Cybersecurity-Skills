# API Reference: Network Penetration Testing Agent

## Overview

Automates network penetration testing: host discovery, TCP SYN scanning with service detection, vulnerability scanning with NSE scripts, SMB enumeration, and SSL auditing. For authorized penetration testing only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| python-nmap | >=0.7.1 | Nmap scan orchestration |

## CLI Usage

```bash
# Full pentest
python agent.py --target 192.168.1.0/24 --ports 1-10000 --output report.json

# Host discovery only
python agent.py --target 10.0.0.0/24 --discovery-only
```

## Key Functions

### `host_discovery(target_network)`
Discovers live hosts using ARP ping and ICMP echo with TCP ACK probes on common ports.

### `port_scan(target, ports, scan_type)`
Performs TCP SYN scan with service version detection (`-sV`), OS detection (`-O`), and banner grabbing.

### `vulnerability_scan(target, ports)`
Runs Nmap vulnerability scripts (`vulners`, `vulscan`) to identify CVEs for detected services.

### `smb_enumeration(target)`
Enumerates SMB shares, users, and OS information via Nmap scripts on ports 139/445.

### `ssl_audit(target, port)`
Audits SSL/TLS cipher suites and certificate details using `ssl-enum-ciphers` and `ssl-cert`.

### `dns_enumeration(domain)`
Performs DNS subdomain brute-forcing using `dns-brute` NSE script.

### `classify_findings(scan_results, vuln_results)`
Classifies vulnerabilities by severity (Critical, High, Medium) based on script output analysis.

## Nmap Scan Types Used

| Argument | Purpose |
|----------|---------|
| `-sn -PE -PA` | Host discovery (ping scan) |
| `-sS -sV -O` | SYN scan with version and OS detection |
| `--script=vulners` | CVE vulnerability lookup |
| `--script=smb-enum-shares` | SMB share enumeration |
| `--script=ssl-enum-ciphers` | SSL/TLS cipher audit |
| `--script=dns-brute` | DNS subdomain enumeration |

## Output Schema

```json
{
  "hosts": [{"ip": "...", "hostname": "..."}],
  "services": [{"ip": "...", "services": [{"port": 80, "service": "http"}]}],
  "vulnerabilities": [{"host": "...", "severity": "Critical", "details": {...}}],
  "summary": {"critical": 3, "high": 12, "medium": 45}
}
```
