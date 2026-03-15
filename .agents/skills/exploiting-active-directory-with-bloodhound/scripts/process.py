#!/usr/bin/env python3
"""
BloodHound AD Attack Path Analyzer

Processes BloodHound data exports to identify and prioritize attack paths:
- Parses BloodHound JSON/ZIP exports
- Identifies high-value targets and attack paths
- Generates attack chain reports
- Exports custom Cypher queries
- Creates visual attack path documentation

Usage:
    python process.py --import-data bloodhound_data.zip --analyze
    python process.py --query kerberoastable --domain targetdomain.local
    python process.py --generate-report --output ./ad_report

Requirements:
    pip install rich neo4j zipfile36
"""

import argparse
import json
import os
import sys
import zipfile
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.tree import Tree
except ImportError:
    print("[!] Missing dependencies. Install with: pip install rich")
    sys.exit(1)

console = Console()


class BloodHoundAnalyzer:
    """Analyzes BloodHound collection data for attack path identification."""

    def __init__(self):
        self.users = []
        self.computers = []
        self.groups = []
        self.domains = []
        self.gpos = []
        self.ous = []
        self.sessions = []
        self.local_admins = []
        self.domain_name = ""

    def import_zip(self, zip_path: str):
        """Import BloodHound ZIP export."""
        console.print(f"[yellow][*] Importing data from {zip_path}...[/yellow]")

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                for filename in zf.namelist():
                    if not filename.endswith(".json"):
                        continue

                    with zf.open(filename) as f:
                        data = json.loads(f.read())

                    if "users" in filename.lower() or (isinstance(data, dict) and data.get("meta", {}).get("type") == "users"):
                        self._process_users(data)
                    elif "computers" in filename.lower() or (isinstance(data, dict) and data.get("meta", {}).get("type") == "computers"):
                        self._process_computers(data)
                    elif "groups" in filename.lower() or (isinstance(data, dict) and data.get("meta", {}).get("type") == "groups"):
                        self._process_groups(data)
                    elif "domains" in filename.lower() or (isinstance(data, dict) and data.get("meta", {}).get("type") == "domains"):
                        self._process_domains(data)
                    elif "gpos" in filename.lower() or (isinstance(data, dict) and data.get("meta", {}).get("type") == "gpos"):
                        self._process_gpos(data)
                    elif "ous" in filename.lower() or (isinstance(data, dict) and data.get("meta", {}).get("type") == "ous"):
                        self._process_ous(data)

            console.print(f"[green][+] Imported: {len(self.users)} users, {len(self.computers)} computers, {len(self.groups)} groups[/green]")

        except Exception as e:
            console.print(f"[red][-] Import failed: {e}[/red]")

    def _process_users(self, data):
        """Process user data from BloodHound export."""
        items = data.get("data", data) if isinstance(data, dict) else data
        if isinstance(items, dict):
            items = items.get("data", [])

        for user in items:
            props = user.get("Properties", user.get("properties", {}))
            self.users.append({
                "name": props.get("name", ""),
                "displayname": props.get("displayname", ""),
                "enabled": props.get("enabled", True),
                "hasspn": props.get("hasspn", False),
                "dontreqpreauth": props.get("dontreqpreauth", False),
                "admincount": props.get("admincount", False),
                "unconstraineddelegation": props.get("unconstraineddelegation", False),
                "passwordnotreqd": props.get("passwordnotreqd", False),
                "sensitive": props.get("sensitive", False),
                "lastlogon": props.get("lastlogon", 0),
                "pwdlastset": props.get("pwdlastset", 0),
                "serviceprincipalnames": props.get("serviceprincipalnames", []),
                "sidhistory": props.get("sidhistory", []),
                "description": props.get("description", ""),
            })

    def _process_computers(self, data):
        """Process computer data from BloodHound export."""
        items = data.get("data", data) if isinstance(data, dict) else data
        if isinstance(items, dict):
            items = items.get("data", [])

        for computer in items:
            props = computer.get("Properties", computer.get("properties", {}))
            self.computers.append({
                "name": props.get("name", ""),
                "operatingsystem": props.get("operatingsystem", ""),
                "enabled": props.get("enabled", True),
                "unconstraineddelegation": props.get("unconstraineddelegation", False),
                "allowedtodelegate": props.get("allowedtodelegate", []),
                "haslaps": props.get("haslaps", False),
                "lastlogontimestamp": props.get("lastlogontimestamp", 0),
            })

    def _process_groups(self, data):
        """Process group data from BloodHound export."""
        items = data.get("data", data) if isinstance(data, dict) else data
        if isinstance(items, dict):
            items = items.get("data", [])

        for group in items:
            props = group.get("Properties", group.get("properties", {}))
            members = group.get("Members", group.get("members", []))
            self.groups.append({
                "name": props.get("name", ""),
                "description": props.get("description", ""),
                "admincount": props.get("admincount", False),
                "member_count": len(members) if isinstance(members, list) else 0,
            })

    def _process_domains(self, data):
        """Process domain data."""
        items = data.get("data", data) if isinstance(data, dict) else data
        if isinstance(items, dict):
            items = items.get("data", [])

        for domain in items:
            props = domain.get("Properties", domain.get("properties", {}))
            self.domains.append({
                "name": props.get("name", ""),
                "functionallevel": props.get("functionallevel", ""),
            })
            if not self.domain_name:
                self.domain_name = props.get("name", "")

    def _process_gpos(self, data):
        """Process GPO data."""
        items = data.get("data", data) if isinstance(data, dict) else data
        if isinstance(items, dict):
            items = items.get("data", [])

        for gpo in items:
            props = gpo.get("Properties", gpo.get("properties", {}))
            self.gpos.append({
                "name": props.get("name", ""),
                "gpcpath": props.get("gpcpath", ""),
            })

    def _process_ous(self, data):
        """Process OU data."""
        items = data.get("data", data) if isinstance(data, dict) else data
        if isinstance(items, dict):
            items = items.get("data", [])

        for ou in items:
            props = ou.get("Properties", ou.get("properties", {}))
            self.ous.append({
                "name": props.get("name", ""),
                "description": props.get("description", ""),
            })

    def find_kerberoastable(self) -> list[dict]:
        """Find users with SPNs set (Kerberoastable)."""
        return [
            u for u in self.users
            if u.get("hasspn") and u.get("enabled", True)
        ]

    def find_asrep_roastable(self) -> list[dict]:
        """Find users without Kerberos pre-authentication."""
        return [
            u for u in self.users
            if u.get("dontreqpreauth") and u.get("enabled", True)
        ]

    def find_unconstrained_delegation(self) -> list[dict]:
        """Find computers with unconstrained delegation."""
        return [
            c for c in self.computers
            if c.get("unconstraineddelegation") and c.get("enabled", True)
        ]

    def find_constrained_delegation(self) -> list[dict]:
        """Find objects with constrained delegation."""
        results = []
        for c in self.computers:
            if c.get("allowedtodelegate"):
                results.append(c)
        for u in self.users:
            if u.get("serviceprincipalnames"):
                results.append(u)
        return results

    def find_privileged_users(self) -> list[dict]:
        """Find users with adminCount set."""
        return [
            u for u in self.users
            if u.get("admincount") and u.get("enabled", True)
        ]

    def find_password_not_required(self) -> list[dict]:
        """Find users with password not required flag."""
        return [
            u for u in self.users
            if u.get("passwordnotreqd") and u.get("enabled", True)
        ]

    def find_computers_without_laps(self) -> list[dict]:
        """Find computers without LAPS configured."""
        return [
            c for c in self.computers
            if not c.get("haslaps") and c.get("enabled", True)
        ]

    def find_legacy_os(self) -> list[dict]:
        """Find computers running legacy/unsupported operating systems."""
        legacy_patterns = [
            "Windows Server 2008", "Windows Server 2003", "Windows XP",
            "Windows 7", "Windows Vista", "Windows Server 2012",
        ]
        results = []
        for c in self.computers:
            os_name = c.get("operatingsystem", "")
            for pattern in legacy_patterns:
                if pattern.lower() in os_name.lower():
                    results.append(c)
                    break
        return results

    def find_users_with_sid_history(self) -> list[dict]:
        """Find users with SID History (potential for SID history injection)."""
        return [
            u for u in self.users
            if u.get("sidhistory") and len(u["sidhistory"]) > 0
        ]

    def get_os_distribution(self) -> dict:
        """Get operating system distribution across computers."""
        os_count = Counter()
        for c in self.computers:
            os_name = c.get("operatingsystem", "Unknown")
            os_count[os_name] += 1
        return dict(os_count.most_common())

    def generate_cypher_queries(self) -> list[dict]:
        """Generate useful Cypher queries for the domain."""
        domain = self.domain_name.upper() if self.domain_name else "TARGETDOMAIN.LOCAL"

        queries = [
            {
                "name": "Shortest Path to Domain Admins",
                "query": f'MATCH p=shortestPath((n)-[*1..]->(g:Group {{name:"DOMAIN ADMINS@{domain}"}})) WHERE n.owned=true RETURN p',
                "description": "Find shortest attack path from owned users to DA",
            },
            {
                "name": "Kerberoastable Users with Admin Rights",
                "query": "MATCH (u:User {hasspn:true, enabled:true})-[:AdminTo]->(c:Computer) RETURN u.name, COLLECT(c.name)",
                "description": "SPN accounts that are local admins",
            },
            {
                "name": "Unconstrained Delegation Computers (Non-DC)",
                "query": "MATCH (c:Computer {unconstraineddelegation:true}) WHERE NOT c.name CONTAINS 'DC' RETURN c.name, c.operatingsystem",
                "description": "Non-DC computers with unconstrained delegation",
            },
            {
                "name": "Users with DCSync Rights",
                "query": f'MATCH p=(n)-[:MemberOf|GetChanges|GetChangesAll*1..]->(d:Domain {{name:"{domain}"}}) RETURN p',
                "description": "Accounts that can perform DCSync",
            },
            {
                "name": "Computers Without LAPS",
                "query": "MATCH (c:Computer {haslaps:false, enabled:true}) RETURN c.name, c.operatingsystem ORDER BY c.name",
                "description": "Computers without LAPS for local admin persistence",
            },
            {
                "name": "High Value Group Members",
                "query": f'MATCH (u:User)-[:MemberOf*1..]->(g:Group {{highvalue:true}}) RETURN u.name, COLLECT(g.name)',
                "description": "Users in high-value groups",
            },
            {
                "name": "Sessions on High Value Targets",
                "query": "MATCH (c:Computer {highvalue:true})<-[:HasSession]-(u:User) RETURN c.name, COLLECT(u.name)",
                "description": "User sessions on high-value computers",
            },
            {
                "name": "GenericAll Rights on Users/Groups",
                "query": "MATCH p=(n)-[:GenericAll]->(m) WHERE (m:User OR m:Group) AND n<>m RETURN p",
                "description": "Objects with full control over users/groups",
            },
        ]

        return queries

    def generate_report(self, output_dir: str):
        """Generate comprehensive analysis report."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        kerberoastable = self.find_kerberoastable()
        asrep = self.find_asrep_roastable()
        unconstrained = self.find_unconstrained_delegation()
        privileged = self.find_privileged_users()
        no_password = self.find_password_not_required()
        no_laps = self.find_computers_without_laps()
        legacy = self.find_legacy_os()
        sid_history = self.find_users_with_sid_history()
        os_dist = self.get_os_distribution()
        queries = self.generate_cypher_queries()

        report = f"""# BloodHound Active Directory Analysis Report
## Domain: {self.domain_name or 'Unknown'}
## Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## 1. Environment Summary

| Category | Count |
|----------|-------|
| Users | {len(self.users)} |
| Computers | {len(self.computers)} |
| Groups | {len(self.groups)} |
| Domains | {len(self.domains)} |
| GPOs | {len(self.gpos)} |
| OUs | {len(self.ous)} |

## 2. High-Risk Findings

### 2.1 Kerberoastable Accounts ({len(kerberoastable)})

| Username | Display Name | Admin Count | SPNs |
|----------|-------------|-------------|------|
"""
        for u in kerberoastable[:20]:
            spns = ", ".join(u.get("serviceprincipalnames", [])[:2])
            report += f"| {u['name']} | {u.get('displayname', 'N/A')} | {u.get('admincount', False)} | {spns} |\n"

        report += f"""
### 2.2 AS-REP Roastable Accounts ({len(asrep)})

| Username | Display Name | Enabled |
|----------|-------------|---------|
"""
        for u in asrep[:20]:
            report += f"| {u['name']} | {u.get('displayname', 'N/A')} | {u.get('enabled', True)} |\n"

        report += f"""
### 2.3 Unconstrained Delegation ({len(unconstrained)})

| Computer | Operating System |
|----------|-----------------|
"""
        for c in unconstrained:
            report += f"| {c['name']} | {c.get('operatingsystem', 'N/A')} |\n"

        report += f"""
### 2.4 Privileged Accounts ({len(privileged)})

| Username | Admin Count | Sensitive |
|----------|-------------|-----------|
"""
        for u in privileged[:20]:
            report += f"| {u['name']} | {u.get('admincount', False)} | {u.get('sensitive', False)} |\n"

        report += f"""
### 2.5 Password Not Required ({len(no_password)})

| Username | Enabled | Last Logon |
|----------|---------|-----------|
"""
        for u in no_password[:20]:
            report += f"| {u['name']} | {u.get('enabled', True)} | {u.get('lastlogon', 'N/A')} |\n"

        report += f"""
### 2.6 Computers Without LAPS ({len(no_laps)})
Total: {len(no_laps)} out of {len(self.computers)} computers

### 2.7 Legacy Operating Systems ({len(legacy)})

| Computer | OS |
|----------|----|
"""
        for c in legacy[:20]:
            report += f"| {c['name']} | {c.get('operatingsystem', 'N/A')} |\n"

        report += f"""
### 2.8 SID History Users ({len(sid_history)})

| Username | SID History Count |
|----------|------------------|
"""
        for u in sid_history:
            report += f"| {u['name']} | {len(u.get('sidhistory', []))} |\n"

        report += """
## 3. Operating System Distribution

| Operating System | Count |
|-----------------|-------|
"""
        for os_name, count in os_dist.items():
            report += f"| {os_name} | {count} |\n"

        report += """
## 4. Recommended Cypher Queries

"""
        for q in queries:
            report += f"### {q['name']}\n"
            report += f"**Description:** {q['description']}\n"
            report += f"```cypher\n{q['query']}\n```\n\n"

        report += """
## 5. Recommended Attack Paths

### Priority 1: Kerberoasting
1. Request TGS tickets for Kerberoastable accounts
2. Crack tickets offline using hashcat/john
3. Use compromised accounts for lateral movement

### Priority 2: AS-REP Roasting
1. Request AS-REP for accounts without pre-auth
2. Crack hashes offline
3. Leverage any privileged access

### Priority 3: Unconstrained Delegation Abuse
1. Compromise computer with unconstrained delegation
2. Coerce authentication from high-value target (e.g., PrinterBug)
3. Capture TGT and impersonate target

### Priority 4: ACL Abuse Chains
1. Identify ACL-based paths from owned accounts
2. Chain GenericAll/GenericWrite/WriteDACL edges
3. Escalate to Domain Admin via ACL manipulation

---

*Report generated by BloodHound AD Analyzer*
"""

        report_path = out_path / f"bloodhound_analysis_{self.domain_name or 'unknown'}.md"
        with open(report_path, "w") as f:
            f.write(report)

        console.print(f"[green][+] Report saved to: {report_path}[/green]")

        # Save queries as JSON
        queries_path = out_path / "cypher_queries.json"
        with open(queries_path, "w") as f:
            json.dump(queries, f, indent=2)

        console.print(f"[green][+] Queries saved to: {queries_path}[/green]")


def display_summary(analyzer: BloodHoundAnalyzer):
    """Display analysis summary tables."""
    # Summary table
    table = Table(title="AD Environment Summary")
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="green")
    table.add_column("Risk Items", style="red")

    table.add_row("Users", str(len(analyzer.users)), str(len(analyzer.find_kerberoastable())) + " Kerberoastable")
    table.add_row("Computers", str(len(analyzer.computers)), str(len(analyzer.find_unconstrained_delegation())) + " Unconstrained Deleg")
    table.add_row("Groups", str(len(analyzer.groups)), str(len(analyzer.find_privileged_users())) + " Privileged Users")
    table.add_row("AS-REP Roastable", str(len(analyzer.find_asrep_roastable())), "High" if analyzer.find_asrep_roastable() else "None")
    table.add_row("No LAPS", str(len(analyzer.find_computers_without_laps())), "Medium-High")
    table.add_row("Legacy OS", str(len(analyzer.find_legacy_os())), "High")

    console.print(table)


def main():
    parser = argparse.ArgumentParser(
        description="BloodHound AD Attack Path Analyzer"
    )
    parser.add_argument("--import-data", help="Path to BloodHound ZIP export")
    parser.add_argument("--analyze", action="store_true", help="Run full analysis")
    parser.add_argument("--query", choices=["kerberoastable", "asrep", "unconstrained", "privileged", "legacy", "no-laps"],
                        help="Run specific query")
    parser.add_argument("--generate-report", action="store_true", help="Generate analysis report")
    parser.add_argument("--output", default="./bloodhound_report", help="Output directory")
    parser.add_argument("--domain", help="Domain name for query generation")

    args = parser.parse_args()

    analyzer = BloodHoundAnalyzer()

    if args.domain:
        analyzer.domain_name = args.domain

    if args.import_data:
        analyzer.import_zip(args.import_data)

    if args.analyze or args.generate_report:
        if not analyzer.users and not args.import_data:
            console.print("[red][-] No data loaded. Use --import-data to load BloodHound data.[/red]")
            return

        display_summary(analyzer)

        if args.generate_report:
            analyzer.generate_report(args.output)

    if args.query:
        query_map = {
            "kerberoastable": ("Kerberoastable Users", analyzer.find_kerberoastable),
            "asrep": ("AS-REP Roastable Users", analyzer.find_asrep_roastable),
            "unconstrained": ("Unconstrained Delegation", analyzer.find_unconstrained_delegation),
            "privileged": ("Privileged Users", analyzer.find_privileged_users),
            "legacy": ("Legacy OS Computers", analyzer.find_legacy_os),
            "no-laps": ("Computers Without LAPS", analyzer.find_computers_without_laps),
        }

        title, func = query_map[args.query]
        results = func()

        table = Table(title=title)
        table.add_column("Name", style="cyan")
        table.add_column("Details", style="yellow")

        for item in results[:50]:
            name = item.get("name", "N/A")
            details = item.get("operatingsystem", item.get("displayname", item.get("description", "N/A")))
            table.add_row(name, str(details))

        console.print(table)

    if not any([args.import_data, args.analyze, args.query, args.generate_report]):
        # Generate custom Cypher queries
        queries = analyzer.generate_cypher_queries()
        console.print(Panel("[bold]Available Operations[/bold]\n\n"
                           "--import-data <zip>  Import BloodHound data\n"
                           "--analyze            Run full analysis\n"
                           "--query <type>       Run specific query\n"
                           "--generate-report    Generate report\n",
                           title="BloodHound Analyzer"))


if __name__ == "__main__":
    main()
