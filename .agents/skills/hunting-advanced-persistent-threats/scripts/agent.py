#!/usr/bin/env python3
"""APT threat hunting agent using MITRE ATT&CK, attackcti, and osquery."""

import json
import sys
import argparse
from datetime import datetime, timedelta

try:
    from attackcti import attack_client
except ImportError:
    print("Install attackcti: pip install attackcti")
    sys.exit(1)


def get_apt_group_ttps(group_name):
    """Retrieve TTPs for a specific APT group from MITRE ATT&CK."""
    client = attack_client()
    groups = client.get_groups()
    target = None
    for g in groups:
        aliases = [a.lower() for a in g.get("aliases", [])]
        if group_name.lower() in g["name"].lower() or group_name.lower() in aliases:
            target = g
            break
    if not target:
        print(f"[!] Group '{group_name}' not found in ATT&CK")
        return None
    techniques = client.get_techniques_used_by_group(target)
    return {"group": target["name"], "id": target["external_references"][0]["external_id"],
            "techniques": [{"id": t["external_references"][0]["external_id"],
                            "name": t["name"],
                            "tactic": [p["phase_name"] for p in t.get("kill_chain_phases", [])]}
                           for t in techniques]}


def generate_osquery_hunts(techniques):
    """Generate osquery hunt queries for detected ATT&CK techniques."""
    query_map = {
        "T1059": ("Process execution (Command and Scripting)",
                  "SELECT pid, name, cmdline, path, parent FROM processes "
                  "WHERE name IN ('powershell.exe','cmd.exe','wscript.exe','cscript.exe','bash','python');"),
        "T1053": ("Scheduled Task/Job persistence",
                  "SELECT name, action, path, enabled, last_run_time FROM scheduled_tasks "
                  "WHERE enabled=1 AND action NOT LIKE '%System32%';"),
        "T1547": ("Boot/Logon autostart execution",
                  "SELECT name, path, source FROM autoexec;"),
        "T1071": ("Application layer protocol C2",
                  "SELECT pid, remote_address, remote_port, local_port FROM process_open_sockets "
                  "WHERE remote_port IN (443, 8443, 8080, 4443) AND family=2;"),
        "T1055": ("Process injection",
                  "SELECT pid, name, cmdline FROM processes WHERE on_disk=0;"),
        "T1003": ("OS credential dumping",
                  "SELECT pid, name, cmdline FROM processes "
                  "WHERE name IN ('mimikatz.exe','procdump.exe','ntdsutil.exe') "
                  "OR cmdline LIKE '%sekurlsa%' OR cmdline LIKE '%lsass%';"),
        "T1021": ("Remote services lateral movement",
                  "SELECT pid, name, cmdline FROM processes "
                  "WHERE name IN ('psexec.exe','wmic.exe','winrm.cmd') "
                  "OR cmdline LIKE '%invoke-command%';"),
        "T1027": ("Obfuscated files or information",
                  "SELECT pid, name, cmdline FROM processes "
                  "WHERE cmdline LIKE '%-enc%' OR cmdline LIKE '%-encodedcommand%';"),
        "T1566": ("Phishing initial access",
                  "SELECT path, filename, size FROM file "
                  "WHERE directory LIKE '%Downloads%' "
                  "AND (filename LIKE '%.iso' OR filename LIKE '%.img' OR filename LIKE '%.lnk');"),
        "T1218": ("Signed binary proxy execution",
                  "SELECT pid, name, cmdline, parent FROM processes "
                  "WHERE name IN ('mshta.exe','rundll32.exe','regsvr32.exe','certutil.exe');"),
    }
    hunts = []
    for tech in techniques:
        tech_id = tech["id"].split(".")[0]
        if tech_id in query_map:
            desc, query = query_map[tech_id]
            hunts.append({"technique": tech["id"], "name": tech["name"],
                          "description": desc, "osquery": query})
    return hunts


def generate_sigma_rule(technique_id, technique_name, tactic):
    """Generate a Sigma detection rule for a given technique."""
    return {
        "title": f"Detect {technique_name} ({technique_id})",
        "status": "experimental",
        "description": f"Detects potential {technique_name} activity mapped to {technique_id}",
        "references": [f"https://attack.mitre.org/techniques/{technique_id.replace('.','/')}/"],
        "tags": [f"attack.{t}" for t in tactic] + [f"attack.{technique_id.lower()}"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {"selection": {"technique_id": technique_id}, "condition": "selection"},
        "level": "medium",
    }


def build_hunt_report(group_name):
    """Build a complete threat hunt report for an APT group."""
    print(f"\n{'='*70}")
    print(f"  APT THREAT HUNT REPORT")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*70}\n")

    print(f"[*] Querying MITRE ATT&CK for group: {group_name}")
    group_data = get_apt_group_ttps(group_name)
    if not group_data:
        return

    print(f"[+] Found: {group_data['group']} ({group_data['id']})")
    print(f"[+] Techniques mapped: {len(group_data['techniques'])}\n")

    print(f"--- TECHNIQUE COVERAGE ---")
    tactic_counts = {}
    for t in group_data["techniques"]:
        print(f"  [{t['id']}] {t['name']} -> {', '.join(t['tactic'])}")
        for tac in t["tactic"]:
            tactic_counts[tac] = tactic_counts.get(tac, 0) + 1

    print(f"\n--- TACTIC DISTRIBUTION ---")
    for tac, count in sorted(tactic_counts.items(), key=lambda x: -x[1]):
        bar = "#" * count
        print(f"  {tac:<30} {bar} ({count})")

    print(f"\n--- OSQUERY HUNT QUERIES ---")
    hunts = generate_osquery_hunts(group_data["techniques"])
    if hunts:
        for h in hunts:
            print(f"\n  Technique: {h['technique']} - {h['description']}")
            print(f"  Query: {h['osquery']}")
    else:
        print("  No matching osquery hunts for this group's techniques.")

    print(f"\n--- SIGMA RULES ---")
    for t in group_data["techniques"][:5]:
        rule = generate_sigma_rule(t["id"], t["name"], t["tactic"])
        print(f"\n  Rule: {rule['title']}")
        print(f"  Tags: {', '.join(rule['tags'])}")
        print(f"  Level: {rule['level']}")

    print(f"\n--- HUNT RECOMMENDATIONS ---")
    print(f"  1. Execute osquery hunts across all endpoints via fleet manager")
    print(f"  2. Search SIEM for technique indicators over past 90 days")
    print(f"  3. Validate EDR telemetry covers all {len(group_data['techniques'])} techniques")
    print(f"  4. Cross-reference with network logs (Zeek/Suricata) for C2 patterns")
    print(f"  5. Document findings using Diamond Model analysis framework")
    print(f"\n{'='*70}\n")

    return group_data


def main():
    parser = argparse.ArgumentParser(description="APT Threat Hunting Agent")
    parser.add_argument("--group", default="APT29", help="APT group name (e.g., APT29, APT28, Lazarus)")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = build_hunt_report(args.group)
    if report and args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] JSON report saved to {args.output}")


if __name__ == "__main__":
    main()
