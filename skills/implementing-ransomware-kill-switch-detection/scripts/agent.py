#!/usr/bin/env python3
"""Ransomware kill switch detection and mutex vaccination agent.

Detects ransomware kill switch mechanisms (mutexes, domains, registry keys)
and can proactively deploy mutex vaccinations to prevent known ransomware
families from executing. Monitors for kill switch domain DNS queries.
"""

import json
import logging
import platform
import socket
import subprocess
import sys
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("killswitch_agent")

KNOWN_KILL_SWITCH_MUTEXES = {
    "Global\\MsWinZonesCacheCounterMutexA": {
        "family": "WannaCry",
        "type": "instance_guard",
        "notes": "Prevents multiple WannaCry instances from running",
    },
    "Global\\kasKDJSAFJauisiudUASIIQWUA82": {
        "family": "Conti",
        "type": "instance_guard",
        "notes": "Conti ransomware single-instance mutex",
    },
    "Global\\YOURPRODUCT_MUTEX": {
        "family": "Ryuk variant",
        "type": "instance_guard",
        "notes": "Ryuk variant instance check",
    },
    "Global\\JhbGjhBsSQjz": {
        "family": "Maze",
        "type": "instance_guard",
        "notes": "Maze ransomware single-instance mutex",
    },
    "Global\\{A7FE5338-4DDE-8CDE-9F54-FE88C3B8B532}": {
        "family": "LockBit",
        "type": "instance_guard",
        "notes": "LockBit variant mutex (GUID-based)",
    },
    "Global\\MsWinZonesCacheCounterMutexA0": {
        "family": "WannaCry variant",
        "type": "instance_guard",
        "notes": "WannaCry variant with appended zero",
    },
    "Global\\55a42b46-43dc-4e6c-abef-2529ddd744c7": {
        "family": "BlackCat/ALPHV",
        "type": "instance_guard",
        "notes": "ALPHV ransomware instance mutex",
    },
    "Global\\sdjfhksjdhfsd": {
        "family": "Generic ransomware",
        "type": "instance_guard",
        "notes": "Common in several ransomware builders",
    },
}

KNOWN_KILL_SWITCH_DOMAINS = {
    "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com": {
        "family": "WannaCry v1",
        "type": "domain_kill_switch",
        "notes": "Primary WannaCry kill switch domain registered by MalwareTech",
    },
    "fferfsodp9ifjaposdfjhgosurijfaewrwergwea.com": {
        "family": "WannaCry v1 (alternate)",
        "type": "domain_kill_switch",
        "notes": "Secondary WannaCry kill switch domain",
    },
    "ayloginilider.com": {
        "family": "Emotet (ransomware loader)",
        "type": "c2_sinkhole",
        "notes": "Emotet C2 domain sinkholed by law enforcement",
    },
}

KNOWN_KILL_SWITCH_REGISTRY = {
    "HKLM\\SOFTWARE\\WannaDecrypt0r": {
        "family": "WannaCry",
        "type": "registry_marker",
        "key": "HKLM\\SOFTWARE\\WannaDecrypt0r",
    },
}


def check_mutex_exists_windows(mutex_name):
    """Check if a named mutex exists on Windows using PowerShell."""
    ps_script = (
        f'try {{ $m = [System.Threading.Mutex]::OpenExisting("{mutex_name}"); '
        f'"EXISTS" }} catch {{ "NOT_FOUND" }}'
    )
    try:
        result = subprocess.run(
            ["powershell", "-Command", ps_script],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip() == "EXISTS"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def create_mutex_windows(mutex_name):
    """Create a named mutex on Windows for vaccination."""
    ps_script = (
        f'$created = $false; '
        f'$m = New-Object System.Threading.Mutex($true, "{mutex_name}", [ref]$created); '
        f'if ($created) {{ "CREATED" }} else {{ "ALREADY_EXISTS" }}; '
        f'Start-Sleep -Seconds 2'
    )
    try:
        result = subprocess.run(
            ["powershell", "-Command", ps_script],
            capture_output=True, text=True, timeout=15,
        )
        output = result.stdout.strip()
        return output == "CREATED" or output == "ALREADY_EXISTS", output
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, str(e)


def check_kill_switch_domain(domain):
    """Check if a kill switch domain resolves (indicating it is active)."""
    try:
        ip = socket.gethostbyname(domain)
        return {
            "domain": domain,
            "resolves": True,
            "ip": ip,
            "kill_switch_active": True,
            "notes": "Domain resolves - kill switch is ACTIVE (ransomware should abort)",
        }
    except socket.gaierror:
        return {
            "domain": domain,
            "resolves": False,
            "ip": None,
            "kill_switch_active": False,
            "notes": "Domain does NOT resolve - kill switch INACTIVE (ransomware would proceed)",
        }


def scan_all_kill_switches():
    """Scan for all known kill switch mechanisms."""
    report = {
        "scan_time": datetime.now().isoformat(),
        "hostname": platform.node(),
        "platform": platform.system(),
        "mutex_checks": [],
        "domain_checks": [],
        "registry_checks": [],
        "summary": {"total_checked": 0, "active_vaccinations": 0, "active_domains": 0},
    }

    # Check mutexes (Windows only)
    if platform.system() == "Windows":
        logger.info("Checking %d known ransomware mutexes...", len(KNOWN_KILL_SWITCH_MUTEXES))
        for mutex_name, info in KNOWN_KILL_SWITCH_MUTEXES.items():
            exists = check_mutex_exists_windows(mutex_name)
            check = {
                "mutex": mutex_name,
                "family": info["family"],
                "exists": exists,
                "vaccinated": exists is True,
            }
            report["mutex_checks"].append(check)
            report["summary"]["total_checked"] += 1
            if exists:
                report["summary"]["active_vaccinations"] += 1
                logger.warning("Mutex EXISTS: %s (%s)", mutex_name, info["family"])
    else:
        logger.info("Mutex checking is Windows-only. Skipping on %s.", platform.system())

    # Check kill switch domains
    logger.info("Checking %d known kill switch domains...", len(KNOWN_KILL_SWITCH_DOMAINS))
    for domain, info in KNOWN_KILL_SWITCH_DOMAINS.items():
        result = check_kill_switch_domain(domain)
        result["family"] = info["family"]
        report["domain_checks"].append(result)
        report["summary"]["total_checked"] += 1
        if result["resolves"]:
            report["summary"]["active_domains"] += 1

    return report


def vaccinate_endpoint(mutex_list=None):
    """Deploy mutex vaccinations to prevent ransomware execution."""
    if platform.system() != "Windows":
        return {"error": "Mutex vaccination is only supported on Windows"}

    if mutex_list is None:
        mutex_list = list(KNOWN_KILL_SWITCH_MUTEXES.keys())

    results = {"vaccinated": [], "failed": [], "already_exists": []}

    for mutex_name in mutex_list:
        info = KNOWN_KILL_SWITCH_MUTEXES.get(mutex_name, {"family": "Custom"})
        success, status = create_mutex_windows(mutex_name)

        record = {"mutex": mutex_name, "family": info.get("family", "Custom"), "status": status}

        if status == "CREATED":
            results["vaccinated"].append(record)
            logger.info("Vaccinated: %s (%s)", mutex_name, info.get("family"))
        elif status == "ALREADY_EXISTS":
            results["already_exists"].append(record)
            logger.info("Already vaccinated: %s", mutex_name)
        else:
            results["failed"].append(record)
            logger.error("Failed to vaccinate: %s - %s", mutex_name, status)

    results["summary"] = {
        "total_attempted": len(mutex_list),
        "newly_vaccinated": len(results["vaccinated"]),
        "already_vaccinated": len(results["already_exists"]),
        "failed": len(results["failed"]),
    }
    return results


def generate_vaccination_script():
    """Generate a PowerShell script for persistent mutex vaccination."""
    lines = [
        "# Ransomware Mutex Vaccination Script",
        "# Deploy via Group Policy Startup Script or Scheduled Task",
        f"# Generated: {datetime.now().isoformat()}",
        "# This script creates named mutexes that prevent known ransomware from executing",
        "",
        "$mutexHandles = @()",
        "",
    ]

    for mutex_name, info in KNOWN_KILL_SWITCH_MUTEXES.items():
        lines.append(f"# {info['family']} - {info['notes']}")
        lines.append('$created = $false')
        lines.append(f'$m = New-Object System.Threading.Mutex($true, "{mutex_name}", [ref]$created)')
        lines.append(f'if ($created) {{ Write-Host "Vaccinated: {mutex_name}" }}')
        lines.append('$mutexHandles += $m')
        lines.append("")

    lines.append("# Keep script running to maintain mutex handles")
    lines.append("Write-Host 'Mutex vaccination active. Press Ctrl+C to stop.'")
    lines.append("while ($true) { Start-Sleep -Seconds 60 }")

    return "\n".join(lines)


if __name__ == "__main__":
    print("=" * 60)
    print("Ransomware Kill Switch Detection & Vaccination Agent")
    print("Mutex vaccination, domain monitoring, kill switch analysis")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python agent.py scan                Scan for all known kill switches")
        print("  python agent.py vaccinate           Deploy mutex vaccinations")
        print("  python agent.py domains             Check kill switch domain status")
        print("  python agent.py generate-script     Generate PowerShell vaccination script")
        print("  python agent.py list                List all known kill switches")
        sys.exit(0)

    command = sys.argv[1]

    if command == "scan":
        report = scan_all_kill_switches()
        print("\n--- Kill Switch Scan Results ---")
        print(f"  Total checked: {report['summary']['total_checked']}")
        print(f"  Active mutex vaccinations: {report['summary']['active_vaccinations']}")
        print(f"  Active kill switch domains: {report['summary']['active_domains']}")
        for mc in report["mutex_checks"]:
            status = "VACCINATED" if mc["vaccinated"] else "not vaccinated"
            print(f"  [{status:15s}] {mc['family']:20s} {mc['mutex']}")
        for dc in report["domain_checks"]:
            status = "ACTIVE" if dc["resolves"] else "INACTIVE"
            print(f"  [{status:15s}] {dc['family']:20s} {dc['domain']}")
        print(f"\n{json.dumps(report, indent=2, default=str)}")

    elif command == "vaccinate":
        print("\n[*] Deploying mutex vaccinations...")
        results = vaccinate_endpoint()
        print("\n--- Vaccination Results ---")
        print(f"  Newly vaccinated: {results['summary']['newly_vaccinated']}")
        print(f"  Already vaccinated: {results['summary']['already_vaccinated']}")
        print(f"  Failed: {results['summary']['failed']}")

    elif command == "domains":
        print("\n--- Kill Switch Domain Status ---")
        for domain, info in KNOWN_KILL_SWITCH_DOMAINS.items():
            result = check_kill_switch_domain(domain)
            status = "ACTIVE (resolves)" if result["resolves"] else "INACTIVE (no DNS)"
            print(f"  [{status}] {info['family']}: {domain}")
            if result["resolves"]:
                print(f"    Resolves to: {result['ip']}")

    elif command == "generate-script":
        script = generate_vaccination_script()
        output_file = "mutex_vaccination.ps1"
        with open(output_file, "w") as f:
            f.write(script)
        print(f"\n[+] Vaccination script saved to: {output_file}")
        print("[+] Deploy via GPO startup script or scheduled task")
        print(f"\n{script[:500]}...")

    elif command == "list":
        print("\n--- Known Ransomware Kill Switches ---")
        print(f"\nMutexes ({len(KNOWN_KILL_SWITCH_MUTEXES)}):")
        for name, info in KNOWN_KILL_SWITCH_MUTEXES.items():
            print(f"  {info['family']:20s} {name}")
        print(f"\nDomains ({len(KNOWN_KILL_SWITCH_DOMAINS)}):")
        for domain, info in KNOWN_KILL_SWITCH_DOMAINS.items():
            print(f"  {info['family']:20s} {domain}")

    else:
        print(f"[!] Unknown command: {command}")
