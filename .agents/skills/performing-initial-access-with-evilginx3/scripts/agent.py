#!/usr/bin/env python3
"""Agent for performing initial access simulation with Evilginx3 phishlet analysis — educational/authorized pentest use."""

import json
import argparse
import subprocess
import re
from pathlib import Path
from datetime import datetime


def parse_phishlet(phishlet_path):
    """Parse an Evilginx3 YAML phishlet file and extract configuration."""
    try:
        import yaml
    except ImportError:
        return {"error": "pyyaml not installed — pip install pyyaml"}
    content = Path(phishlet_path).read_text(encoding="utf-8")
    config = yaml.safe_load(content)
    proxy_hosts = config.get("proxy_hosts", [])
    sub_filters = config.get("sub_filters", [])
    auth_tokens = config.get("auth_tokens", [])
    cred_fields = config.get("credentials", {})
    return {
        "phishlet": phishlet_path,
        "name": config.get("name", ""),
        "author": config.get("author", ""),
        "target_domain": proxy_hosts[0].get("domain", "") if proxy_hosts else "",
        "proxy_hosts": [{"phish_sub": h.get("phish_sub"), "orig_sub": h.get("orig_sub"), "domain": h.get("domain")} for h in proxy_hosts],
        "auth_tokens": [{"domain": t.get("domain"), "keys": t.get("keys", [])} for t in auth_tokens],
        "credential_fields": cred_fields,
        "sub_filters_count": len(sub_filters),
        "analysis": {
            "captures_session_tokens": len(auth_tokens) > 0,
            "captures_credentials": bool(cred_fields),
            "mfa_bypass_capable": len(auth_tokens) > 0,
        },
    }


def analyze_session_log(log_file):
    """Analyze Evilginx session capture logs."""
    content = Path(log_file).read_text(encoding="utf-8", errors="replace")
    sessions = []
    current = {}
    for line in content.splitlines():
        if "new session" in line.lower() or "session started" in line.lower():
            if current:
                sessions.append(current)
            current = {"start": line.strip(), "tokens": [], "credentials": []}
        elif "token" in line.lower() or "cookie" in line.lower():
            current.setdefault("tokens", []).append(line.strip()[:200])
        elif "username" in line.lower() or "password" in line.lower() or "credential" in line.lower():
            current.setdefault("credentials", []).append(line.strip()[:200])
        elif "landing_url" in line.lower() or "remote_addr" in line.lower():
            ip_match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
            if ip_match:
                current["source_ip"] = ip_match.group()
    if current:
        sessions.append(current)
    return {
        "log_file": log_file,
        "total_sessions": len(sessions),
        "sessions_with_tokens": sum(1 for s in sessions if s.get("tokens")),
        "sessions_with_creds": sum(1 for s in sessions if s.get("credentials")),
        "sessions": sessions[:20],
    }


def check_evilginx_installation():
    """Check if Evilginx3 is installed and get version."""
    try:
        result = subprocess.run(["evilginx", "--version"], capture_output=True, text=True, timeout=10)
        version = result.stdout.strip() or result.stderr.strip()
        return {"installed": True, "version": version}
    except FileNotFoundError:
        return {"installed": False, "error": "evilginx not found in PATH"}
    except Exception as e:
        return {"installed": False, "error": str(e)}


def list_phishlets(phishlet_dir):
    """List available phishlets in a directory."""
    p = Path(phishlet_dir)
    if not p.is_dir():
        return {"error": f"Directory not found: {phishlet_dir}"}
    phishlets = []
    for f in sorted(p.glob("*.yaml")) + sorted(p.glob("*.yml")):
        phishlets.append({"name": f.stem, "path": str(f), "size": f.stat().st_size})
    return {"directory": phishlet_dir, "count": len(phishlets), "phishlets": phishlets}


def generate_detection_rules(phishlet_path):
    """Generate detection signatures for a phishlet's attack patterns."""
    try:
        import yaml
    except ImportError:
        return {"error": "pyyaml not installed"}
    config = yaml.safe_load(Path(phishlet_path).read_text())
    proxy_hosts = config.get("proxy_hosts", [])
    rules = []
    for host in proxy_hosts:
        domain = host.get("domain", "")
        phish_sub = host.get("phish_sub", "")
        rules.append({
            "type": "dns_monitor",
            "description": f"Monitor for DNS queries to subdomains impersonating {domain}",
            "pattern": f"*.{domain}",
            "indicator": f"Phishing subdomain: {phish_sub}.{domain}",
        })
    auth_tokens = config.get("auth_tokens", [])
    for token in auth_tokens:
        for key in token.get("keys", []):
            rules.append({
                "type": "cookie_monitor",
                "description": f"Monitor for session token relay of {key}",
                "cookie_name": key,
                "domain": token.get("domain", ""),
            })
    rules.append({
        "type": "network_signature",
        "description": "Detect reverse proxy header anomalies",
        "indicators": ["X-Forwarded-For mismatch", "Origin header discrepancy", "TLS certificate mismatch"],
    })
    return {
        "phishlet": phishlet_path,
        "detection_rules": rules,
        "total_rules": len(rules),
        "recommendations": [
            "Enable FIDO2/WebAuthn MFA to prevent session token theft",
            "Monitor for certificate transparency log entries with suspicious subdomains",
            "Deploy conditional access policies requiring compliant devices",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="Evilginx3 Phishlet Analysis Agent (Authorized Testing Only)")
    sub = parser.add_subparsers(dest="command")
    p = sub.add_parser("parse", help="Parse phishlet YAML")
    p.add_argument("--phishlet", required=True)
    l = sub.add_parser("logs", help="Analyze session logs")
    l.add_argument("--file", required=True)
    sub.add_parser("check", help="Check Evilginx installation")
    ls = sub.add_parser("list", help="List available phishlets")
    ls.add_argument("--dir", required=True)
    d = sub.add_parser("detect", help="Generate detection rules")
    d.add_argument("--phishlet", required=True)
    args = parser.parse_args()
    if args.command == "parse":
        result = parse_phishlet(args.phishlet)
    elif args.command == "logs":
        result = analyze_session_log(args.file)
    elif args.command == "check":
        result = check_evilginx_installation()
    elif args.command == "list":
        result = list_phishlets(args.dir)
    elif args.command == "detect":
        result = generate_detection_rules(args.phishlet)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
