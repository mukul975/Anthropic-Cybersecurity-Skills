#!/usr/bin/env python3
"""Agent for auditing HashiCorp Boundary zero trust access configuration."""

import subprocess
import json
import argparse
import sys
from datetime import datetime, timezone


def run_boundary_cmd(args_list, addr, token):
    """Execute a boundary CLI command and return parsed JSON."""
    env_vars = {"BOUNDARY_ADDR": addr, "BOUNDARY_TOKEN": token}
    cmd = ["boundary"] + args_list + ["-format=json"]
    result = subprocess.run(cmd, capture_output=True, text=True, env={**dict(__import__('os').environ), **env_vars}, timeout=30)
    if result.returncode != 0:
        print(f"  [-] Error: {result.stderr.strip()[:200]}")
        return {}
    return json.loads(result.stdout) if result.stdout else {}


def list_scopes(addr, token):
    """List organization and project scopes."""
    data = run_boundary_cmd(["scopes", "list", "-scope-id=global"], addr, token)
    scopes = data.get("items", [])
    print(f"[*] Scopes: {len(scopes)}")
    for s in scopes:
        print(f"  {s.get('id')}: {s.get('name', 'unnamed')} (type={s.get('type')})")
    return scopes


def list_targets(addr, token, scope_id):
    """List targets (resources users can connect to) in a scope."""
    data = run_boundary_cmd(["targets", "list", f"-scope-id={scope_id}"], addr, token)
    targets = data.get("items", [])
    findings = []
    print(f"\n[*] Targets in scope {scope_id}: {len(targets)}")
    for t in targets:
        session_max = t.get("session_max_seconds", 0)
        conn_limit = t.get("session_connection_limit", -1)
        print(f"  {t.get('name')}: type={t.get('type')}, "
              f"max_sec={session_max}, conn_limit={conn_limit}")
        if conn_limit == -1:
            findings.append({"target": t.get("name"), "issue": "Unlimited connections",
                             "severity": "MEDIUM"})
        if session_max == 0 or session_max > 28800:
            findings.append({"target": t.get("name"),
                             "issue": f"Long session timeout ({session_max}s)", "severity": "HIGH"})
    return targets, findings


def list_host_catalogs(addr, token, scope_id):
    """List host catalogs (static or dynamic)."""
    data = run_boundary_cmd(["host-catalogs", "list", f"-scope-id={scope_id}"], addr, token)
    catalogs = data.get("items", [])
    print(f"\n[*] Host Catalogs in scope {scope_id}: {len(catalogs)}")
    for c in catalogs:
        print(f"  {c.get('id')}: {c.get('name', 'unnamed')} (type={c.get('type')})")
    return catalogs


def list_credential_stores(addr, token, scope_id):
    """List credential stores (Vault integration check)."""
    data = run_boundary_cmd(["credential-stores", "list", f"-scope-id={scope_id}"], addr, token)
    stores = data.get("items", [])
    print(f"\n[*] Credential Stores in scope {scope_id}: {len(stores)}")
    vault_stores = [s for s in stores if s.get("type") == "vault"]
    static_stores = [s for s in stores if s.get("type") == "static"]
    print(f"  Vault-backed: {len(vault_stores)}, Static: {len(static_stores)}")
    findings = []
    if static_stores:
        for s in static_stores:
            findings.append({"store": s.get("name"), "type": "static",
                             "issue": "Static credentials (not Vault-brokered)", "severity": "MEDIUM"})
    return stores, findings


def list_sessions(addr, token, scope_id):
    """List active sessions for audit."""
    data = run_boundary_cmd(["sessions", "list", f"-scope-id={scope_id}"], addr, token)
    sessions = data.get("items", [])
    print(f"\n[*] Active Sessions in scope {scope_id}: {len(sessions)}")
    for s in sessions[:10]:
        print(f"  {s.get('id')[:12]}... user={s.get('user_id', 'N/A')} "
              f"target={s.get('target_id', 'N/A')} status={s.get('status')}")
    return sessions


def check_auth_methods(addr, token, scope_id="global"):
    """Audit configured authentication methods."""
    data = run_boundary_cmd(["auth-methods", "list", f"-scope-id={scope_id}"], addr, token)
    methods = data.get("items", [])
    findings = []
    print(f"\n[*] Auth Methods: {len(methods)}")
    for m in methods:
        mtype = m.get("type", "unknown")
        print(f"  {m.get('name', 'unnamed')}: type={mtype}")
        if mtype == "password":
            findings.append({"method": m.get("name"), "type": mtype,
                             "issue": "Password-only auth (use OIDC for zero trust)", "severity": "HIGH"})
    return methods, findings


def generate_report(target_findings, cred_findings, auth_findings, output_path):
    """Generate Boundary audit report."""
    all_findings = target_findings + cred_findings + auth_findings
    report = {
        "audit_date": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(all_findings),
        "target_findings": target_findings,
        "credential_findings": cred_findings,
        "auth_findings": auth_findings,
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] Report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="HashiCorp Boundary Zero Trust Audit Agent")
    parser.add_argument("action", choices=["scopes", "targets", "hosts", "creds",
                                           "sessions", "auth", "full-audit"])
    parser.add_argument("--addr", required=True, help="Boundary controller address")
    parser.add_argument("--token", required=True, help="Boundary auth token")
    parser.add_argument("--scope-id", default="global", help="Scope ID to audit")
    parser.add_argument("-o", "--output", default="boundary_audit.json")
    args = parser.parse_args()

    if args.action == "scopes":
        list_scopes(args.addr, args.token)
    elif args.action == "targets":
        list_targets(args.addr, args.token, args.scope_id)
    elif args.action == "hosts":
        list_host_catalogs(args.addr, args.token, args.scope_id)
    elif args.action == "creds":
        list_credential_stores(args.addr, args.token, args.scope_id)
    elif args.action == "sessions":
        list_sessions(args.addr, args.token, args.scope_id)
    elif args.action == "auth":
        check_auth_methods(args.addr, args.token)
    elif args.action == "full-audit":
        scopes = list_scopes(args.addr, args.token)
        all_tf, all_cf, all_af = [], [], []
        _, af = check_auth_methods(args.addr, args.token)
        all_af.extend(af)
        for s in scopes:
            sid = s.get("id")
            _, tf = list_targets(args.addr, args.token, sid)
            all_tf.extend(tf)
            _, cf = list_credential_stores(args.addr, args.token, sid)
            all_cf.extend(cf)
            list_sessions(args.addr, args.token, sid)
        generate_report(all_tf, all_cf, all_af, args.output)


if __name__ == "__main__":
    main()
