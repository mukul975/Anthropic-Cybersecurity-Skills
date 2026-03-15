#!/usr/bin/env python3
"""BloodHound CE reconnaissance agent using bloodhound Python ingestor and Neo4j."""

import json
import sys
import argparse
import subprocess
from datetime import datetime

try:
    from neo4j import GraphDatabase
except ImportError:
    print("Install: pip install neo4j")
    sys.exit(1)


def collect_bloodhound_data(domain, username, password, dc_ip, method="all"):
    """Run BloodHound Python ingestor to collect AD data."""
    cmd = [
        "bloodhound-python", "-d", domain, "-u", username, "-p", password,
        "-ns", dc_ip, "-c", method, "--zip",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {"status": "completed", "output": result.stdout[:1000]}
    except FileNotFoundError:
        return {"status": "error", "message": "Install: pip install bloodhound"}
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}


def query_shortest_path_to_da(driver):
    """Find shortest path to Domain Admins."""
    with driver.session() as session:
        result = session.run(
            "MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name: $group})) "
            "WHERE u.enabled = true RETURN u.name AS user, length(p) AS hops "
            "ORDER BY hops LIMIT 10",
            group="DOMAIN ADMINS@DOMAIN.LOCAL",
        )
        return [{"user": r["user"], "hops": r["hops"]} for r in result]


def query_kerberoastable_users(driver):
    """Find kerberoastable user accounts."""
    with driver.session() as session:
        result = session.run(
            "MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true "
            "RETURN u.name AS user, u.serviceprincipalnames AS spns, "
            "u.admincount AS admin_count ORDER BY u.admincount DESC"
        )
        return [{"user": r["user"], "spns": r["spns"],
                 "admin": r["admin_count"]} for r in result]


def query_unconstrained_delegation(driver):
    """Find computers with unconstrained delegation."""
    with driver.session() as session:
        result = session.run(
            "MATCH (c:Computer) WHERE c.unconstraineddelegation = true "
            "RETURN c.name AS computer, c.operatingsystem AS os"
        )
        return [{"computer": r["computer"], "os": r["os"]} for r in result]


def query_as_rep_roastable(driver):
    """Find AS-REP roastable accounts (no pre-auth required)."""
    with driver.session() as session:
        result = session.run(
            "MATCH (u:User) WHERE u.dontreqpreauth = true AND u.enabled = true "
            "RETURN u.name AS user, u.admincount AS admin_count"
        )
        return [{"user": r["user"], "admin": r["admin_count"]} for r in result]


def run_recon(neo4j_uri, neo4j_user, neo4j_password):
    """Run BloodHound reconnaissance queries."""
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    print(f"\n{'='*60}")
    print(f"  BLOODHOUND CE RECONNAISSANCE")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    paths = query_shortest_path_to_da(driver)
    print(f"--- SHORTEST PATHS TO DOMAIN ADMIN ({len(paths)}) ---")
    for p in paths:
        print(f"  {p['user']}: {p['hops']} hops")

    kerb = query_kerberoastable_users(driver)
    print(f"\n--- KERBEROASTABLE USERS ({len(kerb)}) ---")
    for k in kerb[:10]:
        print(f"  {k['user']} (admin={k['admin']})")

    deleg = query_unconstrained_delegation(driver)
    print(f"\n--- UNCONSTRAINED DELEGATION ({len(deleg)}) ---")
    for d in deleg:
        print(f"  {d['computer']}: {d['os']}")

    asrep = query_as_rep_roastable(driver)
    print(f"\n--- AS-REP ROASTABLE ({len(asrep)}) ---")
    for a in asrep:
        print(f"  {a['user']} (admin={a['admin']})")

    driver.close()
    return {"paths_to_da": paths, "kerberoastable": kerb,
            "unconstrained_delegation": deleg, "asrep_roastable": asrep}


def main():
    parser = argparse.ArgumentParser(description="BloodHound CE Recon Agent")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    parser.add_argument("--neo4j-password", required=True, help="Neo4j password")
    parser.add_argument("--collect", action="store_true", help="Run data collection first")
    parser.add_argument("--domain", help="AD domain for collection")
    parser.add_argument("--ad-user", help="AD username for collection")
    parser.add_argument("--ad-pass", help="AD password for collection")
    parser.add_argument("--dc-ip", help="Domain controller IP")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    if args.collect and args.domain:
        result = collect_bloodhound_data(args.domain, args.ad_user, args.ad_pass, args.dc_ip)
        print(json.dumps(result, indent=2))

    report = run_recon(args.neo4j_uri, args.neo4j_user, args.neo4j_password)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
