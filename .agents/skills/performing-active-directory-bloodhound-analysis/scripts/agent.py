#!/usr/bin/env python3
"""BloodHound Attack Path Analysis Agent - Queries Neo4j for AD attack paths to Domain Admin."""

import json
import logging
import argparse
from datetime import datetime

from neo4j import GraphDatabase

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def connect_neo4j(uri, username, password):
    """Connect to Neo4j database containing BloodHound data."""
    driver = GraphDatabase.driver(uri, auth=(username, password))
    driver.verify_connectivity()
    logger.info("Connected to Neo4j at %s", uri)
    return driver


def find_domain_admins(driver):
    """Find all members of the Domain Admins group."""
    query = (
        "MATCH (u:User)-[:MemberOf*1..]->(g:Group) "
        "WHERE g.name STARTS WITH 'DOMAIN ADMINS' "
        "RETURN u.name AS user, u.enabled AS enabled, u.lastlogon AS lastlogon"
    )
    with driver.session() as session:
        results = [dict(record) for record in session.run(query)]
    logger.info("Found %d Domain Admin members", len(results))
    return results


def find_shortest_paths_to_da(driver, start_user=None):
    """Find shortest attack paths from owned users to Domain Admin."""
    if start_user:
        query = (
            "MATCH p=shortestPath((u:User {name: $user})-[*1..]->(g:Group)) "
            "WHERE g.name STARTS WITH 'DOMAIN ADMINS' "
            "RETURN p, length(p) AS hops"
        )
        params = {"user": start_user}
    else:
        query = (
            "MATCH p=shortestPath((u:User {owned: true})-[*1..]->(g:Group)) "
            "WHERE g.name STARTS WITH 'DOMAIN ADMINS' "
            "RETURN u.name AS start, length(p) AS hops "
            "ORDER BY hops ASC LIMIT 20"
        )
        params = {}
    with driver.session() as session:
        results = [dict(record) for record in session.run(query, params)]
    logger.info("Found %d attack paths to DA", len(results))
    return results


def find_kerberoastable_users(driver):
    """Find users with SPNs set (Kerberoastable) that have paths to high-value targets."""
    query = (
        "MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true "
        "RETURN u.name AS user, u.serviceprincipalnames AS spns, "
        "u.admincount AS admincount, u.pwdlastset AS pwdlastset"
    )
    with driver.session() as session:
        results = [dict(record) for record in session.run(query)]
    logger.info("Found %d Kerberoastable users", len(results))
    return results


def find_asrep_roastable(driver):
    """Find users with Kerberos pre-auth disabled (AS-REP Roastable)."""
    query = (
        "MATCH (u:User) WHERE u.dontreqpreauth = true AND u.enabled = true "
        "RETURN u.name AS user, u.enabled AS enabled"
    )
    with driver.session() as session:
        results = [dict(record) for record in session.run(query)]
    logger.info("Found %d AS-REP Roastable users", len(results))
    return results


def find_unconstrained_delegation(driver):
    """Find computers with unconstrained delegation enabled."""
    query = (
        "MATCH (c:Computer) WHERE c.unconstraineddelegation = true "
        "RETURN c.name AS computer, c.operatingsystem AS os, c.enabled AS enabled"
    )
    with driver.session() as session:
        results = [dict(record) for record in session.run(query)]
    logger.info("Found %d unconstrained delegation computers", len(results))
    return results


def find_local_admin_paths(driver, target_computer):
    """Find users with local admin rights on a target computer."""
    query = (
        "MATCH p=(u:User)-[:AdminTo|MemberOf*1..]->(c:Computer {name: $computer}) "
        "RETURN u.name AS user, length(p) AS hops "
        "ORDER BY hops ASC LIMIT 50"
    )
    with driver.session() as session:
        results = [dict(record) for record in session.run(query, {"computer": target_computer})]
    logger.info("Found %d users with admin access to %s", len(results), target_computer)
    return results


def find_gpo_attack_paths(driver):
    """Find GPO-based attack paths that could lead to privilege escalation."""
    query = (
        "MATCH (g:GPO)-[:GpLink]->(ou:OU)-[:Contains*1..]->(c:Computer) "
        "MATCH (u:User)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl]->(g) "
        "WHERE u.enabled = true "
        "RETURN u.name AS user, g.name AS gpo, c.name AS affected_computer "
        "LIMIT 50"
    )
    with driver.session() as session:
        results = [dict(record) for record in session.run(query)]
    logger.info("Found %d GPO attack paths", len(results))
    return results


def assess_ad_risk(da_members, paths, kerberoastable, asrep, unconstrained, gpo_paths):
    """Calculate overall AD security risk score."""
    score = 0
    if len(paths) > 0:
        score += 30
    if len(kerberoastable) > 5:
        score += 20
    if len(asrep) > 0:
        score += 15
    if len(unconstrained) > 1:
        score += 15
    if len(gpo_paths) > 0:
        score += 20
    risk = "Critical" if score >= 60 else "High" if score >= 40 else "Medium" if score >= 20 else "Low"
    return {"score": score, "risk_level": risk}


def generate_report(da_members, paths, kerberoastable, asrep, unconstrained, gpo_paths, risk):
    """Generate BloodHound analysis report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "domain_admins": da_members,
        "attack_paths_to_da": paths[:20],
        "kerberoastable_users": kerberoastable,
        "asrep_roastable": asrep,
        "unconstrained_delegation": unconstrained,
        "gpo_attack_paths": gpo_paths[:20],
        "risk_assessment": risk,
    }
    print(f"BLOODHOUND REPORT: Risk={risk['risk_level']} Score={risk['score']}")
    return report


def main():
    parser = argparse.ArgumentParser(description="BloodHound Attack Path Analysis Agent")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687")
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument("--neo4j-password", required=True)
    parser.add_argument("--start-user", help="Specific user to find paths from")
    parser.add_argument("--output", default="bloodhound_report.json")
    args = parser.parse_args()

    driver = connect_neo4j(args.neo4j_uri, args.neo4j_user, args.neo4j_password)
    da_members = find_domain_admins(driver)
    paths = find_shortest_paths_to_da(driver, args.start_user)
    kerberoastable = find_kerberoastable_users(driver)
    asrep = find_asrep_roastable(driver)
    unconstrained = find_unconstrained_delegation(driver)
    gpo_paths = find_gpo_attack_paths(driver)
    risk = assess_ad_risk(da_members, paths, kerberoastable, asrep, unconstrained, gpo_paths)

    report = generate_report(da_members, paths, kerberoastable, asrep, unconstrained, gpo_paths, risk)
    driver.close()
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
