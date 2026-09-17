#!/usr/bin/env python3
"""Cartography cloud asset inventory agent.

Wraps the Cartography tool to enumerate and inventory cloud assets
across AWS accounts, then queries the resulting Neo4j graph database
to identify security-relevant relationships, exposed resources, and
misconfigured assets.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

try:
    from neo4j import GraphDatabase
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False


def run_cartography(profile=None, neo4j_uri="bolt://localhost:7687",
                    neo4j_user="neo4j", neo4j_password="neo4j"):
    """Execute Cartography to populate the Neo4j graph."""
    cmd = [sys.executable, "-m", "cartography",
           "--neo4j-uri", neo4j_uri,
           "--neo4j-user", neo4j_user,
           "--neo4j-password-env-var", "NEO4J_PASSWORD"]
    if profile:
        cmd.extend(["--aws-requested-syncs", "ec2,iam,s3,rds,lambda,ecs"])
    env = dict(os.environ)
    env["NEO4J_PASSWORD"] = neo4j_password
    print("[*] Running Cartography sync...")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=900, env=env)
    if result.returncode != 0:
        print(f"[!] Cartography error: {result.stderr[:300]}", file=sys.stderr)
    return result.returncode


def query_neo4j(driver, query, params=None):
    """Execute a Cypher query against the Neo4j graph."""
    with driver.session() as session:
        result = session.run(query, params or {})
        return [record.data() for record in result]


def inventory_ec2_instances(driver):
    """Query EC2 instances from the graph."""
    query = """
    MATCH (i:EC2Instance)
    OPTIONAL MATCH (i)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
    RETURN i.id AS instance_id, i.instancetype AS type,
           i.state AS state, i.publicipaddress AS public_ip,
           i.privateipaddress AS private_ip,
           i.launchtime AS launch_time,
           collect(DISTINCT sg.groupid) AS security_groups
    ORDER BY i.launchtime DESC
    """
    return query_neo4j(driver, query)


def inventory_s3_buckets(driver):
    """Query S3 buckets from the graph."""
    query = """
    MATCH (b:S3Bucket)
    OPTIONAL MATCH (b)-[:RESOURCE]->(acl:S3Acl)
    RETURN b.name AS bucket_name, b.region AS region,
           b.anonymous_access AS anonymous_access,
           b.default_encryption AS encryption,
           b.versioning_status AS versioning
    ORDER BY b.name
    """
    return query_neo4j(driver, query)


def find_public_resources(driver):
    """Find publicly accessible resources."""
    findings = []
    # Public EC2 instances
    query = """
    MATCH (i:EC2Instance)
    WHERE i.publicipaddress IS NOT NULL AND i.state = 'running'
    MATCH (i)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
           -[:MEMBER_OF_EC2_SECURITY_GROUP]->(rule:IpRule)
    WHERE rule.cidr_ip = '0.0.0.0/0'
    RETURN DISTINCT i.id AS resource_id, 'EC2Instance' AS type,
           i.publicipaddress AS public_ip, rule.fromport AS port
    """
    for r in query_neo4j(driver, query):
        findings.append({
            "type": "public_ec2",
            "resource": r["resource_id"],
            "severity": "HIGH",
            "detail": f"Public IP {r.get('public_ip', 'N/A')} open on port {r.get('port', 'all')}",
        })

    # Public S3 buckets
    query = """
    MATCH (b:S3Bucket) WHERE b.anonymous_access = true
    RETURN b.name AS bucket_name
    """
    for r in query_neo4j(driver, query):
        findings.append({
            "type": "public_s3",
            "resource": r["bucket_name"],
            "severity": "CRITICAL",
            "detail": "S3 bucket allows anonymous access",
        })

    # IAM users without MFA
    query = """
    MATCH (u:AWSUser) WHERE u.mfa_active = false AND u.password_enabled = true
    RETURN u.name AS username, u.arn AS arn
    """
    for r in query_neo4j(driver, query):
        findings.append({
            "type": "iam_no_mfa",
            "resource": r["username"],
            "severity": "HIGH",
            "detail": f"IAM user {r['username']} has console access without MFA",
        })

    return findings


def find_unencrypted_resources(driver):
    """Find unencrypted storage resources."""
    findings = []
    query = """
    MATCH (v:EBSVolume) WHERE v.encrypted = false
    RETURN v.id AS volume_id, v.size AS size_gb, v.state AS state
    """
    for r in query_neo4j(driver, query):
        findings.append({
            "type": "unencrypted_ebs",
            "resource": r["volume_id"],
            "severity": "HIGH",
            "detail": f"Unencrypted EBS volume ({r.get('size_gb', '?')} GB)",
        })

    query = """
    MATCH (b:S3Bucket)
    WHERE b.default_encryption IS NULL OR b.default_encryption = false
    RETURN b.name AS bucket_name
    """
    for r in query_neo4j(driver, query):
        findings.append({
            "type": "unencrypted_s3",
            "resource": r["bucket_name"],
            "severity": "MEDIUM",
            "detail": "S3 bucket without default encryption",
        })

    return findings


def format_summary(ec2_instances, s3_buckets, security_findings):
    """Print inventory summary."""
    print(f"\n{'='*60}")
    print("  Cartography Cloud Asset Inventory")
    print(f"{'='*60}")
    print(f"  EC2 Instances    : {len(ec2_instances)}")
    print(f"  S3 Buckets       : {len(s3_buckets)}")
    print(f"  Security Findings: {len(security_findings)}")

    running = sum(1 for i in ec2_instances if i.get("state") == "running")
    public = sum(1 for i in ec2_instances if i.get("public_ip"))
    print(f"\n  EC2: {running} running, {public} with public IP")

    if security_findings:
        severity_counts = {}
        for f in security_findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        print("\n  Security Findings:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
            count = severity_counts.get(sev, 0)
            if count:
                print(f"    {sev:10s}: {count}")
        for f in security_findings[:15]:
            print(f"    [{f['severity']:8s}] {f['type']:20s} | {f['resource']}: {f['detail'][:40]}")

    return {s: severity_counts.get(s, 0) for s in ["CRITICAL", "HIGH", "MEDIUM"]} if security_findings else {}


def main():
    parser = argparse.ArgumentParser(description="Cartography cloud asset inventory agent")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687")
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument("--neo4j-password", default=os.environ.get("NEO4J_PASSWORD", "neo4j"))
    parser.add_argument("--sync", action="store_true", help="Run Cartography sync before query")
    parser.add_argument("--profile", help="AWS CLI profile for sync")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if not HAS_NEO4J:
        print("[!] neo4j driver required: pip install neo4j", file=sys.stderr)
        sys.exit(1)

    if args.sync:
        run_cartography(args.profile, args.neo4j_uri, args.neo4j_user, args.neo4j_password)

    driver = GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_password))

    ec2_instances = inventory_ec2_instances(driver)
    s3_buckets = inventory_s3_buckets(driver)
    public_findings = find_public_resources(driver)
    encryption_findings = find_unencrypted_resources(driver)
    all_findings = public_findings + encryption_findings

    severity_counts = format_summary(ec2_instances, s3_buckets, all_findings)
    driver.close()

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "Cartography",
        "ec2_instances": ec2_instances,
        "s3_buckets": s3_buckets,
        "security_findings": all_findings,
        "severity_counts": severity_counts,
        "risk_level": (
            "CRITICAL" if severity_counts.get("CRITICAL", 0) > 0
            else "HIGH" if severity_counts.get("HIGH", 0) > 0
            else "MEDIUM" if all_findings else "LOW"
        ),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
