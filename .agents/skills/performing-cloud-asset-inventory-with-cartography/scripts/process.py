#!/usr/bin/env python3
"""
Cartography Cloud Asset Inventory Security Analysis Script

Connects to Neo4j after Cartography sync and runs security-focused
queries to identify misconfigurations, attack paths, and overprivileged access.
"""

import json
import sys
from datetime import datetime

try:
    from neo4j import GraphDatabase
except ImportError:
    print("Install neo4j driver: pip install neo4j")
    sys.exit(1)


SECURITY_QUERIES = {
    "public_s3_buckets": {
        "description": "S3 buckets with public access",
        "severity": "HIGH",
        "query": """
            MATCH (b:S3Bucket)
            WHERE b.anonymous_access = true
            RETURN b.name AS bucket, b.region AS region, b.arn AS arn
            ORDER BY b.name
        """
    },
    "admin_iam_users": {
        "description": "IAM users with administrator access",
        "severity": "HIGH",
        "query": """
            MATCH (user:AWSUser)-[:POLICY]->(policy:AWSPolicy)
            WHERE policy.name = 'AdministratorAccess'
            RETURN user.name AS username, user.arn AS arn, policy.name AS policy
        """
    },
    "public_ec2_ssh": {
        "description": "EC2 instances with SSH exposed to internet",
        "severity": "CRITICAL",
        "query": """
            MATCH (i:EC2Instance)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
                  -[:MEMBER_OF_EC2_SECURITY_GROUP_RULE]->(rule:IpRule)
            WHERE rule.fromport <= 22 AND rule.toport >= 22
              AND '0.0.0.0/0' IN rule.ipranges
            RETURN i.instanceid AS instance, i.publicipaddress AS public_ip,
                   sg.name AS security_group
        """
    },
    "cross_account_trusts": {
        "description": "Cross-account IAM trust relationships",
        "severity": "MEDIUM",
        "query": """
            MATCH (role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(p:AWSPrincipal)
            WHERE p.arn CONTAINS ':root'
              AND NOT p.arn CONTAINS role.accountid
            RETURN role.name AS role, role.arn AS role_arn,
                   p.arn AS trusted_principal
        """
    },
    "unencrypted_rds": {
        "description": "RDS instances without encryption",
        "severity": "HIGH",
        "query": """
            MATCH (rds:RDSInstance)
            WHERE rds.storage_encrypted = false
            RETURN rds.db_instance_identifier AS database,
                   rds.engine AS engine, rds.region AS region
        """
    },
    "unused_iam_roles": {
        "description": "IAM roles unused for 90+ days",
        "severity": "LOW",
        "query": """
            MATCH (role:AWSRole)
            WHERE role.last_used IS NULL
            RETURN role.name AS role, role.arn AS arn
            LIMIT 50
        """
    },
    "lambda_admin_roles": {
        "description": "Lambda functions with admin permissions",
        "severity": "HIGH",
        "query": """
            MATCH (f:AWSLambda)-[:STS_ASSUME_ROLE_ALLOWS]->(r:AWSRole)-[:POLICY]->(p:AWSPolicy)
            WHERE p.name = 'AdministratorAccess'
            RETURN f.name AS function_name, r.name AS role, p.name AS policy
        """
    }
}


def run_security_audit(uri, user, password):
    """Run all security queries against Neo4j."""
    driver = GraphDatabase.driver(uri, auth=(user, password))
    results = {}

    with driver.session() as session:
        for check_name, check_config in SECURITY_QUERIES.items():
            print(f"\n[*] Running: {check_config['description']} [{check_config['severity']}]")
            try:
                result = session.run(check_config["query"])
                records = [dict(record) for record in result]
                results[check_name] = {
                    "description": check_config["description"],
                    "severity": check_config["severity"],
                    "findings": records,
                    "count": len(records)
                }
                if records:
                    print(f"  [!] Found {len(records)} issues")
                    for r in records[:5]:
                        print(f"    - {json.dumps(r, default=str)}")
                    if len(records) > 5:
                        print(f"    ... and {len(records) - 5} more")
                else:
                    print(f"  [OK] No issues found")
            except Exception as e:
                print(f"  [ERROR] {e}")
                results[check_name] = {"error": str(e)}

    driver.close()
    return results


def generate_report(results, output_file=None):
    """Generate security audit report from query results."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 60,
        "Cartography Cloud Asset Security Audit",
        f"Generated: {timestamp}",
        "=" * 60
    ]

    total_findings = sum(r.get("count", 0) for r in results.values() if "error" not in r)
    critical = sum(r.get("count", 0) for r in results.values() if r.get("severity") == "CRITICAL")
    high = sum(r.get("count", 0) for r in results.values() if r.get("severity") == "HIGH")

    lines.append(f"\nTotal Findings: {total_findings}")
    lines.append(f"Critical: {critical} | High: {high}")

    for name, data in results.items():
        if "error" in data:
            continue
        lines.append(f"\n## {data['description']} [{data['severity']}]")
        lines.append(f"Findings: {data['count']}")
        for f in data.get("findings", [])[:10]:
            lines.append(f"  - {json.dumps(f, default=str)}")

    report = "\n".join(lines)
    if output_file:
        with open(output_file, "w") as f:
            f.write(report)
        print(f"\n[+] Report saved to {output_file}")
    else:
        print(report)
    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Cartography Security Audit")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687")
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument("--neo4j-password", required=True)
    parser.add_argument("--output", type=str, help="Output report file")
    args = parser.parse_args()

    results = run_security_audit(args.neo4j_uri, args.neo4j_user, args.neo4j_password)
    generate_report(results, args.output)
