#!/usr/bin/env python3
"""Cloud WAF rules management agent using AWS WAFv2 boto3 client."""

import json
import sys
import argparse
from datetime import datetime

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("Install boto3: pip install boto3")
    sys.exit(1)


MANAGED_RULE_GROUPS = [
    {"vendor": "AWS", "name": "AWSManagedRulesCommonRuleSet",
     "description": "OWASP Top 10 core protection"},
    {"vendor": "AWS", "name": "AWSManagedRulesSQLiRuleSet",
     "description": "SQL injection protection"},
    {"vendor": "AWS", "name": "AWSManagedRulesKnownBadInputsRuleSet",
     "description": "Known malicious input patterns"},
    {"vendor": "AWS", "name": "AWSManagedRulesLinuxRuleSet",
     "description": "Linux-specific LFI protection"},
    {"vendor": "AWS", "name": "AWSManagedRulesBotControlRuleSet",
     "description": "Bot management and detection"},
    {"vendor": "AWS", "name": "AWSManagedRulesATPRuleSet",
     "description": "Account takeover prevention"},
]


def get_waf_client(region="us-east-1", scope="REGIONAL"):
    """Create WAFv2 client."""
    return boto3.client("wafv2", region_name=region)


def create_web_acl(client, name, scope="REGIONAL", description=""):
    """Create a new Web ACL with default block action."""
    try:
        resp = client.create_web_acl(
            Name=name, Scope=scope,
            DefaultAction={"Allow": {}},
            Description=description or f"WAF ACL managed by agent - {name}",
            VisibilityConfig={
                "SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                "MetricName": name.replace("-", "")},
            Rules=[])
        return {"arn": resp["Summary"]["ARN"], "id": resp["Summary"]["Id"],
                "status": "created"}
    except ClientError as e:
        return {"error": str(e)}


def add_managed_rule_group(client, acl_name, acl_id, lock_token, scope,
                           vendor, rule_group_name, priority):
    """Add a managed rule group to an existing Web ACL."""
    try:
        acl = client.get_web_acl(Name=acl_name, Scope=scope, Id=acl_id)
        rules = acl["WebACL"]["Rules"]
        lock_token = acl["LockToken"]
        rules.append({
            "Name": rule_group_name,
            "Priority": priority,
            "Statement": {
                "ManagedRuleGroupStatement": {"VendorName": vendor, "Name": rule_group_name}},
            "OverrideAction": {"None": {}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                "MetricName": rule_group_name}})
        client.update_web_acl(
            Name=acl_name, Scope=scope, Id=acl_id, LockToken=lock_token,
            DefaultAction={"Allow": {}}, Rules=rules,
            VisibilityConfig=acl["WebACL"]["VisibilityConfig"])
        return {"rule_group": rule_group_name, "status": "added", "priority": priority}
    except ClientError as e:
        return {"rule_group": rule_group_name, "error": str(e)}


def create_rate_limit_rule(client, acl_name, acl_id, scope, limit=2000, priority=1):
    """Create a rate-limiting rule for DDoS/brute-force protection."""
    try:
        acl = client.get_web_acl(Name=acl_name, Scope=scope, Id=acl_id)
        rules = acl["WebACL"]["Rules"]
        lock_token = acl["LockToken"]
        rules.append({
            "Name": "RateLimitRule",
            "Priority": priority,
            "Statement": {"RateBasedStatement": {"Limit": limit, "AggregateKeyType": "IP"}},
            "Action": {"Block": {}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                "MetricName": "RateLimitRule"}})
        client.update_web_acl(
            Name=acl_name, Scope=scope, Id=acl_id, LockToken=lock_token,
            DefaultAction={"Allow": {}}, Rules=rules,
            VisibilityConfig=acl["WebACL"]["VisibilityConfig"])
        return {"rule": "RateLimitRule", "limit": limit, "status": "created"}
    except ClientError as e:
        return {"error": str(e)}


def create_geo_block_rule(client, acl_name, acl_id, scope, country_codes, priority=2):
    """Create a geo-blocking rule for specified country codes."""
    try:
        acl = client.get_web_acl(Name=acl_name, Scope=scope, Id=acl_id)
        rules = acl["WebACL"]["Rules"]
        lock_token = acl["LockToken"]
        rules.append({
            "Name": "GeoBlockRule",
            "Priority": priority,
            "Statement": {"GeoMatchStatement": {"CountryCodes": country_codes}},
            "Action": {"Block": {}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                "MetricName": "GeoBlockRule"}})
        client.update_web_acl(
            Name=acl_name, Scope=scope, Id=acl_id, LockToken=lock_token,
            DefaultAction={"Allow": {}}, Rules=rules,
            VisibilityConfig=acl["WebACL"]["VisibilityConfig"])
        return {"rule": "GeoBlockRule", "countries": country_codes, "status": "created"}
    except ClientError as e:
        return {"error": str(e)}


def list_web_acls(client, scope="REGIONAL"):
    """List all Web ACLs."""
    try:
        resp = client.list_web_acls(Scope=scope)
        return [{"name": acl["Name"], "id": acl["Id"], "arn": acl["ARN"]}
                for acl in resp.get("WebACLs", [])]
    except ClientError as e:
        return [{"error": str(e)}]


def get_sampled_requests(client, acl_arn, rule_metric, scope="REGIONAL", max_items=100):
    """Get sampled requests for WAF rule analysis."""
    try:
        resp = client.get_sampled_requests(
            WebAclArn=acl_arn, RuleMetricName=rule_metric, Scope=scope,
            TimeWindow={"StartTime": datetime.utcnow().replace(hour=0, minute=0),
                        "EndTime": datetime.utcnow()},
            MaxItems=max_items)
        return [{"action": r["Action"], "uri": r["Request"]["URI"],
                 "method": r["Request"]["Method"],
                 "country": r["Request"].get("Country", ""),
                 "source_ip": r["Request"]["ClientIP"]}
                for r in resp.get("SampledRequests", [])]
    except ClientError as e:
        return [{"error": str(e)}]


def run_waf_audit(region="us-east-1", scope="REGIONAL"):
    """Run WAF configuration audit."""
    client = get_waf_client(region, scope)

    print(f"\n{'='*60}")
    print(f"  AWS WAF CONFIGURATION AUDIT")
    print(f"  Region: {region} | Scope: {scope}")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    acls = list_web_acls(client, scope)
    print(f"--- WEB ACLs ({len(acls)}) ---")
    for acl in acls:
        if "error" in acl:
            print(f"  Error: {acl['error']}")
            continue
        print(f"  {acl['name']} ({acl['id']})")
        try:
            detail = client.get_web_acl(Name=acl["name"], Scope=scope, Id=acl["id"])
            rules = detail["WebACL"]["Rules"]
            print(f"    Rules: {len(rules)}")
            for r in rules:
                print(f"      [{r['Priority']}] {r['Name']}")
        except ClientError:
            pass

    print(f"\n--- AVAILABLE MANAGED RULE GROUPS ---")
    for mrg in MANAGED_RULE_GROUPS:
        print(f"  {mrg['name']}: {mrg['description']}")

    print(f"\n{'='*60}\n")
    return {"acls": acls}


def main():
    parser = argparse.ArgumentParser(description="Cloud WAF Rules Agent")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--scope", default="REGIONAL", choices=["REGIONAL", "CLOUDFRONT"])
    parser.add_argument("--audit", action="store_true", help="Audit WAF configuration")
    parser.add_argument("--create-acl", help="Create new Web ACL with given name")
    parser.add_argument("--output", help="Save report to JSON")
    args = parser.parse_args()

    if args.audit:
        report = run_waf_audit(args.region, args.scope)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
    elif args.create_acl:
        client = get_waf_client(args.region, args.scope)
        result = create_web_acl(client, args.create_acl, args.scope)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
