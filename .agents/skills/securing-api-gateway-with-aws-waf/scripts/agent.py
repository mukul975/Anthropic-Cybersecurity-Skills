#!/usr/bin/env python3
"""Agent for managing AWS WAF Web ACLs protecting API Gateway endpoints."""

import boto3
import json
import sys
import argparse
from datetime import datetime, timedelta, timezone


def get_waf_client(region="us-east-1"):
    """Create WAFv2 client for regional resources."""
    return boto3.client("wafv2", region_name=region)


def list_web_acls(client, scope="REGIONAL"):
    """List all Web ACLs in the account."""
    response = client.list_web_acls(Scope=scope)
    acls = response.get("WebACLs", [])
    print(f"[*] Found {len(acls)} Web ACL(s)")
    for acl in acls:
        print(f"  - {acl['Name']} (ID: {acl['Id']})")
    return acls


def get_web_acl_details(client, name, acl_id, scope="REGIONAL"):
    """Get detailed Web ACL configuration including all rules."""
    response = client.get_web_acl(Name=name, Scope=scope, Id=acl_id)
    acl = response["WebACL"]
    lock_token = response["LockToken"]
    print(f"\n[*] Web ACL: {acl['Name']}")
    print(f"  ARN: {acl['ARN']}")
    print(f"  Default Action: {list(acl['DefaultAction'].keys())[0]}")
    print(f"  Rules: {len(acl.get('Rules', []))}")
    for rule in acl.get("Rules", []):
        action = list(rule.get("Action", rule.get("OverrideAction", {})).keys())[0]
        print(f"    [{rule['Priority']}] {rule['Name']} -> {action}")
    return acl, lock_token


def check_waf_association(client, web_acl_arn):
    """Check which resources are associated with a Web ACL."""
    resource_types = ["API_GATEWAY", "APPLICATION_LOAD_BALANCER", "APPSYNC", "COGNITO_USER_POOL"]
    associations = []
    for rt in resource_types:
        try:
            resp = client.list_resources_for_web_acl(WebACLArn=web_acl_arn, ResourceType=rt)
            for arn in resp.get("ResourceArns", []):
                associations.append({"type": rt, "arn": arn})
                print(f"  [+] Associated: {rt} -> {arn}")
        except client.exceptions.WAFInvalidParameterException:
            continue
    if not associations:
        print("  [-] No resources associated with this Web ACL")
    return associations


def get_sampled_requests(client, web_acl_arn, rule_metric, scope="REGIONAL", minutes=60):
    """Get sampled requests for a specific rule to analyze blocks."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=minutes)
    try:
        response = client.get_sampled_requests(
            WebAclArn=web_acl_arn, RuleMetricName=rule_metric, Scope=scope,
            TimeWindow={"StartTime": start_time, "EndTime": end_time}, MaxItems=50,
        )
        samples = response.get("SampledRequests", [])
        print(f"\n[*] Sampled requests for rule '{rule_metric}': {len(samples)}")
        for s in samples[:10]:
            req = s["Request"]
            print(f"  [{s.get('Action', '?')}] {req['Method']} {req.get('URI', '/')} "
                  f"from {req.get('ClientIP', '?')} at {s.get('Timestamp', '?')}")
        return samples
    except Exception as e:
        print(f"  [-] Error getting samples: {e}")
        return []


def get_rate_based_keys(client, name, acl_id, rule_name, scope="REGIONAL"):
    """Get IPs currently rate-limited by a rate-based rule."""
    try:
        response = client.get_rate_based_statement_managed_keys(
            Scope=scope, WebACLName=name, WebACLId=acl_id, RuleName=rule_name,
        )
        keys = response.get("ManagedKeysIPV4", {}).get("Addresses", [])
        keys += response.get("ManagedKeysIPV6", {}).get("Addresses", [])
        print(f"\n[*] Rate-limited IPs for rule '{rule_name}': {len(keys)}")
        for ip in keys:
            print(f"  [!] {ip}")
        return keys
    except Exception as e:
        print(f"  [-] Error: {e}")
        return []


def get_waf_metrics(region="us-east-1", acl_name="api-gateway-waf", hours=24):
    """Get WAF CloudWatch metrics for blocked and allowed requests."""
    cw = boto3.client("cloudwatch", region_name=region)
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)
    metrics = {}
    for metric_name in ["AllowedRequests", "BlockedRequests"]:
        response = cw.get_metric_statistics(
            Namespace="AWS/WAFV2", MetricName=metric_name,
            Dimensions=[{"Name": "WebACL", "Value": acl_name}, {"Name": "Rule", "Value": "ALL"}],
            StartTime=start_time, EndTime=end_time, Period=3600, Statistics=["Sum"],
        )
        total = sum(dp["Sum"] for dp in response.get("Datapoints", []))
        metrics[metric_name] = total
        print(f"  {metric_name}: {int(total):,}")
    return metrics


def audit_web_acl(client, name, acl_id, scope="REGIONAL"):
    """Run a security audit on a Web ACL configuration."""
    acl, _ = get_web_acl_details(client, name, acl_id, scope)
    findings = []
    rules = acl.get("Rules", [])
    rule_names = [r["Name"] for r in rules]
    recommended = ["AWSManagedRulesCommonRuleSet", "AWSManagedRulesKnownBadInputsRuleSet",
                    "AWSManagedRulesSQLiRuleSet", "AWSManagedRulesAmazonIpReputationList"]
    for rec in recommended:
        if not any(rec in rn for rn in rule_names):
            findings.append(f"MISSING: Recommended managed rule group '{rec}' not found")
    has_rate_rule = any("RateBasedStatement" in json.dumps(r.get("Statement", {})) for r in rules)
    if not has_rate_rule:
        findings.append("MISSING: No rate-based rule configured")
    default_action = list(acl["DefaultAction"].keys())[0]
    if default_action == "Allow":
        print("  [INFO] Default action is Allow (standard for WAF)")
    print(f"\n[*] Audit findings: {len(findings)}")
    for f in findings:
        print(f"  [!] {f}")
    return findings


def main():
    parser = argparse.ArgumentParser(description="AWS WAF API Gateway Security Agent")
    parser.add_argument("action", choices=["list", "details", "audit", "metrics", "samples", "rate-keys"])
    parser.add_argument("--name", help="Web ACL name")
    parser.add_argument("--id", help="Web ACL ID")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--rule-metric", help="Rule metric name for sampling")
    parser.add_argument("--rule-name", help="Rate-based rule name")
    parser.add_argument("--hours", type=int, default=24, help="Lookback hours for metrics")
    args = parser.parse_args()

    client = get_waf_client(args.region)

    if args.action == "list":
        list_web_acls(client)
    elif args.action == "details":
        acl, _ = get_web_acl_details(client, args.name, args.id)
        check_waf_association(client, acl["ARN"])
    elif args.action == "audit":
        audit_web_acl(client, args.name, args.id)
    elif args.action == "metrics":
        get_waf_metrics(args.region, args.name or "api-gateway-waf", args.hours)
    elif args.action == "samples":
        acls = list_web_acls(client)
        acl_arn = next((a["ARN"] for a in acls if a["Name"] == args.name), None)
        if acl_arn:
            get_sampled_requests(client, acl_arn, args.rule_metric or "ALL")
    elif args.action == "rate-keys":
        get_rate_based_keys(client, args.name, args.id, args.rule_name or "RateLimitPerIP")


if __name__ == "__main__":
    main()
