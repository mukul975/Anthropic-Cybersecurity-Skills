#!/usr/bin/env python3
"""Azure Storage misconfiguration detection agent using Azure CLI."""

import json
import subprocess
import sys
from datetime import datetime


def az_cli(args):
    """Execute Azure CLI command and return parsed JSON."""
    cmd = ["az"] + args + ["--output", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
        return {"error": result.stderr.strip()} if result.returncode != 0 else {}
    except Exception as e:
        return {"error": str(e)}


def list_storage_accounts():
    """List all storage accounts with security-relevant properties."""
    return az_cli([
        "storage", "account", "list",
        "--query", "[].{name:name, resourceGroup:resourceGroup, location:location, "
                  "httpsOnly:enableHttpsTrafficOnly, minTls:minimumTlsVersion, "
                  "publicAccess:allowBlobPublicAccess, kind:kind, sku:sku.name}",
    ])


def check_public_containers(account_name, account_key=None):
    """Check for publicly accessible blob containers in a storage account."""
    args = ["storage", "container", "list", "--account-name", account_name,
            "--query", "[].{name:name, publicAccess:properties.publicAccess}"]
    if account_key:
        args.extend(["--account-key", account_key])
    result = az_cli(args)
    if isinstance(result, list):
        public = [c for c in result if c.get("publicAccess") and c["publicAccess"] != "None"]
        return {
            "account": account_name,
            "total_containers": len(result),
            "public_containers": public,
            "public_count": len(public),
        }
    return result


def check_encryption_settings(account_name, resource_group):
    """Verify encryption configuration for a storage account."""
    result = az_cli([
        "storage", "account", "show",
        "--name", account_name, "--resource-group", resource_group,
        "--query", "{encryption:encryption, httpsOnly:enableHttpsTrafficOnly, "
                  "minTls:minimumTlsVersion, keySource:encryption.keySource}",
    ])
    return result


def check_network_rules(account_name, resource_group):
    """Check network access rules for a storage account."""
    result = az_cli([
        "storage", "account", "show",
        "--name", account_name, "--resource-group", resource_group,
        "--query", "{defaultAction:networkRuleSet.defaultAction, "
                  "bypass:networkRuleSet.bypass, "
                  "ipRules:networkRuleSet.ipRules, "
                  "virtualNetworkRules:networkRuleSet.virtualNetworkRules}",
    ])
    issues = []
    if isinstance(result, dict):
        if result.get("defaultAction") == "Allow":
            issues.append("Default network action is Allow (should be Deny)")
        if not result.get("ipRules") and not result.get("virtualNetworkRules"):
            if result.get("defaultAction") == "Allow":
                issues.append("No IP or VNet restrictions configured")
    return {"account": account_name, "network_rules": result, "issues": issues}


def check_logging_enabled(account_name, account_key=None):
    """Check if storage analytics logging is enabled."""
    args = ["storage", "logging", "show", "--account-name", account_name, "--services", "bqt"]
    if account_key:
        args.extend(["--account-key", account_key])
    return az_cli(args)


def check_soft_delete(account_name, resource_group):
    """Check if soft delete is enabled for blobs and containers."""
    result = az_cli([
        "storage", "account", "blob-service-properties", "show",
        "--account-name", account_name, "--resource-group", resource_group,
        "--query", "{deleteRetention:deleteRetentionPolicy, "
                  "containerDeleteRetention:containerDeleteRetentionPolicy, "
                  "versioning:isVersioningEnabled}",
    ])
    return result


def audit_storage_account(account_name, resource_group):
    """Run full security audit on a single storage account."""
    findings = []

    account = az_cli([
        "storage", "account", "show",
        "--name", account_name, "--resource-group", resource_group,
    ])
    if isinstance(account, dict) and "error" not in account:
        if not account.get("enableHttpsTrafficOnly"):
            findings.append({"severity": "HIGH", "finding": "HTTPS-only not enforced"})
        tls = account.get("minimumTlsVersion", "")
        if tls and tls < "TLS1_2":
            findings.append({"severity": "HIGH", "finding": f"Minimum TLS version is {tls} (should be TLS1_2)"})
        if account.get("allowBlobPublicAccess"):
            findings.append({"severity": "CRITICAL", "finding": "Public blob access is enabled at account level"})

    network = check_network_rules(account_name, resource_group)
    if network.get("issues"):
        for issue in network["issues"]:
            findings.append({"severity": "HIGH", "finding": issue})

    return {
        "account": account_name,
        "resource_group": resource_group,
        "findings": findings,
        "finding_count": len(findings),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def audit_all_accounts():
    """Audit all storage accounts across the subscription."""
    accounts = list_storage_accounts()
    if not isinstance(accounts, list):
        return accounts

    results = []
    for acct in accounts:
        name = acct.get("name")
        rg = acct.get("resourceGroup")
        if name and rg:
            audit = audit_storage_account(name, rg)
            results.append(audit)

    total_findings = sum(r.get("finding_count", 0) for r in results)
    critical = sum(
        1 for r in results
        for f in r.get("findings", [])
        if f.get("severity") == "CRITICAL"
    )
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "accounts_audited": len(results),
        "total_findings": total_findings,
        "critical_findings": critical,
        "results": results,
    }


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "audit-all"
    if action == "audit-all":
        print(json.dumps(audit_all_accounts(), indent=2, default=str))
    elif action == "audit" and len(sys.argv) > 3:
        print(json.dumps(audit_storage_account(sys.argv[2], sys.argv[3]), indent=2))
    elif action == "list":
        print(json.dumps(list_storage_accounts(), indent=2))
    elif action == "public" and len(sys.argv) > 2:
        print(json.dumps(check_public_containers(sys.argv[2]), indent=2))
    elif action == "network" and len(sys.argv) > 3:
        print(json.dumps(check_network_rules(sys.argv[2], sys.argv[3]), indent=2))
    else:
        print("Usage: agent.py [audit-all|audit <name> <rg>|list|public <name>|network <name> <rg>]")
