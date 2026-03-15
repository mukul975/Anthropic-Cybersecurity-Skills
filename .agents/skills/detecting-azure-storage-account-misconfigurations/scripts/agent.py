#!/usr/bin/env python3
"""Audit Azure Storage accounts for security misconfigurations using azure-mgmt-storage SDK."""

import argparse
import json
import os
import sys
from datetime import datetime


def get_storage_client():
    """Initialize StorageManagementClient with DefaultAzureCredential."""
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.storage import StorageManagementClient
    except ImportError:
        print("Install required packages: pip install azure-mgmt-storage azure-identity", file=sys.stderr)
        sys.exit(1)

    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not subscription_id:
        print("Set AZURE_SUBSCRIPTION_ID environment variable", file=sys.stderr)
        sys.exit(1)

    credential = DefaultAzureCredential()
    return StorageManagementClient(credential=credential, subscription_id=subscription_id)


def audit_storage_account(client, account):
    """Audit a single storage account for misconfigurations."""
    findings = []
    resource_group = account.id.split("/")[4]
    account_name = account.name

    # Check public blob access
    if account.allow_blob_public_access is True:
        findings.append({
            "check": "public_blob_access",
            "severity": "Critical",
            "message": f"Storage account '{account_name}' allows public blob access",
            "remediation": "Set allow_blob_public_access to false on the storage account"
        })

    # Check HTTPS-only enforcement
    if account.enable_https_traffic_only is False:
        findings.append({
            "check": "https_enforcement",
            "severity": "High",
            "message": f"Storage account '{account_name}' allows HTTP traffic",
            "remediation": "Enable 'Secure transfer required' in storage account settings"
        })

    # Check minimum TLS version
    min_tls = getattr(account, "minimum_tls_version", None)
    if min_tls and min_tls in ("TLS1_0", "TLS1_1"):
        findings.append({
            "check": "minimum_tls_version",
            "severity": "High",
            "message": f"Storage account '{account_name}' allows {min_tls} (should be TLS1_2)",
            "remediation": "Set minimum TLS version to TLS1_2"
        })

    # Check encryption at rest
    encryption = account.encryption
    if encryption:
        if not getattr(encryption.services, "blob", None) or not encryption.services.blob.enabled:
            findings.append({
                "check": "blob_encryption",
                "severity": "High",
                "message": f"Storage account '{account_name}' does not have blob encryption enabled",
                "remediation": "Enable Azure Storage Service Encryption for blobs"
            })
        if not getattr(encryption.services, "file", None) or not encryption.services.file.enabled:
            findings.append({
                "check": "file_encryption",
                "severity": "Medium",
                "message": f"Storage account '{account_name}' does not have file encryption enabled",
                "remediation": "Enable Azure Storage Service Encryption for files"
            })
    else:
        findings.append({
            "check": "encryption_missing",
            "severity": "Critical",
            "message": f"Storage account '{account_name}' has no encryption configuration",
            "remediation": "Enable Azure Storage Service Encryption"
        })

    # Check network rules - default action
    network_rules = account.network_rule_set
    if network_rules and network_rules.default_action == "Allow":
        findings.append({
            "check": "network_default_allow",
            "severity": "High",
            "message": f"Storage account '{account_name}' allows access from all networks",
            "remediation": "Set network default action to Deny and add specific virtual network/IP rules"
        })

    # Check infrastructure encryption (double encryption)
    if encryption and not getattr(encryption, "require_infrastructure_encryption", False):
        findings.append({
            "check": "infrastructure_encryption",
            "severity": "Low",
            "message": f"Storage account '{account_name}' does not use infrastructure encryption (double encryption)",
            "remediation": "Enable infrastructure encryption for additional protection"
        })

    # Check key source - prefer customer-managed keys
    if encryption and getattr(encryption, "key_source", None) == "Microsoft.Storage":
        findings.append({
            "check": "customer_managed_keys",
            "severity": "Low",
            "message": f"Storage account '{account_name}' uses Microsoft-managed keys instead of customer-managed keys",
            "remediation": "Configure customer-managed keys via Azure Key Vault for enhanced control"
        })

    return {
        "account_name": account_name,
        "resource_group": resource_group,
        "location": account.location,
        "sku": account.sku.name if account.sku else "unknown",
        "kind": account.kind,
        "findings": findings,
        "finding_count": len(findings)
    }


def audit_blob_containers(client, account):
    """Check blob containers for individual public access settings."""
    resource_group = account.id.split("/")[4]
    container_findings = []

    try:
        containers = client.blob_containers.list(
            resource_group_name=resource_group,
            account_name=account.name
        )
        for container in containers:
            public_access = getattr(container, "public_access", None)
            if public_access and public_access != "None":
                container_findings.append({
                    "container_name": container.name,
                    "public_access_level": str(public_access),
                    "severity": "Critical",
                    "message": f"Container '{container.name}' has public access level: {public_access}",
                    "remediation": "Set container public access level to 'None' (private)"
                })
    except Exception as e:
        container_findings.append({
            "error": f"Could not list containers for {account.name}: {str(e)}"
        })

    return container_findings


def run_audit(args):
    """Run the full storage account audit."""
    client = get_storage_client()
    results = {
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "subscription_id": os.environ.get("AZURE_SUBSCRIPTION_ID", ""),
        "accounts": [],
        "summary": {
            "total_accounts": 0,
            "accounts_with_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
    }

    accounts = list(client.storage_accounts.list())
    results["summary"]["total_accounts"] = len(accounts)

    for account in accounts:
        account_result = audit_storage_account(client, account)

        if args.check_containers:
            container_findings = audit_blob_containers(client, account)
            account_result["container_findings"] = container_findings

        results["accounts"].append(account_result)

        if account_result["finding_count"] > 0:
            results["summary"]["accounts_with_findings"] += 1

        for finding in account_result["findings"]:
            severity = finding.get("severity", "").lower()
            if severity in results["summary"]:
                results["summary"][severity] += 1

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Audit Azure Storage accounts for security misconfigurations"
    )
    parser.add_argument(
        "--check-containers", action="store_true",
        help="Also check individual blob container public access settings"
    )
    parser.add_argument(
        "--output", "-o", default="-",
        help="Output file path (default: stdout)"
    )
    parser.add_argument(
        "--severity-filter", choices=["critical", "high", "medium", "low"],
        help="Only show findings at or above this severity level"
    )
    args = parser.parse_args()

    results = run_audit(args)

    if args.severity_filter:
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        min_severity = severity_order[args.severity_filter]
        for account in results["accounts"]:
            account["findings"] = [
                f for f in account["findings"]
                if severity_order.get(f.get("severity", "").lower(), 0) >= min_severity
            ]
            account["finding_count"] = len(account["findings"])

    output_json = json.dumps(results, indent=2)

    if args.output == "-":
        print(output_json)
    else:
        with open(args.output, "w") as f:
            f.write(output_json)
        print(f"Audit report written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
