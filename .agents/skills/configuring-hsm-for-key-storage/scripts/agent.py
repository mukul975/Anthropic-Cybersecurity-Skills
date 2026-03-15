#!/usr/bin/env python3
"""HSM key storage management agent using PKCS#11 and AWS CloudHSM."""

import json
import sys
import argparse
from datetime import datetime

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("Install: pip install boto3")
    sys.exit(1)


def list_cloudhsm_clusters(session):
    """List AWS CloudHSM clusters."""
    client = session.client("cloudhsmv2")
    clusters = []
    response = client.describe_clusters()
    for cluster in response.get("Clusters", []):
        clusters.append({
            "id": cluster["ClusterId"],
            "state": cluster["State"],
            "hsm_type": cluster["HsmType"],
            "vpc_id": cluster.get("VpcId", ""),
            "hsms": len(cluster.get("Hsms", [])),
            "security_group": cluster.get("SecurityGroup", ""),
        })
    return clusters


def list_hsm_instances(session, cluster_id):
    """List HSM instances in a cluster."""
    client = session.client("cloudhsmv2")
    response = client.describe_clusters(Filters={"clusterIds": [cluster_id]})
    hsms = []
    for cluster in response.get("Clusters", []):
        for hsm in cluster.get("Hsms", []):
            hsms.append({
                "hsm_id": hsm["HsmId"],
                "az": hsm.get("AvailabilityZone", ""),
                "ip": hsm.get("EniIp", ""),
                "state": hsm.get("State", ""),
            })
    return hsms


def audit_kms_keys(session):
    """Audit KMS keys backed by CloudHSM custom key store."""
    kms = session.client("kms")
    custom_store_keys = []
    paginator = kms.get_paginator("list_keys")
    for page in paginator.paginate():
        for key in page["Keys"]:
            try:
                desc = kms.describe_key(KeyId=key["KeyId"])
                meta = desc["KeyMetadata"]
                if meta.get("CustomKeyStoreId"):
                    custom_store_keys.append({
                        "key_id": meta["KeyId"],
                        "description": meta.get("Description", ""),
                        "key_state": meta["KeyState"],
                        "key_spec": meta.get("KeySpec", ""),
                        "custom_store_id": meta["CustomKeyStoreId"],
                        "origin": meta.get("Origin", ""),
                    })
            except ClientError:
                pass
    return custom_store_keys


def check_cloudhsm_backup(session):
    """Check CloudHSM backup status."""
    client = session.client("cloudhsmv2")
    response = client.describe_backups()
    backups = []
    for backup in response.get("Backups", []):
        backups.append({
            "backup_id": backup["BackupId"],
            "state": backup["BackupState"],
            "cluster_id": backup.get("ClusterId", ""),
            "create_time": str(backup.get("CreateTimestamp", "")),
        })
    return sorted(backups, key=lambda x: x["create_time"], reverse=True)


def run_audit(profile=None, region="us-east-1"):
    """Execute HSM key storage audit."""
    session = boto3.Session(profile_name=profile, region_name=region)
    print(f"\n{'='*60}")
    print(f"  HSM KEY STORAGE AUDIT")
    print(f"  Region: {region}")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    clusters = list_cloudhsm_clusters(session)
    print(f"--- CLOUDHSM CLUSTERS ({len(clusters)}) ---")
    for c in clusters:
        print(f"  {c['id']}: {c['state']} ({c['hsm_type']}, {c['hsms']} HSMs)")

    for cluster in clusters:
        hsms = list_hsm_instances(session, cluster["id"])
        print(f"\n--- HSMs in {cluster['id']} ({len(hsms)}) ---")
        for h in hsms:
            print(f"  {h['hsm_id']}: {h['state']} ({h['az']}, {h['ip']})")

    keys = audit_kms_keys(session)
    print(f"\n--- CUSTOM KEY STORE KEYS ({len(keys)}) ---")
    for k in keys[:10]:
        print(f"  {k['key_id']}: {k['key_state']} ({k['key_spec']})")

    backups = check_cloudhsm_backup(session)
    print(f"\n--- BACKUPS ({len(backups)}) ---")
    for b in backups[:5]:
        print(f"  {b['backup_id']}: {b['state']} ({b['create_time']})")

    return {"clusters": clusters, "keys": keys, "backups": backups}


def main():
    parser = argparse.ArgumentParser(description="HSM Key Storage Agent")
    parser.add_argument("--profile", help="AWS CLI profile")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--audit", action="store_true", help="Run full audit")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    if args.audit:
        report = run_audit(args.profile, args.region)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n[+] Report saved to {args.output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
