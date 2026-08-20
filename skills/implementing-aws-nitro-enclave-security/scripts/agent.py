#!/usr/bin/env python3
# For authorized cloud security assessments only
"""AWS Nitro Enclave Security Agent - Validates enclave attestation, audits KMS policies, and verifies enclave isolation."""

import argparse
import base64
import json
import logging
import sys
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("ERROR: boto3 required. Install with: pip install boto3")
    sys.exit(1)

try:
    import cbor2
except ImportError:
    cbor2 = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def get_nitro_instances(ec2_client, region):
    """Find EC2 instances with Nitro Enclave support enabled."""
    findings = []
    paginator = ec2_client.get_paginator("describe_instances")
    for page in paginator.paginate(
        Filters=[{"Name": "enclave-options.enabled", "Values": ["true"]}]
    ):
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                instance_info = {
                    "instance_id": instance["InstanceId"],
                    "instance_type": instance["InstanceType"],
                    "state": instance["State"]["Name"],
                    "enclave_enabled": True,
                    "iam_role": None,
                    "launch_time": instance.get("LaunchTime", "").isoformat() if instance.get("LaunchTime") else None,
                    "region": region,
                }
                if instance.get("IamInstanceProfile"):
                    instance_info["iam_role"] = instance["IamInstanceProfile"]["Arn"]
                findings.append(instance_info)
    logger.info("Found %d Nitro Enclave-enabled instances in %s", len(findings), region)
    return findings


def audit_kms_key_policy(kms_client, key_id):
    """Audit a KMS key policy for Nitro Enclave attestation conditions."""
    result = {
        "key_id": key_id,
        "has_attestation_condition": False,
        "pcr_conditions": [],
        "image_sha_condition": False,
        "allowed_principals": [],
        "allowed_actions": [],
        "issues": [],
    }
    try:
        key_meta = kms_client.describe_key(KeyId=key_id)
        result["key_arn"] = key_meta["KeyMetadata"]["Arn"]
        result["key_state"] = key_meta["KeyMetadata"]["KeyState"]
        result["key_usage"] = key_meta["KeyMetadata"]["KeyUsage"]

        policy_json = kms_client.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
        policy = json.loads(policy_json)

        for statement in policy.get("Statement", []):
            principals = statement.get("Principal", {})
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            conditions = statement.get("Condition", {})

            for action in actions:
                if action not in result["allowed_actions"]:
                    result["allowed_actions"].append(action)

            if isinstance(principals, dict) and "AWS" in principals:
                aws_principals = principals["AWS"]
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                result["allowed_principals"].extend(aws_principals)

            # Check for attestation conditions
            for operator_key, operator_conditions in conditions.items():
                for cond_key, cond_value in operator_conditions.items():
                    if "RecipientAttestation" in cond_key:
                        result["has_attestation_condition"] = True
                        if "ImageSha384" in cond_key:
                            result["image_sha_condition"] = True
                            result["pcr_conditions"].append({
                                "type": "ImageSha384 (PCR0)",
                                "operator": operator_key,
                                "value": cond_value[:32] + "..." if len(str(cond_value)) > 32 else cond_value,
                            })
                        elif "PCR" in cond_key:
                            pcr_id = cond_key.split(":")[-1]
                            result["pcr_conditions"].append({
                                "type": pcr_id,
                                "operator": operator_key,
                                "value": cond_value[:32] + "..." if len(str(cond_value)) > 32 else cond_value,
                            })

            # Check for missing attestation on decrypt actions
            has_decrypt = any("Decrypt" in a or "GenerateDataKey" in a for a in actions)
            if has_decrypt and not any("RecipientAttestation" in str(conditions)):
                if statement.get("Effect") == "Allow":
                    result["issues"].append(
                        f"Statement '{statement.get('Sid', 'unnamed')}' allows Decrypt/GenerateDataKey "
                        f"without kms:RecipientAttestation condition - parent instance can decrypt directly"
                    )

        if not result["has_attestation_condition"]:
            result["issues"].append(
                "KMS key policy has no RecipientAttestation conditions - "
                "decryption is not restricted to verified enclaves"
            )

    except ClientError as e:
        result["issues"].append(f"Error accessing key: {e.response['Error']['Message']}")

    return result


def audit_iam_role_for_enclave(iam_client, role_name):
    """Check if an IAM role has appropriate permissions for enclave operations."""
    result = {
        "role_name": role_name,
        "has_kms_permissions": False,
        "kms_actions": [],
        "has_ec2_enclave_permissions": False,
        "overprivileged": False,
        "issues": [],
    }
    try:
        # Check attached policies
        attached = iam_client.list_attached_role_policies(RoleName=role_name)
        for policy in attached["AttachedPolicies"]:
            if policy["PolicyName"] == "AdministratorAccess":
                result["overprivileged"] = True
                result["issues"].append(
                    "Role has AdministratorAccess - violates least privilege for enclave workloads"
                )

            policy_version = iam_client.get_policy(PolicyArn=policy["PolicyArn"])
            version_id = policy_version["Policy"]["DefaultVersionId"]
            policy_doc = iam_client.get_policy_version(
                PolicyArn=policy["PolicyArn"], VersionId=version_id
            )
            for stmt in policy_doc["PolicyVersion"]["Document"].get("Statement", []):
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                for action in actions:
                    if "kms:" in action:
                        result["has_kms_permissions"] = True
                        result["kms_actions"].append(action)
                    if action in ("kms:*", "*"):
                        result["overprivileged"] = True
                        result["issues"].append(
                            f"Role has wildcard KMS permissions ({action}) - should restrict to specific keys"
                        )

        # Check inline policies
        inline = iam_client.list_role_policies(RoleName=role_name)
        for policy_name in inline["PolicyNames"]:
            policy_doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            for stmt in policy_doc["PolicyDocument"].get("Statement", []):
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                resources = stmt.get("Resource", [])
                if isinstance(resources, str):
                    resources = [resources]
                for action in actions:
                    if "kms:" in action:
                        result["has_kms_permissions"] = True
                        result["kms_actions"].append(action)
                if "*" in resources:
                    result["issues"].append(
                        f"Inline policy '{policy_name}' uses wildcard Resource - restrict to specific KMS key ARNs"
                    )

        if not result["has_kms_permissions"]:
            result["issues"].append("Role has no KMS permissions - cannot perform enclave-side decryption")

    except ClientError as e:
        result["issues"].append(f"Error auditing role: {e.response['Error']['Message']}")

    return result


def check_enclave_allocator_config(instance_id, ssm_client):
    """Check enclave allocator configuration via SSM (if available)."""
    result = {
        "instance_id": instance_id,
        "allocator_configured": False,
        "memory_mib": None,
        "cpu_count": None,
        "issues": [],
    }
    try:
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={
                "commands": ["cat /etc/nitro_enclaves/allocator.yaml 2>/dev/null || echo 'NOT_FOUND'"]
            },
        )
        command_id = response["Command"]["CommandId"]

        import time
        time.sleep(3)

        output = ssm_client.get_command_invocation(
            CommandId=command_id, InstanceId=instance_id
        )
        stdout = output.get("StandardOutputContent", "")

        if "NOT_FOUND" in stdout:
            result["issues"].append("Allocator config not found at /etc/nitro_enclaves/allocator.yaml")
        else:
            result["allocator_configured"] = True
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith("memory_mib:"):
                    result["memory_mib"] = int(line.split(":")[1].strip())
                elif line.startswith("cpu_count:"):
                    result["cpu_count"] = int(line.split(":")[1].strip())

            if result["memory_mib"] and result["memory_mib"] < 512:
                result["issues"].append(
                    f"Allocated memory ({result['memory_mib']} MiB) is very low - may cause enclave launch failures"
                )
            if result["cpu_count"] and result["cpu_count"] < 2:
                result["issues"].append(
                    f"Allocated CPUs ({result['cpu_count']}) is minimal - consider 2+ for production"
                )

    except ClientError as e:
        result["issues"].append(f"SSM access failed: {e.response['Error']['Message']}")

    return result


def validate_attestation_document_structure(attestation_b64):
    """Validate the structure of a base64-encoded attestation document."""
    if cbor2 is None:
        return {"error": "cbor2 package required for attestation validation. Install with: pip install cbor2"}

    result = {
        "valid_structure": False,
        "pcrs": {},
        "module_id": None,
        "digest": None,
        "timestamp": None,
        "has_certificate": False,
        "has_cabundle": False,
        "has_public_key": False,
        "issues": [],
    }
    try:
        attestation_bytes = base64.b64decode(attestation_b64)

        # COSE_Sign1 is a CBOR array: [protected, unprotected, payload, signature]
        cose_structure = cbor2.loads(attestation_bytes)
        if hasattr(cose_structure, "tag") and cose_structure.tag == 18:
            cose_array = cose_structure.value
        elif isinstance(cose_structure, list) and len(cose_structure) == 4:
            cose_array = cose_structure
        else:
            result["issues"].append("Not a valid COSE_Sign1 structure")
            return result

        payload = cbor2.loads(cose_array[2])

        result["module_id"] = payload.get("module_id")
        result["digest"] = payload.get("digest")
        result["timestamp"] = payload.get("timestamp")

        if result["timestamp"]:
            ts = datetime.fromtimestamp(result["timestamp"] / 1000, tz=timezone.utc)
            result["timestamp_human"] = ts.isoformat()

        pcrs = payload.get("pcrs", {})
        for idx, value in pcrs.items():
            result["pcrs"][f"PCR{idx}"] = value.hex() if isinstance(value, bytes) else str(value)

        result["has_certificate"] = "certificate" in payload and payload["certificate"] is not None
        result["has_cabundle"] = "cabundle" in payload and len(payload.get("cabundle", [])) > 0
        result["has_public_key"] = "public_key" in payload and payload["public_key"] is not None

        result["valid_structure"] = True

        if not result["has_cabundle"]:
            result["issues"].append("Missing CA bundle - cannot verify certificate chain to AWS root")
        if not result["has_public_key"]:
            result["issues"].append("No public key in attestation - KMS cannot encrypt response to enclave")
        if "PCR0" not in result["pcrs"]:
            result["issues"].append("PCR0 (image hash) not present in attestation document")

    except Exception as e:
        result["issues"].append(f"Attestation parsing error: {str(e)}")

    return result


def audit_cloudtrail_enclave_events(cloudtrail_client, days_back=7):
    """Search CloudTrail for enclave-related security events."""
    from datetime import timedelta
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days_back)

    events_of_interest = [
        "RunInstances",
        "TerminateInstances",
        "ModifyInstanceAttribute",
    ]
    kms_events = ["Decrypt", "GenerateDataKey", "GenerateDataKeyPair", "GenerateRandom"]

    findings = []

    # Check for instance launches with enclave options
    for event_name in events_of_interest:
        try:
            response = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {"AttributeKey": "EventName", "AttributeValue": event_name}
                ],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50,
            )
            for event in response.get("Events", []):
                ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
                req_params = ct_event.get("requestParameters", {})

                if event_name == "RunInstances":
                    enclave_opts = req_params.get("enclaveOptions", {})
                    if enclave_opts.get("enabled"):
                        findings.append({
                            "event": event_name,
                            "time": event["EventTime"].isoformat(),
                            "user": event.get("Username"),
                            "detail": "Enclave-enabled instance launched",
                            "source_ip": ct_event.get("sourceIPAddress"),
                        })
        except ClientError:
            continue

    # Check for KMS calls with Recipient parameter (enclave attestation)
    for event_name in kms_events:
        try:
            response = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {"AttributeKey": "EventName", "AttributeValue": event_name}
                ],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50,
            )
            for event in response.get("Events", []):
                ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
                req_params = ct_event.get("requestParameters", {})
                if "recipient" in req_params or "Recipient" in req_params:
                    findings.append({
                        "event": event_name,
                        "time": event["EventTime"].isoformat(),
                        "user": event.get("Username"),
                        "detail": "KMS operation with enclave attestation document",
                        "key_id": req_params.get("keyId"),
                        "source_ip": ct_event.get("sourceIPAddress"),
                    })
        except ClientError:
            continue

    logger.info("Found %d enclave-related CloudTrail events", len(findings))
    return findings


def generate_report(instances, kms_audits, iam_audits, cloudtrail_events, attestation_results=None):
    """Generate comprehensive Nitro Enclave security assessment report."""
    total_issues = 0
    critical_issues = []

    for audit in kms_audits:
        total_issues += len(audit.get("issues", []))
        if not audit.get("has_attestation_condition"):
            critical_issues.append(f"KMS key {audit['key_id']} has no attestation conditions")

    for audit in iam_audits:
        total_issues += len(audit.get("issues", []))
        if audit.get("overprivileged"):
            critical_issues.append(f"IAM role {audit['role_name']} is overprivileged")

    report = {
        "report_type": "Nitro Enclave Security Assessment",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "enclave_instances": len(instances),
            "kms_keys_audited": len(kms_audits),
            "iam_roles_audited": len(iam_audits),
            "cloudtrail_events": len(cloudtrail_events),
            "total_issues": total_issues,
            "critical_issues": len(critical_issues),
        },
        "critical_findings": critical_issues,
        "instances": instances,
        "kms_policy_audits": kms_audits,
        "iam_role_audits": iam_audits,
        "cloudtrail_events": cloudtrail_events,
    }

    if attestation_results:
        report["attestation_validation"] = attestation_results

    return report


def main():
    parser = argparse.ArgumentParser(description="AWS Nitro Enclave Security Assessment Agent")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--kms-key-ids", nargs="+", help="KMS key IDs to audit")
    parser.add_argument("--iam-roles", nargs="+", help="IAM role names to audit for enclave permissions")
    parser.add_argument("--attestation-doc", help="Base64-encoded attestation document to validate")
    parser.add_argument("--cloudtrail-days", type=int, default=7, help="Days of CloudTrail history to search")
    parser.add_argument("--output", default="nitro_enclave_security_report.json", help="Output report file")
    args = parser.parse_args()

    session = boto3.Session(region_name=args.region)
    ec2_client = session.client("ec2")
    kms_client = session.client("kms")
    iam_client = session.client("iam")
    cloudtrail_client = session.client("cloudtrail")

    logger.info("Starting Nitro Enclave security assessment in %s", args.region)

    # Step 1: Find enclave-enabled instances
    instances = get_nitro_instances(ec2_client, args.region)

    # Step 2: Audit KMS key policies
    kms_audits = []
    if args.kms_key_ids:
        for key_id in args.kms_key_ids:
            logger.info("Auditing KMS key: %s", key_id)
            kms_audits.append(audit_kms_key_policy(kms_client, key_id))
    else:
        # Auto-discover KMS keys
        try:
            keys_response = kms_client.list_keys(Limit=100)
            for key in keys_response.get("Keys", []):
                audit = audit_kms_key_policy(kms_client, key["KeyId"])
                if audit.get("has_attestation_condition") or audit.get("allowed_actions"):
                    kms_audits.append(audit)
        except ClientError as e:
            logger.warning("Cannot list KMS keys: %s", e)

    # Step 3: Audit IAM roles
    iam_audits = []
    if args.iam_roles:
        for role_name in args.iam_roles:
            logger.info("Auditing IAM role: %s", role_name)
            iam_audits.append(audit_iam_role_for_enclave(iam_client, role_name))

    # Step 4: Search CloudTrail events
    cloudtrail_events = audit_cloudtrail_enclave_events(cloudtrail_client, args.cloudtrail_days)

    # Step 5: Validate attestation document if provided
    attestation_results = None
    if args.attestation_doc:
        logger.info("Validating attestation document")
        attestation_results = validate_attestation_document_structure(args.attestation_doc)

    # Generate report
    report = generate_report(instances, kms_audits, iam_audits, cloudtrail_events, attestation_results)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report saved to %s", args.output)

    # Print summary
    summary = report["summary"]
    logger.info(
        "Assessment complete: %d instances, %d KMS keys, %d IAM roles, %d issues (%d critical)",
        summary["enclave_instances"],
        summary["kms_keys_audited"],
        summary["iam_roles_audited"],
        summary["total_issues"],
        summary["critical_issues"],
    )

    if report["critical_findings"]:
        logger.warning("CRITICAL FINDINGS:")
        for finding in report["critical_findings"]:
            logger.warning("  - %s", finding)

    return 0 if summary["critical_issues"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
