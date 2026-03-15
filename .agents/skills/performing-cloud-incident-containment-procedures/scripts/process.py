"""
Cloud Incident Containment Automation Script
Provides containment procedures for AWS, Azure, and GCP environments.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path


class CloudContainmentManager:
    """Manages cloud incident containment across AWS, Azure, and GCP."""

    def __init__(self, output_dir="cloud_containment_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.actions_log = []
        self.contained_resources = []

    def log_action(self, platform, action, resource, status, details=""):
        """Log a containment action for audit trail."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": platform,
            "action": action,
            "resource": resource,
            "status": status,
            "details": details,
        }
        self.actions_log.append(entry)
        print(f"[{platform}] {action}: {resource} -> {status}")

    def generate_aws_containment_commands(self, incident_type, resource_details):
        """Generate AWS CLI containment commands based on incident type."""
        commands = []

        if incident_type == "credential_compromise":
            user = resource_details.get("username", "UNKNOWN")
            commands.extend([
                {
                    "step": 1,
                    "description": "Disable all access keys",
                    "command": f"aws iam list-access-keys --user-name {user} --query 'AccessKeyMetadata[].AccessKeyId' --output text | xargs -I {{}} aws iam update-access-key --user-name {user} --access-key-id {{}} --status Inactive",
                },
                {
                    "step": 2,
                    "description": "Attach deny-all policy",
                    "command": f'aws iam put-user-policy --user-name {user} --policy-name EmergencyDenyAll --policy-document \'{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Action":"*","Resource":"*"}}]}}\'',
                },
                {
                    "step": 3,
                    "description": "Delete console password",
                    "command": f"aws iam delete-login-profile --user-name {user}",
                },
                {
                    "step": 4,
                    "description": "Deactivate MFA devices",
                    "command": f"aws iam list-mfa-devices --user-name {user}",
                },
            ])

        elif incident_type == "ec2_compromise":
            instance_id = resource_details.get("instance_id", "i-UNKNOWN")
            vpc_id = resource_details.get("vpc_id", "vpc-UNKNOWN")
            volume_ids = resource_details.get("volume_ids", [])

            commands.extend([
                {
                    "step": 1,
                    "description": "Create forensic snapshots of all volumes",
                    "command": " && ".join([
                        f'aws ec2 create-snapshot --volume-id {vol} --description "Forensic-IR-$(date +%Y%m%d)" --tag-specifications \'ResourceType=snapshot,Tags=[{{Key=IR-Case,Value=active}}]\''
                        for vol in volume_ids
                    ]) if volume_ids else f"aws ec2 describe-instance-attribute --instance-id {instance_id} --attribute blockDeviceMapping",
                },
                {
                    "step": 2,
                    "description": "Create quarantine security group",
                    "command": f"aws ec2 create-security-group --group-name quarantine-$(date +%s) --description 'IR Quarantine' --vpc-id {vpc_id}",
                },
                {
                    "step": 3,
                    "description": "Remove default egress rule from quarantine SG",
                    "command": "aws ec2 revoke-security-group-egress --group-id SG_ID --ip-permissions '[{\"IpProtocol\":\"-1\",\"FromPort\":-1,\"ToPort\":-1,\"IpRanges\":[{\"CidrIp\":\"0.0.0.0/0\"}]}]'",
                },
                {
                    "step": 4,
                    "description": "Apply quarantine SG to instance",
                    "command": f"aws ec2 modify-instance-attribute --instance-id {instance_id} --groups SG_ID",
                },
                {
                    "step": 5,
                    "description": "Tag instance as contained",
                    "command": f"aws ec2 create-tags --resources {instance_id} --tags Key=IR-Status,Value=Contained Key=IR-Date,Value=$(date +%Y%m%d)",
                },
            ])

        elif incident_type == "s3_exposure":
            bucket = resource_details.get("bucket_name", "UNKNOWN")
            commands.extend([
                {
                    "step": 1,
                    "description": "Block all public access",
                    "command": f"aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                },
                {
                    "step": 2,
                    "description": "Enable versioning for evidence",
                    "command": f"aws s3api put-bucket-versioning --bucket {bucket} --versioning-configuration Status=Enabled",
                },
                {
                    "step": 3,
                    "description": "Enable server access logging",
                    "command": f"aws s3api put-bucket-logging --bucket {bucket} --bucket-logging-status '{{\"LoggingEnabled\":{{\"TargetBucket\":\"ir-logs-bucket\",\"TargetPrefix\":\"{bucket}/\"}}}}'",
                },
            ])

        elif incident_type == "lambda_compromise":
            function_name = resource_details.get("function_name", "UNKNOWN")
            commands.extend([
                {
                    "step": 1,
                    "description": "Stop function invocations",
                    "command": f"aws lambda put-function-concurrency --function-name {function_name} --reserved-concurrent-executions 0",
                },
                {
                    "step": 2,
                    "description": "Remove event source mappings",
                    "command": f"aws lambda list-event-source-mappings --function-name {function_name}",
                },
                {
                    "step": 3,
                    "description": "Capture function configuration",
                    "command": f"aws lambda get-function --function-name {function_name} > lambda_evidence_{function_name}.json",
                },
            ])

        return commands

    def generate_azure_containment_commands(self, incident_type, resource_details):
        """Generate Azure CLI/PowerShell containment commands."""
        commands = []

        if incident_type == "identity_compromise":
            user_id = resource_details.get("user_id", "UNKNOWN")
            commands.extend([
                {
                    "step": 1,
                    "description": "Revoke all refresh tokens",
                    "command": f"az rest --method POST --url 'https://graph.microsoft.com/v1.0/users/{user_id}/revokeSignInSessions'",
                },
                {
                    "step": 2,
                    "description": "Disable user account",
                    "command": f"az ad user update --id {user_id} --account-enabled false",
                },
                {
                    "step": 3,
                    "description": "Force password reset",
                    "command": f"az ad user update --id {user_id} --force-change-password-next-sign-in true",
                },
            ])

        elif incident_type == "vm_compromise":
            vm_name = resource_details.get("vm_name", "UNKNOWN")
            rg = resource_details.get("resource_group", "UNKNOWN")
            commands.extend([
                {
                    "step": 1,
                    "description": "Create disk snapshot",
                    "command": f"az snapshot create -g {rg} -n forensic-snap-$(date +%s) --source $(az vm show -g {rg} -n {vm_name} --query 'storageProfile.osDisk.managedDisk.id' -o tsv)",
                },
                {
                    "step": 2,
                    "description": "Create quarantine NSG",
                    "command": f"az network nsg create -g {rg} -n quarantine-nsg",
                },
                {
                    "step": 3,
                    "description": "Add deny-all inbound rule",
                    "command": f"az network nsg rule create -g {rg} --nsg-name quarantine-nsg -n DenyAllInbound --priority 100 --direction Inbound --access Deny --protocol '*' --source-address-prefix '*' --destination-address-prefix '*'",
                },
                {
                    "step": 4,
                    "description": "Add deny-all outbound rule",
                    "command": f"az network nsg rule create -g {rg} --nsg-name quarantine-nsg -n DenyAllOutbound --priority 100 --direction Outbound --access Deny --protocol '*' --source-address-prefix '*' --destination-address-prefix '*'",
                },
            ])

        return commands

    def generate_containment_playbook(self, case_id, platform, incident_type, resource_details):
        """Generate complete containment playbook."""
        if platform == "aws":
            commands = self.generate_aws_containment_commands(incident_type, resource_details)
        elif platform == "azure":
            commands = self.generate_azure_containment_commands(incident_type, resource_details)
        else:
            commands = []

        playbook = {
            "case_id": case_id,
            "platform": platform,
            "incident_type": incident_type,
            "generated": datetime.now(timezone.utc).isoformat(),
            "resource_details": resource_details,
            "pre_containment_checklist": [
                "Verify incident is confirmed (not false positive)",
                "Notify incident commander",
                "Create forensic snapshots/backups BEFORE containment",
                "Document current state of affected resources",
                "Identify break-glass credentials for IR team",
            ],
            "containment_commands": commands,
            "post_containment_checklist": [
                "Verify containment is effective (test connectivity)",
                "Confirm forensic evidence is preserved",
                "Update incident ticket with containment actions",
                "Notify stakeholders of containment status",
                "Begin eradication planning",
            ],
        }

        playbook_file = self.output_dir / f"containment_playbook_{case_id}.json"
        with open(playbook_file, "w") as f:
            json.dump(playbook, f, indent=2)

        print(f"[+] Containment playbook generated: {playbook_file}")
        print(f"    Platform: {platform}")
        print(f"    Type: {incident_type}")
        print(f"    Steps: {len(commands)}")
        return playbook

    def generate_report(self):
        """Generate containment actions report."""
        report = {
            "title": "Cloud Incident Containment Report",
            "generated": datetime.now(timezone.utc).isoformat(),
            "actions_taken": self.actions_log,
            "resources_contained": self.contained_resources,
            "total_actions": len(self.actions_log),
        }

        report_file = self.output_dir / "containment_report.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)

        print(f"[+] Containment report: {report_file}")
        return report


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Cloud Incident Containment Tool")
    parser.add_argument("--platform", choices=["aws", "azure", "gcp"], required=True)
    parser.add_argument("--incident-type", choices=[
        "credential_compromise", "ec2_compromise", "s3_exposure",
        "lambda_compromise", "identity_compromise", "vm_compromise",
    ], required=True)
    parser.add_argument("--case-id", default="IR-2025-001")
    parser.add_argument("--resource-json", help="JSON file with resource details")
    parser.add_argument("-o", "--output", default="cloud_containment_results")

    args = parser.parse_args()

    resource_details = {}
    if args.resource_json:
        with open(args.resource_json) as f:
            resource_details = json.load(f)

    manager = CloudContainmentManager(output_dir=args.output)
    manager.generate_containment_playbook(
        args.case_id, args.platform, args.incident_type, resource_details
    )


if __name__ == "__main__":
    main()
