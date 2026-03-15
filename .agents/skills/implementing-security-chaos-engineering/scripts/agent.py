#!/usr/bin/env python3
"""Agent for security chaos engineering experiments."""

import os
import json
import time
import argparse
from datetime import datetime

import boto3
from botocore.exceptions import ClientError


class ChaosExperiment:
    """Base class for security chaos experiments."""

    def __init__(self, name, description, severity="MEDIUM"):
        self.name = name
        self.description = description
        self.severity = severity
        self.start_time = None
        self.end_time = None
        self.result = None

    def run(self, setup_fn, verify_fn, rollback_fn, timeout=300):
        """Execute experiment with automatic rollback."""
        self.start_time = datetime.utcnow().isoformat()
        try:
            setup_fn()
            self.result = verify_fn(timeout)
        except Exception as e:
            self.result = {"status": "ERROR", "error": str(e)}
        finally:
            rollback_fn()
            self.end_time = datetime.utcnow().isoformat()
        return self.to_dict()

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "result": self.result,
        }


def experiment_open_security_group(session, sg_id, check_interval=30, timeout=300):
    """Experiment: Open a security group and verify detection."""
    ec2 = session.client("ec2")
    config_client = session.client("config")

    def setup():
        ec2.authorize_security_group_ingress(
            GroupId=sg_id, IpProtocol="tcp", FromPort=22, ToPort=22,
            CidrIp="0.0.0.0/0",
        )
        print(f"  [!] Opened SG {sg_id} port 22 to 0.0.0.0/0")

    def verify(timeout_sec):
        elapsed = 0
        while elapsed < timeout_sec:
            time.sleep(check_interval)
            elapsed += check_interval
            results = config_client.get_compliance_details_by_config_rule(
                ConfigRuleName="restricted-ssh", ComplianceTypes=["NON_COMPLIANT"]
            )
            items = results.get("EvaluationResults", [])
            for item in items:
                resource_id = item.get("EvaluationResultIdentifier", {}).get(
                    "EvaluationResultQualifier", {}).get("ResourceId", "")
                if resource_id == sg_id:
                    return {"detected": True, "detection_time_sec": elapsed}
        return {"detected": False, "timeout": timeout_sec}

    def rollback():
        try:
            ec2.revoke_security_group_ingress(
                GroupId=sg_id, IpProtocol="tcp", FromPort=22, ToPort=22,
                CidrIp="0.0.0.0/0",
            )
            print(f"  [+] Rolled back SG {sg_id}")
        except ClientError:
            pass

    exp = ChaosExperiment("open_security_group",
                          "Verify detection of unrestricted SSH access")
    return exp.run(setup, verify, rollback, timeout)


def experiment_create_admin_user(session, username="chaos-test-admin", timeout=300):
    """Experiment: Create IAM admin user and verify detection."""
    iam = session.client("iam")
    gd = session.client("guardduty")

    def setup():
        iam.create_user(UserName=username)
        iam.attach_user_policy(
            UserName=username,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        print(f"  [!] Created admin user {username}")

    def verify(timeout_sec):
        elapsed = 0
        while elapsed < timeout_sec:
            time.sleep(30)
            elapsed += 30
            detectors = gd.list_detectors()["DetectorIds"]
            for det_id in detectors:
                findings = gd.list_findings(
                    DetectorId=det_id,
                    FindingCriteria={"Criterion": {
                        "type": {"Eq": ["Recon:IAMUser/UserPermissions"]},
                    }},
                )
                if findings.get("FindingIds"):
                    return {"detected": True, "detection_time_sec": elapsed}
        return {"detected": False, "timeout": timeout_sec}

    def rollback():
        try:
            iam.detach_user_policy(
                UserName=username,
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
            )
            iam.delete_user(UserName=username)
            print(f"  [+] Rolled back user {username}")
        except ClientError:
            pass

    exp = ChaosExperiment("create_admin_user",
                          "Verify detection of unauthorized admin user creation")
    return exp.run(setup, verify, rollback, timeout)


def experiment_stop_cloudtrail(session, trail_name, timeout=300):
    """Experiment: Stop CloudTrail and verify detection."""
    ct = session.client("cloudtrail")

    def setup():
        ct.stop_logging(Name=trail_name)
        print(f"  [!] Stopped CloudTrail {trail_name}")

    def verify(timeout_sec):
        elapsed = 0
        cw = session.client("cloudwatch")
        while elapsed < timeout_sec:
            time.sleep(30)
            elapsed += 30
            alarms = cw.describe_alarms(AlarmNamePrefix="CloudTrail")
            for alarm in alarms.get("MetricAlarms", []):
                if alarm["StateValue"] == "ALARM":
                    return {"detected": True, "detection_time_sec": elapsed,
                            "alarm": alarm["AlarmName"]}
        return {"detected": False, "timeout": timeout_sec}

    def rollback():
        try:
            ct.start_logging(Name=trail_name)
            print(f"  [+] Restarted CloudTrail {trail_name}")
        except ClientError:
            pass

    exp = ChaosExperiment("stop_cloudtrail",
                          "Verify detection of CloudTrail logging disabled")
    return exp.run(setup, verify, rollback, timeout)


def dry_run_experiments():
    """List available experiments without executing them."""
    return [
        {"name": "open_security_group", "severity": "HIGH",
         "description": "Open SG port 22 to 0.0.0.0/0, verify Config Rule alert"},
        {"name": "create_admin_user", "severity": "CRITICAL",
         "description": "Create IAM admin user, verify GuardDuty detection"},
        {"name": "stop_cloudtrail", "severity": "CRITICAL",
         "description": "Stop CloudTrail logging, verify CloudWatch alarm"},
    ]


def main():
    parser = argparse.ArgumentParser(description="Security Chaos Engineering Agent")
    parser.add_argument("--profile", default=os.getenv("AWS_PROFILE"))
    parser.add_argument("--region", default=os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
    parser.add_argument("--sg-id", help="Security Group ID for SG experiment")
    parser.add_argument("--trail-name", help="CloudTrail name for trail experiment")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--output", default="chaos_report.json")
    parser.add_argument("--action", choices=[
        "dry_run", "open_sg", "admin_user", "stop_trail", "full_suite"
    ], default="dry_run")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "experiments": []}

    if args.action == "dry_run":
        report["experiments"] = dry_run_experiments()
        print("[+] Dry run - experiments listed but not executed")
        for exp in report["experiments"]:
            print(f"    {exp['name']}: {exp['description']}")
    else:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        if args.action in ("open_sg", "full_suite") and args.sg_id:
            result = experiment_open_security_group(session, args.sg_id, timeout=args.timeout)
            report["experiments"].append(result)

        if args.action in ("admin_user", "full_suite"):
            result = experiment_create_admin_user(session, timeout=args.timeout)
            report["experiments"].append(result)

        if args.action in ("stop_trail", "full_suite") and args.trail_name:
            result = experiment_stop_cloudtrail(session, args.trail_name, timeout=args.timeout)
            report["experiments"].append(result)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
