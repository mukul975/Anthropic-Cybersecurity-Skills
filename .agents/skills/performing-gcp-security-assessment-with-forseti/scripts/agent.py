#!/usr/bin/env python3
"""Agent for performing GCP security assessment.

Audits IAM policies, firewall rules, storage permissions, and
Security Command Center findings using Google Cloud client libraries.
"""

import json
import sys
from collections import defaultdict

from google.cloud import securitycenter_v1
from google.cloud import asset_v1
from google.cloud import storage
from google.cloud import compute_v1


class GCPSecurityAssessmentAgent:
    """Performs security assessments on GCP organizations and projects."""

    def __init__(self, organization_id, project_id=None):
        self.org_id = organization_id
        self.project_id = project_id
        self.scc_client = securitycenter_v1.SecurityCenterClient()
        self.asset_client = asset_v1.AssetServiceClient()

    def list_scc_findings(self, severity="CRITICAL"):
        """List active Security Command Center findings by severity."""
        parent = f"organizations/{self.org_id}/sources/-"
        findings = []
        request = securitycenter_v1.ListFindingsRequest(
            parent=parent,
            filter=f'state="ACTIVE" AND severity="{severity}"',
        )
        for finding_result in self.scc_client.list_findings(request=request):
            f = finding_result.finding
            findings.append({
                "category": f.category,
                "severity": securitycenter_v1.Finding.Severity(f.severity).name,
                "resource": f.resource_name,
                "event_time": f.event_time.isoformat() if f.event_time else None,
                "description": f.description[:200] if f.description else "",
            })
        return findings

    def audit_iam_policies(self):
        """Search for overly permissive IAM bindings across the organization."""
        scope = f"organizations/{self.org_id}"
        findings = {"owner_bindings": [], "public_access": [], "sa_admin": []}

        for query, category in [
            ("policy:roles/owner OR policy:roles/editor", "owner_bindings"),
            ("policy:allUsers OR policy:allAuthenticatedUsers", "public_access"),
        ]:
            request = asset_v1.SearchAllIamPoliciesRequest(scope=scope, query=query)
            for result in self.asset_client.search_all_iam_policies(request=request):
                for binding in result.policy.bindings:
                    findings[category].append({
                        "resource": result.resource,
                        "role": binding.role,
                        "members": list(binding.members),
                    })
        return findings

    def audit_firewall_rules(self):
        """Audit VPC firewall rules for overly permissive ingress."""
        if not self.project_id:
            return {"error": "project_id required for firewall audit"}

        client = compute_v1.FirewallsClient()
        risky_rules = []

        for rule in client.list(project=self.project_id):
            if rule.direction != "INGRESS":
                continue
            source_ranges = list(rule.source_ranges) if rule.source_ranges else []
            if "0.0.0.0/0" not in source_ranges:
                continue
            allowed_ports = []
            for allowed in rule.allowed:
                ports = list(allowed.ports) if allowed.ports else ["all"]
                allowed_ports.append({
                    "protocol": allowed.I_p_protocol,
                    "ports": ports,
                })
            risky_rules.append({
                "name": rule.name,
                "network": rule.network,
                "source_ranges": source_ranges,
                "allowed": allowed_ports,
                "priority": rule.priority,
                "disabled": rule.disabled,
            })
        return risky_rules

    def audit_storage_buckets(self):
        """Check storage buckets for public access and encryption settings."""
        if not self.project_id:
            return {"error": "project_id required for storage audit"}

        client = storage.Client(project=self.project_id)
        bucket_findings = []

        for bucket in client.list_buckets():
            policy = bucket.get_iam_policy()
            is_public = False
            public_roles = []
            for binding in policy.bindings:
                members = set(binding.get("members", []))
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    is_public = True
                    public_roles.append(binding["role"])

            bucket_findings.append({
                "name": bucket.name,
                "location": bucket.location,
                "storage_class": bucket.storage_class,
                "is_public": is_public,
                "public_roles": public_roles,
                "uniform_access": bucket.iam_configuration.get(
                    "uniformBucketLevelAccess", {}
                ).get("enabled", False),
                "versioning": bucket.versioning_enabled,
            })
        return bucket_findings

    def get_finding_summary(self):
        """Get summary counts of SCC findings grouped by severity."""
        parent = f"organizations/{self.org_id}/sources/-"
        summary = defaultdict(int)

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            request = securitycenter_v1.ListFindingsRequest(
                parent=parent,
                filter=f'state="ACTIVE" AND severity="{severity}"',
            )
            count = 0
            for _ in self.scc_client.list_findings(request=request):
                count += 1
            summary[severity] = count
        return dict(summary)

    def generate_assessment_report(self):
        """Generate a comprehensive GCP security assessment report."""
        report = {
            "organization_id": self.org_id,
            "project_id": self.project_id,
        }

        report["scc_findings_summary"] = self.get_finding_summary()
        report["critical_findings"] = self.list_scc_findings("CRITICAL")
        report["iam_audit"] = self.audit_iam_policies()

        if self.project_id:
            report["firewall_audit"] = self.audit_firewall_rules()
            report["storage_audit"] = self.audit_storage_buckets()

        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <org_id> [project_id] [action]")
        print("Actions: report, findings, iam, firewall, storage")
        sys.exit(1)

    org_id = sys.argv[1]
    project_id = sys.argv[2] if len(sys.argv) > 2 else None
    action = sys.argv[3] if len(sys.argv) > 3 else "report"

    agent = GCPSecurityAssessmentAgent(org_id, project_id)

    if action == "report":
        agent.generate_assessment_report()
    elif action == "findings":
        findings = agent.list_scc_findings()
        print(json.dumps(findings, indent=2, default=str))
    elif action == "iam":
        iam = agent.audit_iam_policies()
        print(json.dumps(iam, indent=2))
    elif action == "firewall":
        fw = agent.audit_firewall_rules()
        print(json.dumps(fw, indent=2))
    elif action == "storage":
        buckets = agent.audit_storage_buckets()
        print(json.dumps(buckets, indent=2))


if __name__ == "__main__":
    main()
