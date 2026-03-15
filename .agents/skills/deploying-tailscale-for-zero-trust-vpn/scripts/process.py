#!/usr/bin/env python3
"""
Tailscale Zero Trust VPN Management and Monitoring.

Manages Tailscale deployment, ACL generation, network health monitoring,
and compliance reporting for zero trust mesh VPN infrastructure.
"""

import json
import subprocess
import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class TailscaleNode:
    hostname: str
    ip4: str
    ip6: str = ""
    os: str = ""
    online: bool = False
    tags: list = field(default_factory=list)
    key_expiry: str = ""
    last_seen: str = ""
    exit_node: bool = False
    subnet_routes: list = field(default_factory=list)


@dataclass
class ACLRule:
    action: str  # "accept" or "deny"
    src: list
    dst: list
    description: str = ""


@dataclass
class ACLGroup:
    name: str
    members: list


class TailscaleACLGenerator:
    """Generate and validate Tailscale ACL configurations."""

    def __init__(self):
        self.groups: dict[str, list] = {}
        self.tag_owners: dict[str, list] = {}
        self.acls: list[dict] = []
        self.ssh_rules: list[dict] = []
        self.auto_approvers: dict = {"routes": {}, "exitNode": []}
        self.node_attrs: list[dict] = []

    def add_group(self, name: str, members: list):
        if not name.startswith("group:"):
            name = f"group:{name}"
        self.groups[name] = members

    def add_tag(self, tag: str, owners: list):
        if not tag.startswith("tag:"):
            tag = f"tag:{tag}"
        self.tag_owners[tag] = owners

    def add_acl_rule(self, src: list, dst: list, action: str = "accept"):
        self.acls.append({"action": action, "src": src, "dst": dst})

    def add_ssh_rule(self, src: list, dst: list, users: list, action: str = "check"):
        self.ssh_rules.append({
            "action": action,
            "src": src,
            "dst": dst,
            "users": users,
        })

    def add_auto_approver_route(self, cidr: str, approvers: list):
        self.auto_approvers["routes"][cidr] = approvers

    def add_auto_approver_exit_node(self, approvers: list):
        self.auto_approvers["exitNode"] = approvers

    def generate_policy(self) -> dict:
        policy = {}
        if self.groups:
            policy["groups"] = self.groups
        if self.tag_owners:
            policy["tagOwners"] = self.tag_owners
        if self.acls:
            policy["acls"] = self.acls
        if self.ssh_rules:
            policy["ssh"] = self.ssh_rules
        if self.auto_approvers["routes"] or self.auto_approvers["exitNode"]:
            policy["autoApprovers"] = self.auto_approvers
        if self.node_attrs:
            policy["nodeAttrs"] = self.node_attrs
        return policy

    def export_policy(self, output_path: str):
        policy = self.generate_policy()
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(policy, f, indent=2)
        return policy

    def validate_policy(self) -> list:
        """Validate ACL policy for common issues."""
        issues = []
        policy = self.generate_policy()

        # Check for empty ACLs
        if not policy.get("acls"):
            issues.append("WARNING: No ACL rules defined - all traffic will be denied")

        # Check for overly permissive rules
        for i, rule in enumerate(self.acls):
            if "*" in rule.get("src", []) and "*" in rule.get("dst", []):
                issues.append(f"CRITICAL: Rule {i} allows all-to-all access")
            for dst in rule.get("dst", []):
                if dst.endswith(":*"):
                    issues.append(f"WARNING: Rule {i} allows all ports to {dst}")

        # Check groups reference valid members
        for group_name, members in self.groups.items():
            if not members:
                issues.append(f"WARNING: Group {group_name} has no members")

        # Check tag owners exist
        for tag, owners in self.tag_owners.items():
            for owner in owners:
                if owner.startswith("group:") and owner not in self.groups:
                    issues.append(f"ERROR: Tag {tag} references undefined group {owner}")

        # Check SSH rules
        for i, rule in enumerate(self.ssh_rules):
            if "root" in rule.get("users", []) and rule.get("action") != "check":
                issues.append(f"WARNING: SSH rule {i} allows root access without re-auth check")

        return issues


class TailscaleMonitor:
    """Monitor Tailscale network health and compliance."""

    def __init__(self):
        self.nodes: list[TailscaleNode] = []

    def get_status(self) -> dict:
        """Get current Tailscale status via CLI."""
        try:
            result = subprocess.run(
                ["tailscale", "status", "--json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass
        return {}

    def parse_nodes(self, status: dict) -> list[TailscaleNode]:
        """Parse Tailscale status into node objects."""
        self.nodes = []
        peers = status.get("Peer", {})
        for peer_id, peer_data in peers.items():
            node = TailscaleNode(
                hostname=peer_data.get("HostName", "unknown"),
                ip4=peer_data.get("TailscaleIPs", [""])[0] if peer_data.get("TailscaleIPs") else "",
                ip6=peer_data.get("TailscaleIPs", ["", ""])[1] if len(peer_data.get("TailscaleIPs", [])) > 1 else "",
                os=peer_data.get("OS", ""),
                online=peer_data.get("Online", False),
                tags=peer_data.get("Tags", []),
                key_expiry=peer_data.get("KeyExpiry", ""),
                last_seen=peer_data.get("LastSeen", ""),
                exit_node=peer_data.get("ExitNode", False),
            )
            self.nodes.append(node)
        return self.nodes

    def check_health(self) -> dict:
        """Run health checks on the tailnet."""
        report = {
            "timestamp": datetime.datetime.now().isoformat(),
            "total_nodes": len(self.nodes),
            "online_nodes": sum(1 for n in self.nodes if n.online),
            "offline_nodes": sum(1 for n in self.nodes if not n.online),
            "expiring_keys": [],
            "untagged_nodes": [],
            "exit_nodes": [],
            "issues": [],
        }

        for node in self.nodes:
            # Check for expiring keys
            if node.key_expiry:
                try:
                    expiry = datetime.datetime.fromisoformat(node.key_expiry.replace("Z", "+00:00"))
                    days_until = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
                    if days_until < 30:
                        report["expiring_keys"].append({
                            "hostname": node.hostname,
                            "expires_in_days": days_until,
                        })
                except (ValueError, TypeError):
                    pass

            # Check for untagged nodes
            if not node.tags:
                report["untagged_nodes"].append(node.hostname)

            # Track exit nodes
            if node.exit_node:
                report["exit_nodes"].append(node.hostname)

        # Generate issues
        if report["offline_nodes"] > 0:
            report["issues"].append(
                f"{report['offline_nodes']} nodes offline"
            )
        if report["expiring_keys"]:
            report["issues"].append(
                f"{len(report['expiring_keys'])} nodes with keys expiring within 30 days"
            )
        if report["untagged_nodes"]:
            report["issues"].append(
                f"{len(report['untagged_nodes'])} nodes without tags (ungoverned by ACLs)"
            )

        return report

    def generate_compliance_report(self) -> dict:
        """Generate zero trust compliance report for the tailnet."""
        report = {
            "report_date": datetime.datetime.now().isoformat(),
            "zero_trust_checks": {
                "encryption": {
                    "status": "PASS",
                    "detail": "All connections use WireGuard end-to-end encryption",
                },
                "identity_based_access": {
                    "status": "PASS" if all(n.tags for n in self.nodes) else "FAIL",
                    "detail": "All nodes should have identity tags for ACL enforcement",
                },
                "least_privilege": {
                    "status": "REVIEW",
                    "detail": "ACL policy review required - validate minimum necessary access",
                },
                "continuous_verification": {
                    "status": "PASS" if not any(
                        n.key_expiry == "" for n in self.nodes
                    ) else "WARNING",
                    "detail": "Key expiry should be enabled for all non-server nodes",
                },
                "device_trust": {
                    "status": "REVIEW",
                    "detail": "Verify device authorization and Network Lock status",
                },
            },
        }
        return report


def generate_example_policy():
    """Generate an example zero trust ACL policy for Tailscale."""
    gen = TailscaleACLGenerator()

    # Define groups
    gen.add_group("engineering", ["eng1@company.com", "eng2@company.com"])
    gen.add_group("sre", ["sre1@company.com", "sre2@company.com"])
    gen.add_group("security", ["sec1@company.com"])
    gen.add_group("management", ["mgr1@company.com"])

    # Define tags
    gen.add_tag("production", ["group:sre"])
    gen.add_tag("staging", ["group:engineering", "group:sre"])
    gen.add_tag("development", ["group:engineering"])
    gen.add_tag("database", ["group:sre"])
    gen.add_tag("monitoring", ["group:sre", "group:security"])
    gen.add_tag("ci-runner", ["group:sre"])

    # ACL rules - zero trust, least privilege
    gen.add_acl_rule(
        src=["group:engineering"],
        dst=["tag:development:*", "tag:staging:443,8080"]
    )
    gen.add_acl_rule(
        src=["group:sre"],
        dst=["tag:production:22,443,8080", "tag:staging:*", "tag:database:5432,3306"]
    )
    gen.add_acl_rule(
        src=["group:security"],
        dst=["tag:monitoring:443,9090", "tag:production:443"]
    )
    gen.add_acl_rule(
        src=["tag:ci-runner"],
        dst=["tag:staging:443,8080", "tag:production:443"]
    )

    # SSH rules with re-authentication
    gen.add_ssh_rule(
        src=["group:sre"],
        dst=["tag:production"],
        users=["admin"],
        action="check"  # Requires re-auth, records session
    )
    gen.add_ssh_rule(
        src=["group:engineering"],
        dst=["tag:development"],
        users=["autogroup:nonroot"],
        action="accept"
    )

    # Auto-approvers for subnet routes
    gen.add_auto_approver_route("10.0.0.0/16", ["group:sre"])
    gen.add_auto_approver_exit_node(["group:sre"])

    # Validate
    issues = gen.validate_policy()
    if issues:
        print("Policy Validation Issues:")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("Policy validation: PASSED")

    # Export
    policy = gen.export_policy("tailscale_acl_policy.json")
    print(f"\nGenerated ACL policy with:")
    print(f"  Groups: {len(gen.groups)}")
    print(f"  Tags: {len(gen.tag_owners)}")
    print(f"  ACL Rules: {len(gen.acls)}")
    print(f"  SSH Rules: {len(gen.ssh_rules)}")
    print(f"\nPolicy saved to: tailscale_acl_policy.json")
    print(f"\nPolicy preview:")
    print(json.dumps(policy, indent=2))


if __name__ == "__main__":
    generate_example_policy()
