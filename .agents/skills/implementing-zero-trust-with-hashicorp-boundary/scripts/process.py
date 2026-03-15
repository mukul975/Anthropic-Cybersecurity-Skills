#!/usr/bin/env python3
"""
HashiCorp Boundary Zero Trust Access Management.

Generates Boundary Terraform configurations, validates access policies,
and monitors session activity for compliance reporting.
"""

import json
import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class BoundaryScope:
    name: str
    description: str
    scope_type: str  # "org" or "project"
    parent_scope_id: str = "global"


@dataclass
class BoundaryTarget:
    name: str
    description: str
    target_type: str  # "ssh" or "tcp"
    default_port: int
    host_addresses: list = field(default_factory=list)
    session_max_seconds: int = 3600
    session_connection_limit: int = -1
    enable_recording: bool = False
    credential_type: str = "none"  # "none", "brokered", "injected"
    vault_path: str = ""


@dataclass
class BoundaryRole:
    name: str
    description: str
    scope_id: str
    grant_strings: list = field(default_factory=list)
    principal_groups: list = field(default_factory=list)


class BoundaryTerraformGenerator:
    """Generate Terraform configuration for Boundary resources."""

    def __init__(self, boundary_addr: str, vault_addr: str = ""):
        self.boundary_addr = boundary_addr
        self.vault_addr = vault_addr
        self.scopes: list[BoundaryScope] = []
        self.targets: list[BoundaryTarget] = []
        self.roles: list[BoundaryRole] = []
        self.oidc_config: dict = {}

    def add_scope(self, name: str, description: str, scope_type: str = "project",
                  parent: str = "global") -> BoundaryScope:
        scope = BoundaryScope(name=name, description=description,
                              scope_type=scope_type, parent_scope_id=parent)
        self.scopes.append(scope)
        return scope

    def add_target(self, name: str, description: str, target_type: str,
                   port: int, hosts: list, **kwargs) -> BoundaryTarget:
        target = BoundaryTarget(
            name=name, description=description, target_type=target_type,
            default_port=port, host_addresses=hosts, **kwargs
        )
        self.targets.append(target)
        return target

    def add_role(self, name: str, description: str, scope_id: str,
                 grants: list, groups: list) -> BoundaryRole:
        role = BoundaryRole(
            name=name, description=description, scope_id=scope_id,
            grant_strings=grants, principal_groups=groups
        )
        self.roles.append(role)
        return role

    def configure_oidc(self, issuer: str, client_id: str, scopes: list = None):
        self.oidc_config = {
            "issuer": issuer,
            "client_id": client_id,
            "scopes": scopes or ["openid", "profile", "groups"],
        }

    def generate_provider_block(self) -> str:
        return f'''terraform {{
  required_providers {{
    boundary = {{
      source  = "hashicorp/boundary"
      version = "~> 1.1"
    }}
  }}
}}

provider "boundary" {{
  addr             = "{self.boundary_addr}"
  recovery_kms_hcl = file("recovery_kms.hcl")
}}
'''

    def generate_scopes(self) -> str:
        blocks = []
        for scope in self.scopes:
            resource_name = scope.name.replace("-", "_")
            if scope.scope_type == "org":
                blocks.append(f'''
resource "boundary_scope" "{resource_name}" {{
  scope_id                 = "{scope.parent_scope_id}"
  name                     = "{scope.name}"
  description              = "{scope.description}"
  auto_create_admin_role   = true
  auto_create_default_role = true
}}
''')
            else:
                parent_ref = scope.parent_scope_id.replace("-", "_")
                blocks.append(f'''
resource "boundary_scope" "{resource_name}" {{
  name                     = "{scope.name}"
  description              = "{scope.description}"
  scope_id                 = boundary_scope.{parent_ref}.id
  auto_create_admin_role   = true
  auto_create_default_role = true
}}
''')
        return "\n".join(blocks)

    def generate_targets(self) -> str:
        blocks = []
        for target in self.targets:
            resource_name = target.name.replace("-", "_")
            recording_block = ""
            if target.enable_recording:
                recording_block = """
  enable_session_recording = true
  storage_bucket_id        = boundary_storage_bucket.sessions.id"""

            credential_block = ""
            if target.credential_type == "brokered" and target.vault_path:
                credential_block = f"""
  brokered_credential_source_ids = [
    boundary_credential_library_vault.{resource_name}_creds.id
  ]"""
            elif target.credential_type == "injected" and target.vault_path:
                credential_block = f"""
  injected_application_credential_source_ids = [
    boundary_credential_library_vault_ssh_certificate.{resource_name}_cert.id
  ]"""

            blocks.append(f'''
resource "boundary_target" "{resource_name}" {{
  name         = "{target.name}"
  description  = "{target.description}"
  type         = "{target.target_type}"
  scope_id     = boundary_scope.production.id
  default_port = {target.default_port}

  session_max_seconds      = {target.session_max_seconds}
  session_connection_limit = {target.session_connection_limit}{recording_block}{credential_block}
}}
''')
        return "\n".join(blocks)

    def generate_roles(self) -> str:
        blocks = []
        for role in self.roles:
            resource_name = role.name.replace("-", "_")
            grants = ",\n    ".join(f'"{g}"' for g in role.grant_strings)
            principals = ",\n    ".join(
                f'boundary_managed_group.{g.replace("-", "_")}.id'
                for g in role.principal_groups
            )
            blocks.append(f'''
resource "boundary_role" "{resource_name}" {{
  name          = "{role.name}"
  description   = "{role.description}"
  scope_id      = {role.scope_id}
  grant_strings = [
    {grants}
  ]
  principal_ids = [
    {principals}
  ]
}}
''')
        return "\n".join(blocks)

    def generate_full_config(self) -> str:
        sections = [
            self.generate_provider_block(),
            "# Scopes",
            self.generate_scopes(),
            "# Targets",
            self.generate_targets(),
            "# Roles",
            self.generate_roles(),
        ]
        return "\n".join(sections)

    def export_config(self, output_path: str):
        config = self.generate_full_config()
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.write(config)
        return config


class BoundaryAccessAuditor:
    """Audit and validate Boundary access configurations."""

    def __init__(self):
        self.findings: list[dict] = []

    def check_session_limits(self, targets: list[BoundaryTarget]) -> list[dict]:
        for target in targets:
            if target.session_max_seconds > 7200:
                self.findings.append({
                    "severity": "WARNING",
                    "target": target.name,
                    "finding": f"Session max exceeds 2 hours ({target.session_max_seconds}s)",
                    "recommendation": "Reduce session duration for privileged targets",
                })
            if target.session_connection_limit == -1:
                self.findings.append({
                    "severity": "INFO",
                    "target": target.name,
                    "finding": "Unlimited connections per session",
                    "recommendation": "Consider setting connection limits for sensitive targets",
                })
            if target.default_port == 22 and not target.enable_recording:
                self.findings.append({
                    "severity": "HIGH",
                    "target": target.name,
                    "finding": "SSH target without session recording",
                    "recommendation": "Enable session recording for SSH access",
                })
            if target.credential_type == "none":
                self.findings.append({
                    "severity": "MEDIUM",
                    "target": target.name,
                    "finding": "No credential management configured",
                    "recommendation": "Use Vault credential brokering or injection",
                })
        return self.findings

    def check_role_grants(self, roles: list[BoundaryRole]) -> list[dict]:
        for role in roles:
            for grant in role.grant_strings:
                if "ids=*" in grant and "actions=*" in grant:
                    self.findings.append({
                        "severity": "CRITICAL",
                        "role": role.name,
                        "finding": "Wildcard IDs and actions grant (admin-level access)",
                        "recommendation": "Restrict to specific resource types and actions",
                    })
                if "type=target" in grant and "authorize-session" in grant and "ids=*" in grant:
                    self.findings.append({
                        "severity": "HIGH",
                        "role": role.name,
                        "finding": "Role can authorize sessions to all targets",
                        "recommendation": "Restrict to specific target IDs or use target-level grants",
                    })
        return self.findings

    def generate_report(self) -> dict:
        report = {
            "audit_date": datetime.datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "by_severity": {},
            "findings": self.findings,
        }
        for finding in self.findings:
            sev = finding["severity"]
            report["by_severity"][sev] = report["by_severity"].get(sev, 0) + 1
        return report


def main():
    """Generate example Boundary Terraform configuration."""
    gen = BoundaryTerraformGenerator(
        boundary_addr="https://boundary.example.com:9200",
        vault_addr="https://vault.example.com:8200"
    )

    # Create scopes
    gen.add_scope("production-org", "Production Organization", "org")
    gen.add_scope("production", "Production Infrastructure", "project", "production-org")

    # Create targets
    gen.add_target(
        "ssh-web-servers", "SSH to production web servers", "ssh", 22,
        ["10.0.1.10", "10.0.1.11"],
        session_max_seconds=3600, enable_recording=True,
        credential_type="injected", vault_path="ssh-signer/sign/web"
    )
    gen.add_target(
        "postgres-production", "Production PostgreSQL", "tcp", 5432,
        ["10.0.2.20"],
        session_max_seconds=1800,
        credential_type="brokered", vault_path="database/creds/readonly"
    )
    gen.add_target(
        "redis-cache", "Production Redis cache", "tcp", 6379,
        ["10.0.3.30"],
        session_max_seconds=900
    )

    # Create roles
    gen.add_role(
        "sre-full-access", "SRE team full production access",
        "boundary_scope.production.id",
        [
            "ids=*;type=target;actions=list,read,authorize-session",
            "ids=*;type=session;actions=list,read,cancel",
        ],
        ["sre-team"]
    )
    gen.add_role(
        "dev-readonly", "Dev team read-only access",
        "boundary_scope.production.id",
        [
            "ids=*;type=target;actions=list,read",
        ],
        ["dev-team"]
    )

    # Generate and export
    config = gen.export_config("boundary_config.tf")
    print("Generated Terraform configuration:")
    print(config[:2000])

    # Run audit
    auditor = BoundaryAccessAuditor()
    auditor.check_session_limits(gen.targets)
    auditor.check_role_grants(gen.roles)
    report = auditor.generate_report()

    print("\n" + "=" * 60)
    print("Access Audit Report")
    print("=" * 60)
    print(f"Total findings: {report['total_findings']}")
    for sev, count in report["by_severity"].items():
        print(f"  {sev}: {count}")
    for finding in report["findings"]:
        target_or_role = finding.get("target", finding.get("role", "N/A"))
        print(f"\n  [{finding['severity']}] {target_or_role}")
        print(f"    Finding: {finding['finding']}")
        print(f"    Recommendation: {finding['recommendation']}")


if __name__ == "__main__":
    main()
