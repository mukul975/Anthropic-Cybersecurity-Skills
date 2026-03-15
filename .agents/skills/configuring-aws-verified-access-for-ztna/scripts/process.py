#!/usr/bin/env python3
"""
AWS Verified Access ZTNA Configuration and Policy Management.

Generates Cedar access policies, validates configurations,
and monitors Verified Access deployments.
"""

import json
import datetime
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TrustProvider:
    name: str
    provider_type: str  # "user" or "device"
    reference_name: str
    config: dict = field(default_factory=dict)


@dataclass
class AccessGroup:
    name: str
    description: str
    policy: str
    endpoints: list = field(default_factory=list)


@dataclass
class AccessEndpoint:
    name: str
    application_domain: str
    endpoint_type: str  # "load-balancer" or "network-interface"
    port: int = 443
    policy: str = ""
    alb_arn: str = ""


class CedarPolicyGenerator:
    """Generate Cedar access policies for AWS Verified Access."""

    def __init__(self, identity_ref: str = "okta", device_ref: str = "crowdstrike"):
        self.identity_ref = identity_ref
        self.device_ref = device_ref

    def permit_group_with_device_trust(self, group: str, min_score: int = 50) -> str:
        return f'''permit(principal, action, resource)
when {{
    context.{self.identity_ref}.groups.contains("{group}") &&
    context.{self.device_ref}.assessment.overall > {min_score}
}};'''

    def permit_group_read_only(self, group: str, min_score: int = 30) -> str:
        return f'''permit(principal, action, resource)
when {{
    context.{self.identity_ref}.groups.contains("{group}") &&
    context.{self.device_ref}.assessment.overall > {min_score} &&
    context.http_request.http_method == "GET"
}};'''

    def forbid_unmanaged_devices(self) -> str:
        return f'''forbid(principal, action, resource)
when {{
    !context.{self.device_ref}.assessment.sensor_config.status == "active"
}};'''

    def permit_admin_high_trust(self, admin_group: str, min_score: int = 90) -> str:
        return f'''permit(principal, action, resource)
when {{
    context.{self.identity_ref}.groups.contains("{admin_group}") &&
    context.{self.device_ref}.assessment.overall > {min_score} &&
    context.{self.identity_ref}.email.endsWith("@company.com")
}};'''

    def combine_policies(self, policies: list) -> str:
        return "\n\n".join(policies)


class VerifiedAccessConfigGenerator:
    """Generate Terraform configuration for AWS Verified Access."""

    def __init__(self):
        self.trust_providers: list[TrustProvider] = []
        self.groups: list[AccessGroup] = []
        self.endpoints: list[AccessEndpoint] = []

    def add_trust_provider(self, name: str, provider_type: str,
                           reference_name: str, config: dict = None):
        self.trust_providers.append(TrustProvider(
            name=name, provider_type=provider_type,
            reference_name=reference_name, config=config or {}
        ))

    def add_group(self, name: str, description: str, policy: str):
        self.groups.append(AccessGroup(name=name, description=description, policy=policy))

    def add_endpoint(self, group_name: str, name: str, domain: str,
                     port: int = 443, policy: str = "", alb_arn: str = ""):
        endpoint = AccessEndpoint(
            name=name, application_domain=domain,
            endpoint_type="load-balancer", port=port,
            policy=policy, alb_arn=alb_arn
        )
        for group in self.groups:
            if group.name == group_name:
                group.endpoints.append(endpoint)
        self.endpoints.append(endpoint)

    def generate_terraform(self) -> str:
        sections = [self._provider_block()]

        sections.append('\n# Verified Access Instance')
        sections.append('''resource "aws_verifiedaccess_instance" "main" {
  description = "Production Zero Trust Access"
  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}''')

        for tp in self.trust_providers:
            sections.append(self._trust_provider_block(tp))

        for group in self.groups:
            sections.append(self._group_block(group))

        for endpoint in self.endpoints:
            sections.append(self._endpoint_block(endpoint))

        return "\n\n".join(sections)

    def _provider_block(self) -> str:
        return '''terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}'''

    def _trust_provider_block(self, tp: TrustProvider) -> str:
        resource_name = tp.name.replace("-", "_")
        return f'''resource "aws_verifiedaccess_trust_provider" "{resource_name}" {{
  policy_reference_name = "{tp.reference_name}"
  trust_provider_type   = "{tp.provider_type}"
  description           = "{tp.name} trust provider"
}}

resource "aws_verifiedaccess_instance_trust_provider_attachment" "{resource_name}" {{
  verifiedaccess_instance_id       = aws_verifiedaccess_instance.main.id
  verifiedaccess_trust_provider_id = aws_verifiedaccess_trust_provider.{resource_name}.id
}}'''

    def _group_block(self, group: AccessGroup) -> str:
        resource_name = group.name.replace("-", "_")
        return f'''resource "aws_verifiedaccess_group" "{resource_name}" {{
  verifiedaccess_instance_id = aws_verifiedaccess_instance.main.id
  description                = "{group.description}"

  policy_document = <<-CEDAR
    {group.policy}
  CEDAR
}}'''

    def _endpoint_block(self, endpoint: AccessEndpoint) -> str:
        resource_name = endpoint.name.replace("-", "_").replace(".", "_")
        policy_block = ""
        if endpoint.policy:
            policy_block = f'''

  policy_document = <<-CEDAR
    {endpoint.policy}
  CEDAR'''

        return f'''resource "aws_verifiedaccess_endpoint" "{resource_name}" {{
  verified_access_group_id = aws_verifiedaccess_group.web_apps.id
  endpoint_type            = "load-balancer"
  attachment_type          = "vpc"
  application_domain       = "{endpoint.application_domain}"
  description              = "{endpoint.name}"{policy_block}
}}'''

    def export_terraform(self, output_path: str):
        config = self.generate_terraform()
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.write(config)
        return config


def main():
    """Generate example AWS Verified Access configuration."""
    # Generate Cedar policies
    cedar = CedarPolicyGenerator(identity_ref="okta", device_ref="crowdstrike")

    group_policy = cedar.combine_policies([
        cedar.permit_group_with_device_trust("production-access", 50),
        cedar.forbid_unmanaged_devices(),
    ])

    admin_policy = cedar.permit_admin_high_trust("platform-admins", 90)
    readonly_policy = cedar.permit_group_read_only("read-only-users", 30)

    print("Generated Cedar Policies:")
    print("=" * 60)
    print("\nGroup Policy (production access):")
    print(group_policy)
    print(f"\nAdmin Policy:")
    print(admin_policy)
    print(f"\nRead-Only Policy:")
    print(readonly_policy)

    # Generate Terraform config
    gen = VerifiedAccessConfigGenerator()
    gen.add_trust_provider("okta-identity", "user", "okta")
    gen.add_trust_provider("crowdstrike-device", "device", "crowdstrike")
    gen.add_group("web-apps", "Production Web Applications", group_policy)
    gen.add_endpoint("web-apps", "internal-app", "app.internal.company.com", 443)
    gen.add_endpoint("web-apps", "admin-portal", "admin.internal.company.com", 443,
                     policy=admin_policy)

    config = gen.export_terraform("verified_access.tf")
    print("\n" + "=" * 60)
    print("Generated Terraform Configuration:")
    print("=" * 60)
    print(config[:3000])


if __name__ == "__main__":
    main()
