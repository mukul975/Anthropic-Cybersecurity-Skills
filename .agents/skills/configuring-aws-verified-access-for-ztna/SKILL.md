---
name: configuring-aws-verified-access-for-ztna
description: Configure AWS Verified Access to provide VPN-less zero trust network access to internal applications using identity and device posture verification with Cedar policy language.
domain: cybersecurity
subdomain: zero-trust-architecture
tags: [zero-trust, aws, verified-access, ztna, cedar-policy, vpn-less, identity-verification, device-posture, aws-ram]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Configuring AWS Verified Access for ZTNA

## Overview

AWS Verified Access is a Zero Trust Network Access (ZTNA) service that provides secure, VPN-less access to corporate applications hosted in AWS. It evaluates each access request in real-time against granular conditional access policies written in the Cedar policy language, ensuring access is granted per-application only when specific security requirements such as user identity and device security posture are met and maintained. Verified Access integrates with AWS IAM Identity Center, third-party identity providers (Okta, CrowdStrike, JumpCloud, Jamf), and device management solutions. For multi-account deployments, AWS Resource Access Manager (RAM) enables sharing Verified Access groups across organizational units.

## Prerequisites

- AWS account with appropriate IAM permissions
- Identity provider (AWS IAM Identity Center, Okta, or OIDC-compatible)
- Device trust provider (CrowdStrike, Jamf, JumpCloud, or AWS Verified Access native)
- Internal Application Load Balancer (ALB) or network interface endpoint
- Understanding of Cedar policy language
- VPC with application workloads to protect

## Architecture

```
    End User (Browser)
         |
         | HTTPS
         v
  +------+--------+
  | Verified      |
  | Access        |
  | Endpoint      |
  | (Public DNS)  |
  +------+--------+
         |
  +------+--------+
  | Verified      |  <-- Cedar Access Policies
  | Access        |  <-- Identity Provider Signals
  | Instance      |  <-- Device Trust Signals
  | (Policy       |
  |  Evaluation)  |
  +------+--------+
         |
  +------+--------+
  | Verified      |
  | Access Group  |
  | (App Group)   |
  +------+--------+
         |
  +------+--------+
  | Internal ALB  |
  | or ENI Target |
  +------+--------+
         |
  +------+--------+
  | Application   |
  | (Private VPC) |
  +--------------+
```

## Core Components

### Verified Access Instance

The regional entity that evaluates access requests against policies.

```bash
# Create Verified Access Instance via AWS CLI
aws ec2 create-verified-access-instance \
  --description "Production Zero Trust Instance" \
  --tag-specifications 'ResourceType=verified-access-instance,Tags=[{Key=Environment,Value=production}]'
```

### Trust Providers

#### Identity Trust Provider (AWS IAM Identity Center)

```bash
# Create identity trust provider
aws ec2 create-verified-access-trust-provider \
  --trust-provider-type user \
  --user-trust-provider-type iam-identity-center \
  --policy-reference-name "idc" \
  --description "IAM Identity Center trust provider" \
  --tag-specifications 'ResourceType=verified-access-trust-provider,Tags=[{Key=Type,Value=identity}]'
```

#### Identity Trust Provider (OIDC - Okta)

```bash
aws ec2 create-verified-access-trust-provider \
  --trust-provider-type user \
  --user-trust-provider-type oidc \
  --oidc-options '{
    "Issuer": "https://company.okta.com/oauth2/default",
    "AuthorizationEndpoint": "https://company.okta.com/oauth2/default/v1/authorize",
    "TokenEndpoint": "https://company.okta.com/oauth2/default/v1/token",
    "UserInfoEndpoint": "https://company.okta.com/oauth2/default/v1/userinfo",
    "ClientId": "0oa1234567890",
    "ClientSecret": "client-secret-here",
    "Scope": "openid profile groups"
  }' \
  --policy-reference-name "okta" \
  --description "Okta OIDC trust provider"
```

#### Device Trust Provider (CrowdStrike)

```bash
aws ec2 create-verified-access-trust-provider \
  --trust-provider-type device \
  --device-trust-provider-type crowdstrike \
  --device-options '{
    "TenantId": "crowdstrike-tenant-id",
    "PublicSigningKeyUrl": "https://api.crowdstrike.com/zero-trust/v2/certificates"
  }' \
  --policy-reference-name "crowdstrike" \
  --description "CrowdStrike device trust provider"
```

### Attach Trust Providers to Instance

```bash
# Attach identity provider
aws ec2 attach-verified-access-trust-provider \
  --verified-access-instance-id vai-0123456789abcdef \
  --verified-access-trust-provider-id vatp-0123456789abcdef

# Attach device provider
aws ec2 attach-verified-access-trust-provider \
  --verified-access-instance-id vai-0123456789abcdef \
  --verified-access-trust-provider-id vatp-device123456
```

### Verified Access Groups

```bash
# Create a group for web applications
aws ec2 create-verified-access-group \
  --verified-access-instance-id vai-0123456789abcdef \
  --description "Production Web Applications" \
  --policy-document 'permit(principal, action, resource)
    when {
      context.okta.groups.contains("production-access") &&
      context.crowdstrike.assessment.overall > 50
    };' \
  --tag-specifications 'ResourceType=verified-access-group,Tags=[{Key=Tier,Value=web}]'
```

### Verified Access Endpoints

```bash
# Create endpoint for ALB-backed application
aws ec2 create-verified-access-endpoint \
  --verified-access-group-id vag-0123456789abcdef \
  --endpoint-type load-balancer \
  --attachment-type vpc \
  --domain-certificate-arn arn:aws:acm:us-east-1:123456789012:certificate/xxxx \
  --application-domain app.internal.company.com \
  --endpoint-domain-prefix myapp \
  --load-balancer-options '{
    "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/internal-alb/xxxx",
    "Port": 443,
    "Protocol": "https",
    "SubnetIds": ["subnet-abc123", "subnet-def456"]
  }' \
  --security-group-ids sg-0123456789abcdef \
  --description "Internal HR Application"
```

## Cedar Policy Language

### Policy Basics

```cedar
// Allow access for users in the engineering group with compliant devices
permit(principal, action, resource)
when {
    context.okta.groups.contains("engineering") &&
    context.crowdstrike.assessment.overall > 70 &&
    context.crowdstrike.assessment.sensor_config.status == "active"
};

// Deny access from unmanaged devices
forbid(principal, action, resource)
when {
    !context.crowdstrike.assessment.sensor_config.status == "active"
};
```

### Advanced Policy Examples

```cedar
// Time-based access - only during business hours (UTC)
permit(principal, action, resource)
when {
    context.okta.groups.contains("contractors") &&
    context.http_request.http_method == "GET" &&
    context.crowdstrike.assessment.overall > 80
};

// Restrict admin access to specific user group with high device trust
permit(principal, action, resource)
when {
    context.idc.groups.contains("admins") &&
    context.crowdstrike.assessment.overall > 90 &&
    context.crowdstrike.assessment.os_version.startswith("Windows 11") ||
    context.crowdstrike.assessment.os_version.startswith("macOS 14")
};

// Allow read-only access for lower trust levels
permit(principal, action, resource)
when {
    context.okta.groups.contains("read-only") &&
    context.crowdstrike.assessment.overall > 30 &&
    context.http_request.http_method == "GET"
};
```

### Group-Level vs Endpoint-Level Policies

```cedar
// Group-level policy (applies to all endpoints in the group)
// Set on the Verified Access Group
permit(principal, action, resource)
when {
    context.okta.groups.contains("employees") &&
    context.crowdstrike.assessment.overall > 50
};

// Endpoint-level policy (additional restrictions for specific app)
// Set on the Verified Access Endpoint
permit(principal, action, resource)
when {
    context.okta.groups.contains("hr-team") &&
    context.okta.email.endsWith("@company.com")
};
```

## Terraform Configuration

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Verified Access Instance
resource "aws_verifiedaccess_instance" "main" {
  description = "Production Zero Trust Access"
  tags = {
    Environment = "production"
  }
}

# Identity Trust Provider (OIDC)
resource "aws_verifiedaccess_trust_provider" "okta" {
  policy_reference_name    = "okta"
  trust_provider_type      = "user"
  user_trust_provider_type = "oidc"
  description              = "Okta identity provider"

  oidc_options {
    authorization_endpoint = "https://company.okta.com/oauth2/default/v1/authorize"
    client_id              = var.okta_client_id
    client_secret          = var.okta_client_secret
    issuer                 = "https://company.okta.com/oauth2/default"
    scope                  = "openid profile groups"
    token_endpoint         = "https://company.okta.com/oauth2/default/v1/token"
    user_info_endpoint     = "https://company.okta.com/oauth2/default/v1/userinfo"
  }
}

# Device Trust Provider (CrowdStrike)
resource "aws_verifiedaccess_trust_provider" "crowdstrike" {
  policy_reference_name     = "crowdstrike"
  trust_provider_type       = "device"
  device_trust_provider_type = "crowdstrike"
  description               = "CrowdStrike device trust"

  device_options {
    tenant_id = var.crowdstrike_tenant_id
  }
}

# Attach providers to instance
resource "aws_verifiedaccess_instance_trust_provider_attachment" "okta" {
  verifiedaccess_instance_id       = aws_verifiedaccess_instance.main.id
  verifiedaccess_trust_provider_id = aws_verifiedaccess_trust_provider.okta.id
}

resource "aws_verifiedaccess_instance_trust_provider_attachment" "crowdstrike" {
  verifiedaccess_instance_id       = aws_verifiedaccess_instance.main.id
  verifiedaccess_trust_provider_id = aws_verifiedaccess_trust_provider.crowdstrike.id
}

# Verified Access Group
resource "aws_verifiedaccess_group" "web_apps" {
  verifiedaccess_instance_id = aws_verifiedaccess_instance.main.id
  description                = "Production Web Applications"

  policy_document = <<-CEDAR
    permit(principal, action, resource)
    when {
      context.okta.groups.contains("production-access") &&
      context.crowdstrike.assessment.overall > 50
    };
  CEDAR

  tags = {
    Tier = "web"
  }
}

# Verified Access Endpoint
resource "aws_verifiedaccess_endpoint" "internal_app" {
  verified_access_group_id = aws_verifiedaccess_group.web_apps.id
  endpoint_type            = "load-balancer"
  attachment_type          = "vpc"
  domain_certificate_arn   = aws_acm_certificate.app.arn
  application_domain       = "app.internal.company.com"
  endpoint_domain_prefix   = "myapp"
  description              = "Internal Application"

  load_balancer_options {
    load_balancer_arn = aws_lb.internal.arn
    port              = 443
    protocol          = "https"
    subnet_ids        = var.private_subnet_ids
  }

  security_group_ids = [aws_security_group.verified_access.id]

  policy_document = <<-CEDAR
    permit(principal, action, resource)
    when {
      context.okta.groups.contains("app-users")
    };
  CEDAR
}

# Logging configuration
resource "aws_verifiedaccess_instance_logging_configuration" "main" {
  verifiedaccess_instance_id = aws_verifiedaccess_instance.main.id

  access_logs {
    cloudwatch_logs {
      enabled   = true
      log_group = aws_cloudwatch_log_group.verified_access.name
    }
    s3 {
      enabled     = true
      bucket_name = aws_s3_bucket.access_logs.id
      prefix      = "verified-access/"
    }
  }
}

resource "aws_cloudwatch_log_group" "verified_access" {
  name              = "/aws/verified-access/production"
  retention_in_days = 90
}
```

## Multi-Account Deployment with AWS RAM

```hcl
# Share Verified Access Group across accounts via RAM
resource "aws_ram_resource_share" "verified_access" {
  name                      = "verified-access-share"
  allow_external_principals = false
}

resource "aws_ram_resource_association" "group_share" {
  resource_arn       = aws_verifiedaccess_group.web_apps.verified_access_group_arn
  resource_share_arn = aws_ram_resource_share.verified_access.arn
}

resource "aws_ram_principal_association" "workload_ou" {
  principal          = "arn:aws:organizations::123456789012:ou/o-xxxx/ou-xxxx-xxxxxxxx"
  resource_share_arn = aws_ram_resource_share.verified_access.arn
}
```

## Monitoring and Logging

```bash
# Query access logs in CloudWatch
aws logs filter-log-events \
  --log-group-name /aws/verified-access/production \
  --filter-pattern '{ $.status_code = "403" }' \
  --start-time $(date -d '1 hour ago' +%s000)

# CloudWatch alarm for access denials
aws cloudwatch put-metric-alarm \
  --alarm-name "VerifiedAccess-HighDenialRate" \
  --metric-name "AccessDenied" \
  --namespace "AWS/VerifiedAccess" \
  --statistic Sum \
  --period 300 \
  --threshold 100 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:security-alerts
```

## Security Best Practices

1. **Layer policies**: Use group-level policies for broad controls and endpoint-level for app-specific restrictions
2. **Require device trust**: Always include device posture checks in Cedar policies
3. **Enable access logging**: Send to both CloudWatch and S3 for real-time monitoring and long-term retention
4. **Use RAM for multi-account**: Share groups across OUs instead of duplicating configuration
5. **Rotate OIDC secrets**: Automate client secret rotation via Secrets Manager
6. **Test policies in non-production**: Validate Cedar policies before production deployment
7. **Set high device trust thresholds**: Require overall score above 70 for production access
8. **Monitor for policy drift**: Use AWS Config rules to detect unauthorized changes

## References

- [AWS Verified Access Documentation](https://docs.aws.amazon.com/verified-access/)
- [Cedar Policy Language](https://www.cedarpolicy.com/)
- [Building Zero Trust Across Multi-Account AWS Environments](https://aws.amazon.com/blogs/networking-and-content-delivery/building-zero-trust-access-across-multi-account-aws-environments/)
- [Visual Guide to AWS Verified Access Setup](https://medium.com/@chaim_sanders/a-visual-guide-to-setting-up-aws-verified-access-1333466f7222)
- [NIST SP 800-207 Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
