# AWS Verified Access ZTNA — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| boto3 | `pip install boto3` | AWS SDK — EC2 Verified Access API |

## Key boto3 EC2 Methods

| Method | Description |
|--------|-------------|
| `describe_verified_access_instances()` | List VA instances |
| `describe_verified_access_groups()` | List VA groups with policies |
| `describe_verified_access_endpoints()` | List VA application endpoints |
| `describe_verified_access_trust_providers()` | List identity/device trust providers |
| `create_verified_access_instance()` | Create new VA instance |
| `create_verified_access_group(VerifiedAccessInstanceId=)` | Create group under instance |
| `create_verified_access_endpoint()` | Expose application via VA |
| `modify_verified_access_group_policy()` | Update Cedar policy document |

## Cedar Policy Language

```cedar
permit(principal, action, resource)
when {
    context.identity.groups has "engineering" &&
    context.identity.email.address like "*@company.com" &&
    context.device.status == "compliant"
};
```

## Trust Provider Types

| Type | Description |
|------|-------------|
| user / iam-identity-center | AWS IAM Identity Center OIDC |
| user / oidc | Third-party OIDC provider |
| device / jamf | Jamf device trust |
| device / crowdstrike | CrowdStrike device posture |

## External References

- [AWS Verified Access Docs](https://docs.aws.amazon.com/verified-access/)
- [Cedar Policy Language](https://www.cedarpolicy.com/en)
- [boto3 EC2 Verified Access](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_verified_access_instances.html)
