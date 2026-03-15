# Microsegmentation for Zero Trust — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| boto3 | `pip install boto3` | AWS security group audit |
| requests | `pip install requests` | Illumio / Guardicore API client |

## Key boto3 EC2 Methods

| Method | Description |
|--------|-------------|
| `describe_security_groups()` | List SGs with inbound/outbound rules |
| `authorize_security_group_ingress()` | Add inbound rule |
| `revoke_security_group_ingress()` | Remove inbound rule |

## Illumio PCE API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v2/orgs/{id}/workloads` | List managed workloads |
| GET | `/api/v2/orgs/{id}/sec_policy/draft/rule_sets` | List rule sets |
| PUT | `/api/v2/orgs/{id}/workloads/{id}` | Update workload enforcement mode |

## Segmentation Enforcement Modes

| Mode | Description |
|------|-------------|
| Visibility Only | Monitor traffic without blocking |
| Selective | Block specific flows, allow rest |
| Full | Deny all, allow by policy (zero trust) |

## External References

- [Illumio API Guide](https://docs.illumio.com/core/23.5/API-Reference/index.html)
- [NIST SP 800-207 Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [AWS Security Groups Best Practices](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
