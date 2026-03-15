# API Reference: GCP Security Assessment with Forseti

## Google Cloud Security Command Center API

| Method | Description |
|--------|-------------|
| `SecurityCenterClient.list_findings(parent, filter)` | List active findings by severity and state |
| `SecurityCenterClient.list_sources(parent)` | List security sources in an organization |
| `SecurityCenterClient.group_findings(parent, group_by)` | Group findings by category or severity |

## Cloud Asset Inventory API

| Method | Description |
|--------|-------------|
| `AssetServiceClient.search_all_iam_policies(scope, query)` | Search IAM policies across org |
| `AssetServiceClient.search_all_resources(scope, asset_types)` | Search resources by type |
| `AssetServiceClient.export_assets(parent, output_config)` | Export asset inventory to BigQuery |

## Compute Engine API (Firewall)

| Method | Description |
|--------|-------------|
| `FirewallsClient.list(project)` | List all VPC firewall rules |
| `FirewallsClient.get(project, firewall)` | Get specific firewall rule details |

## Cloud Storage API

| Method | Description |
|--------|-------------|
| `Client.list_buckets()` | List all buckets in a project |
| `Bucket.get_iam_policy()` | Get IAM policy for a bucket |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `google-cloud-securitycenter` | >=1.23 | Security Command Center API access |
| `google-cloud-asset` | >=3.19 | Cloud Asset Inventory searches |
| `google-cloud-storage` | >=2.10 | Storage bucket auditing |
| `google-cloud-compute` | >=1.14 | Firewall rule enumeration |

## References

- Security Command Center API: https://cloud.google.com/security-command-center/docs/reference/rest
- Cloud Asset API: https://cloud.google.com/asset-inventory/docs/reference/rest
- CIS GCP Foundations Benchmark: https://www.cisecurity.org/benchmark/google_cloud_computing_platform
- ScoutSuite: https://github.com/nccgroup/ScoutSuite
