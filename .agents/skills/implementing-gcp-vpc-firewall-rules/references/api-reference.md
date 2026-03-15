# API Reference: Implementing GCP VPC Firewall Rules

## Libraries

### google-cloud-compute
- **Install**: `pip install google-cloud-compute`
- **Docs**: https://cloud.google.com/python/docs/reference/compute/latest

### Key Classes and Methods

| Class | Method | Description |
|-------|--------|-------------|
| `FirewallsClient` | `list(project)` | List all firewall rules |
| `FirewallsClient` | `get(project, firewall)` | Get rule details |
| `FirewallsClient` | `insert(project, firewall_resource)` | Create rule |
| `FirewallsClient` | `patch(project, firewall, firewall_resource)` | Update rule |
| `FirewallsClient` | `delete(project, firewall)` | Delete rule |
| `NetworksClient` | `list(project)` | List VPC networks |

### Firewall Rule Object Fields
- `name` -- Rule name (unique per project)
- `network` -- VPC network path
- `direction` -- `INGRESS` or `EGRESS`
- `priority` -- 0 (highest) to 65535 (lowest)
- `allowed[]` -- Protocol and port combinations to allow
- `denied[]` -- Protocol and port combinations to deny
- `source_ranges[]` -- Source CIDR ranges for ingress
- `destination_ranges[]` -- Destination CIDRs for egress
- `target_tags[]` -- Network tags to apply rule to
- `source_tags[]` -- Source instance tags
- `disabled` -- Boolean to disable without deleting
- `log_config.enable` -- Enable firewall rule logging

## Priority Ranges (Best Practice)
- 0-999: Emergency/override rules
- 1000-9999: Organization policies
- 10000-49999: Application-specific rules
- 50000-64999: Default deny rules
- 65534: Implied allow egress (GCP default)
- 65535: Implied deny ingress (GCP default)

## gcloud CLI Equivalents
- `gcloud compute firewall-rules list`
- `gcloud compute firewall-rules create NAME --allow tcp:22 --source-ranges 10.0.0.0/8`
- `gcloud compute firewall-rules delete NAME`
- `gcloud compute firewall-rules update NAME --disabled`

## Hierarchical Firewall Policies
- Organization-level: `compute.firewallPolicies`
- Folder-level: Applied via `compute.firewallPolicies.addAssociation`
- Evaluation order: Organization > Folder > VPC rules

## External References
- VPC Firewall Rules: https://cloud.google.com/vpc/docs/firewalls
- Firewall Policies: https://cloud.google.com/vpc/docs/firewall-policies
- VPC Flow Logs: https://cloud.google.com/vpc/docs/using-flow-logs
- Cloud Armor WAF: https://cloud.google.com/armor/docs
