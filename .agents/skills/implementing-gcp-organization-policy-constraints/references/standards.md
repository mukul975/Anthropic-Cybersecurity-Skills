# Standards and References - GCP Organization Policy Constraints

## CIS GCP Foundations Benchmark v3.0

| Section | Control | Constraint |
|---------|---------|-----------|
| 1.4 | Ensure user-managed service account keys are rotated within 90 days | iam.disableServiceAccountKeyCreation |
| 3.10 | Ensure VPC Flow Logs are enabled | N/A (use custom constraint) |
| 4.4 | Ensure OS Login is enabled for a project | compute.requireOsLogin |
| 4.5 | Ensure serial port access is disabled | compute.disableSerialPortAccess |
| 6.2 | Ensure Cloud SQL instances are not publicly accessible | sql.restrictPublicIp |
| 5.1 | Ensure uniform bucket-level access is enabled | storage.uniformBucketLevelAccess |

## NIST 800-53 Controls Mapping

- AC-3: Access Enforcement
- AC-6: Least Privilege
- CM-7: Least Functionality
- SC-7: Boundary Protection
- SC-12: Cryptographic Key Establishment

## Google Cloud Security Best Practices

- Principle of least privilege for organization policies
- Hierarchical policy inheritance model
- Dry-run testing before enforcement
- Separate exception management from baseline policies
