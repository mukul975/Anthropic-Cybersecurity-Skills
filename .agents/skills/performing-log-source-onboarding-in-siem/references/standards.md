# Standards - Log Source Onboarding in SIEM

## Common Information Models

| SIEM Platform | Schema | Documentation |
|---|---|---|
| Splunk | CIM (Common Information Model) | docs.splunk.com |
| Elastic | ECS (Elastic Common Schema) | elastic.co/guide/en/ecs |
| Microsoft Sentinel | ASIM (Azure Sentinel Information Model) | learn.microsoft.com |
| Google Chronicle | UDM (Unified Data Model) | cloud.google.com/chronicle |
| Industry Standard | OCSF (Open Cybersecurity Schema Framework) | ocsf.io |

## Log Collection Protocols

| Protocol | Port | Use Case | Security |
|---|---|---|---|
| Syslog UDP | 514 | Network devices, basic forwarding | None |
| Syslog TCP | 514 | Reliable delivery | None |
| Syslog TLS | 6514 | Encrypted syslog | TLS 1.2+ |
| HTTP/S | 443/8088 | REST API, HEC (Splunk) | TLS |
| Windows WEF | 5985/5986 | Windows Event Forwarding | Kerberos/TLS |
| SNMP | 161/162 | Network device monitoring | SNMPv3 |
| S3/Blob | N/A | Cloud log storage | IAM/SAS |

## NIST SP 800-92 Log Management Guidelines

- Establish log management infrastructure
- Define log retention requirements
- Ensure log data integrity (tamper evidence)
- Configure time synchronization across all sources
- Implement log review and analysis procedures
