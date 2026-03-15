# SCIM Provisioning Standards Reference

## Protocol Standards

### RFC 7644 - SCIM Protocol
- Defines the RESTful API for managing identity resources
- Specifies HTTP methods, headers, and response formats
- Mandates JSON as the data interchange format
- Requires TLS for all communications

### RFC 7643 - SCIM Core Schema
- Defines User, Group, and EnterpriseUser schemas
- Specifies attribute types: string, boolean, decimal, integer, dateTime, reference, complex, binary
- Defines mutability: readOnly, readWrite, immutable, writeOnly
- Specifies attribute uniqueness: none, server, global

### RFC 7642 - SCIM Definitions, Overview, Concepts, and Requirements
- Provides context for the SCIM specification
- Defines terminology and use cases
- Outlines design requirements for cross-domain provisioning

## Okta SCIM Requirements

### Mandatory Endpoints
| Endpoint | Methods | Purpose |
|----------|---------|---------|
| /Users | GET, POST | User listing and creation |
| /Users/{id} | GET, PUT, PATCH, DELETE | Individual user operations |
| /Groups | GET, POST | Group listing and creation |
| /Groups/{id} | GET, PATCH, DELETE | Individual group operations |

### Required Filter Support
- `userName eq "value"` - Exact match on userName
- `id eq "value"` - Exact match on user ID
- `displayName eq "value"` - Exact match for groups

### Pagination Requirements
- Support `startIndex` and `count` query parameters
- Return `totalResults` in ListResponse
- Default `startIndex` is 1 (1-based indexing)
- Maximum `count` should be configurable

## Compliance Standards

### SOC 2 Type II
- Automated provisioning demonstrates access control effectiveness
- Deprovisioning within defined SLA shows timely access removal
- Audit logs of SCIM operations provide evidence for access reviews

### ISO 27001 - A.9.2 User Access Management
- A.9.2.1: User registration and deregistration (automated via SCIM)
- A.9.2.2: User access provisioning (role-based assignment)
- A.9.2.5: Review of user access rights (SCIM audit logs)
- A.9.2.6: Removal of access rights (automated deprovisioning)

### NIST SP 800-53 - AC (Access Control)
- AC-2: Account Management (automated lifecycle)
- AC-2(1): Automated System Account Management
- AC-2(4): Automated Audit Actions
- AC-6: Least Privilege (role-based provisioning)
