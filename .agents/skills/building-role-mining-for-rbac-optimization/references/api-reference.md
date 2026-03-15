# API Reference: Role Mining for RBAC Optimization

## Input Format (CSV)
```csv
user,entitlement,system
john.doe,read_files,FileServer
john.doe,write_files,FileServer
jane.smith,read_files,FileServer
```

## Role Mining Algorithms

### Bottom-Up Mining
Finds exact permission sets shared by >= N users.
- Input: user-permission matrix
- Output: candidate roles with exact permission sets
- Parameter: `min_users` (default: 2)

### Top-Down Mining (Jaccard Clustering)
Groups users by permission similarity.
```
Jaccard(A, B) = |A ∩ B| / |A ∪ B|
```
- Threshold >= 0.8: strict similarity
- Threshold >= 0.6: moderate clustering

## Optimization Metrics
| Metric | Description |
|--------|-------------|
| Total Assignments | Sum of all user-permission pairs |
| Candidate Roles | Discovered role count |
| Role Coverage | Users assigned to candidate roles |
| Avg Permissions/User | Assignment density |
| Outlier Count | Users with unique permissions |

## SailPoint IdentityNow Role Mining API
```
POST https://{tenant}.api.identitynow.com/beta/role-mining-sessions
Authorization: Bearer TOKEN
{
  "scope": {"included": {"identityIds": [...]}},
  "minEntitlementPopularity": 2,
  "pruneThreshold": 50
}
```

## SailPoint Role Mining Status
```
GET /beta/role-mining-sessions/{sessionId}
GET /beta/role-mining-sessions/{sessionId}/potential-roles
```

## CyberArk Identity Role Optimization
```
GET /Roles/GetRoleMembers?name={role}
POST /Roles/OptimizeRoles
{"minUsers": 3, "maxRoles": 50}
```

## NIST RBAC Model Levels
| Level | Description |
|-------|-------------|
| Core RBAC | Users, roles, permissions, sessions |
| Hierarchical | Role inheritance |
| Constrained | Separation of duty (SoD) |
| Symmetric | Permission-role review |
