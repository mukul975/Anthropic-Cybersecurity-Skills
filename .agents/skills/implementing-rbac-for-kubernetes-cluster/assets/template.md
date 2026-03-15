# Kubernetes RBAC Configuration Template

## Namespace RBAC Matrix
| Namespace | Cluster Admin | Namespace Admin | Developer | Viewer | CI/CD SA |
|-----------|--------------|-----------------|-----------|--------|----------|
| production | 2 users | 2 users | 0 | 5 users | 1 SA |
| staging | 2 users | 3 users | 5 users | 3 users | 1 SA |
| development | 2 users | 5 users | 10 users | 0 | 1 SA |

## Role Definitions
| Role Name | Scope | Resources | Verbs | Use Case |
|-----------|-------|-----------|-------|----------|
| namespace-admin | Namespace | * | * (within NS) | Full namespace control |
| developer | Namespace | pods, deployments, services, configmaps | get,list,create,update,delete | Workload management |
| viewer | Namespace | pods, deployments, services, configmaps | get, list, watch | Read-only monitoring |
| secret-reader | Namespace | secrets | get, list | Application secret access |
| ci-deployer | Namespace | deployments, services, configmaps | get,list,create,update,patch | CI/CD pipeline |

## Service Account Inventory
| Service Account | Namespace | Bound Role | automountToken | Purpose |
|-----------------|-----------|------------|----------------|---------|
| | | | | |

## Audit Policy Configuration
- [ ] Log all create/update/delete on RBAC resources (RequestResponse level)
- [ ] Log all pod exec/attach events
- [ ] Log all secret access events
- [ ] Forward audit logs to SIEM
- [ ] Alert on ClusterRoleBinding changes
