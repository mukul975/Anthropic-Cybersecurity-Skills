# Standards Reference - Kubernetes Pod Security Standards

## Kubernetes Pod Security Standards (PSS) v1.31

### Privileged Profile
- No restrictions applied
- Used for: kube-system, monitoring agents, CNI plugins, storage drivers

### Baseline Profile Controls
| Control | Policy |
|---------|--------|
| HostProcess | Must be false |
| Host Namespaces | hostNetwork, hostPID, hostIPC must be false |
| Privileged Containers | Must be false |
| Capabilities | Cannot add beyond: AUDIT_WRITE, CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, MKNOD, NET_BIND_SERVICE, SETFCAP, SETGID, SETPCAP, SETUID, SYS_CHROOT |
| HostPath Volumes | Must not be used |
| Host Ports | Must not define hostPort |
| AppArmor | Must not set to unconfined |
| SELinux | type must be container_t, container_init_t, or container_kvm_t; user/role must not be set |
| /proc Mount Type | Must be Default |
| Seccomp | Must not set to Unconfined |
| Sysctls | Must only use safe sysctls |

### Restricted Profile Controls (in addition to Baseline)
| Control | Policy |
|---------|--------|
| Volume Types | Only: configMap, csi, downwardAPI, emptyDir, ephemeral, persistentVolumeClaim, projected, secret |
| Privilege Escalation | allowPrivilegeEscalation must be false |
| Running as Non-root | runAsNonRoot must be true |
| Running as Non-root User | runAsUser must be non-zero |
| Seccomp | Must be RuntimeDefault or Localhost |
| Capabilities | Must drop ALL; may only add NET_BIND_SERVICE |

## CIS Kubernetes Benchmark v1.8

### Section 5: Policies
- 5.1: RBAC and Service Accounts
- 5.2: Pod Security Standards
  - 5.2.1: Ensure PSA is not set to Privileged on non-system namespaces
  - 5.2.2: Minimize admission of privileged containers
  - 5.2.3: Minimize admission of containers wanting to share host process ID namespace
  - 5.2.4: Minimize admission of containers wanting to share host IPC namespace
  - 5.2.5: Minimize admission of containers wanting to share host network namespace
  - 5.2.6: Minimize admission of containers with allowPrivilegeEscalation
  - 5.2.7: Minimize admission of root containers
  - 5.2.8: Minimize admission of containers with NET_RAW capability
  - 5.2.9: Minimize admission of containers with added capabilities
  - 5.2.10: Minimize admission of containers with capabilities assigned
  - 5.2.11: Minimize admission of containers with HostProcess
  - 5.2.12: Minimize admission of HostPath volumes
  - 5.2.13: Minimize admission of containers with unrestricted Seccomp profile

## NSA/CISA Kubernetes Hardening Guide

### Pod Security Recommendations
- Use PSA in enforce mode for production namespaces
- Set restricted profile as default for all non-system namespaces
- Require seccomp profiles on all pods
- Prevent privileged containers in all workload namespaces
- Require non-root user for all containers
- Drop all capabilities and only add NET_BIND_SERVICE if needed

## MITRE ATT&CK for Containers

### Techniques Prevented by Restricted Profile
| Technique | PSS Control |
|-----------|------------|
| T1611 - Escape to Host | Blocks privileged, hostPID, hostNetwork |
| T1610 - Deploy Container | Blocks privileged containers |
| T1053 - Scheduled Task | Blocks host namespace access |
| T1548 - Abuse Elevation Control | Blocks allowPrivilegeEscalation |
