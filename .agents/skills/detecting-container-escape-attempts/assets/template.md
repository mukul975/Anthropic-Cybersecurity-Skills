# Container Escape Detection Assessment Template

## Environment Information

| Field | Value |
|-------|-------|
| Cluster Name | |
| Container Runtime | Docker / containerd / CRI-O |
| Kernel Version | |
| Runtime Detection Tool | Falco / Sysdig / Tetragon |
| Assessment Date | |

## Escape Surface Inventory

| Container | Privileged | Capabilities | Host NS | Docker Socket | Risk Score |
|-----------|-----------|-------------|---------|--------------|------------|
| | | | | | /10 |

## Detection Rules Deployed

| Rule | Tool | Detects | Status |
|------|------|---------|--------|
| Namespace manipulation | Falco | setns/unshare from container | |
| Docker socket access | Falco | /var/run/docker.sock read/write | |
| Kernel module loading | Falco | modprobe/insmod from container | |
| Sensitive proc access | Falco | /proc/sysrq-trigger, /proc/kcore | |
| Cgroup escape | Falco | release_agent write | |
| Mount operations | auditd | mount/umount2 syscalls | |
| Binary replacement | FIM | runc/containerd binary changes | |

## Findings

| Priority | Container | Risk Factor | Score | Remediation |
|----------|-----------|------------|-------|-------------|
| P1 | | | | |
| P2 | | | | |

## Remediation Tracking

| Finding | Action Required | Owner | Status | Verified |
|---------|----------------|-------|--------|----------|
| | | | | |
