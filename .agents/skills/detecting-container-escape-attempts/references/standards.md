# Standards Reference - Container Escape Detection

## MITRE ATT&CK for Containers

### T1611 - Escape to Host
- **Tactic**: Privilege Escalation
- **Description**: Adversaries may escape container isolation and gain access to the host
- **Sub-techniques**: Privileged container, nsenter, cgroup escape, kernel exploit
- **Detection**: Monitor for namespace manipulation, sensitive path access, privilege changes

### T1610 - Deploy Container
- **Tactic**: Execution
- **Description**: Deploy a new container using Docker socket access from within a container

### T1068 - Exploitation for Privilege Escalation
- **Tactic**: Privilege Escalation
- **Description**: Exploit kernel vulnerabilities for container escape (Dirty Pipe, runc CVEs)

### T1548 - Abuse Elevation Control Mechanism
- **Sub-technique**: T1548.004 - Elevated Execution with Prompt
- **Description**: Abuse Linux capabilities like CAP_SYS_ADMIN for escape

## Known Container Escape CVEs

| CVE | Component | Description | CVSS |
|-----|-----------|-------------|------|
| CVE-2024-21626 | runc | Working directory escape via /proc/self/fd leak | 8.6 |
| CVE-2022-0185 | Linux kernel | fsconfig heap overflow, namespace escape | 8.4 |
| CVE-2022-0847 | Linux kernel | Dirty Pipe - arbitrary file overwrite | 7.8 |
| CVE-2021-22555 | Linux kernel | Netfilter heap OOB, container escape | 7.8 |
| CVE-2020-15257 | containerd | Abstract socket namespace escape | 5.2 |
| CVE-2019-5736 | runc | Binary overwrite, host code execution | 8.6 |

## NIST SP 800-190 - Application Container Security Guide

### Container Runtime Security
- Monitor containers for anomalous behavior
- Detect attempts to access host namespaces
- Alert on kernel module loading from containers
- Implement syscall filtering with seccomp

## Linux Capabilities Required for Escape

| Capability | Escape Risk | Description |
|-----------|------------|-------------|
| CAP_SYS_ADMIN | Critical | Mount filesystems, namespace manipulation |
| CAP_SYS_PTRACE | Critical | ptrace processes, inspect memory |
| CAP_NET_ADMIN | High | Network namespace manipulation |
| CAP_SYS_MODULE | Critical | Load kernel modules |
| CAP_SYS_RAWIO | High | Raw I/O access, iopl/ioperm |
| CAP_DAC_OVERRIDE | High | Bypass file read/write permission |
| CAP_DAC_READ_SEARCH | Medium | Bypass file read permission |
| CAP_MKNOD | Medium | Create device files |
