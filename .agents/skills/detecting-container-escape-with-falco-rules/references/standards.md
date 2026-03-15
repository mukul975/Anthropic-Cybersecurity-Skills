# Standards and References - Container Escape Detection with Falco

## Industry Standards

### NIST SP 800-190: Application Container Security Guide
- Section 4.3: Container Runtime - Monitor containers for anomalous behavior at runtime
- Section 5.4: Container Runtime Security - Implement runtime monitoring and alerting
- Recommends syscall-level monitoring for escape detection

### CIS Kubernetes Benchmark v1.8
- 5.7.1: Create administrative boundaries between resources using namespaces
- 5.7.2: Ensure that the seccomp profile is set to docker/default
- 5.7.3: Apply Security Context to pods and containers
- 5.7.4: The default namespace should not be used

### MITRE ATT&CK for Containers

| Technique ID | Name | Falco Detection |
|-------------|------|-----------------|
| T1611 | Escape to Host | nsenter, mount, chroot detection |
| T1610 | Deploy Container | Privileged container launch detection |
| T1003 | OS Credential Dumping | /etc/shadow access from container |
| T1005 | Data from Local System | Sensitive file read detection |
| T1059 | Command and Scripting Interpreter | Shell spawn in container |
| T1068 | Exploitation for Privilege Escalation | Kernel exploit indicators |

### NSA/CISA Kubernetes Hardening Guide v1.2
- Section 5: Audit Logging and Threat Detection
  - Enable runtime security monitoring
  - Detect anomalous container behavior in real-time
  - Monitor for privilege escalation attempts

## Falco Rule Maturity Levels

| Level | Description | Count |
|-------|-------------|-------|
| maturity_stable | Production-ready, low false positives | 25 rules |
| maturity_incubating | Proven useful, may need tuning | ~30 rules |
| maturity_sandbox | Experimental, high false positive rate | ~38 rules |
| maturity_deprecated | Scheduled for removal | Variable |

## Known Container Escape CVEs

| CVE | Description | Falco Rule |
|-----|-------------|------------|
| CVE-2024-21626 | runc process.cwd container breakout | Detect use of /proc/self/fd to access host |
| CVE-2022-0492 | cgroup v1 release_agent escape | Write to Cgroup Release Agent |
| CVE-2022-0185 | File system context exploit | Detect unshare in container |
| CVE-2020-15257 | containerd-shim API access | Detect abstract socket connections |
| CVE-2019-5736 | runc overwrite host binary | Detect writes to /proc/self/exe |

## Compliance Mappings

### PCI DSS v4.0
- Requirement 10.6.1: Review logs for anomalies at least daily
- Requirement 11.5: Deploy change-detection mechanisms

### SOC 2 Type II
- CC7.2: Monitor system components for anomalies
- CC7.3: Evaluate security events to determine impact
