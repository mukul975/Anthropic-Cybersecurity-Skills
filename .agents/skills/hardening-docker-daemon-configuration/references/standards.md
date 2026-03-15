# Standards and References - Docker Daemon Hardening

## CIS Docker Benchmark v1.6

### Section 2: Docker Daemon Configuration

| Rule | Description | Status |
|------|-------------|--------|
| 2.1 | Run the Docker daemon as a non-root user | Rootless mode |
| 2.2 | Ensure network traffic is restricted between containers | icc: false |
| 2.3 | Ensure the logging level is set to info | log-level: info |
| 2.4 | Ensure Docker is allowed to make changes to iptables | iptables: true |
| 2.5 | Ensure insecure registries are not used | No --insecure-registry |
| 2.6 | Ensure aufs storage driver is not used | overlay2 driver |
| 2.7 | Ensure TLS authentication for Docker daemon is configured | tlsverify: true |
| 2.8 | Ensure the default ulimit is configured appropriately | default-ulimits set |
| 2.9 | Enable user namespace support | userns-remap: default |
| 2.10 | Ensure the default cgroup usage has been confirmed | cgroup-parent |
| 2.11 | Ensure base device size is not changed until needed | Default 10G |
| 2.12 | Ensure that authorization for Docker client commands is enabled | AuthZ plugin |
| 2.13 | Ensure centralized and remote logging is configured | log-driver |
| 2.14 | Ensure containers are restricted from acquiring new privileges | no-new-privileges |
| 2.15 | Ensure live restore is enabled | live-restore: true |
| 2.16 | Ensure Userland Proxy is disabled | userland-proxy: false |
| 2.17 | Ensure daemon-wide custom seccomp profile is applied | seccomp-profile |

## NIST SP 800-190
- Section 4.1.4: Configuration defects in container images
- Section 5.1: Image security - Content trust enforcement
- Section 5.3: Daemon hardening recommendations

## OWASP Docker Security Cheat Sheet
- Rule 0: Keep host and Docker up to date
- Rule 1: Do not expose the Docker daemon socket
- Rule 2: Set a user
- Rule 3: Limit capabilities
- Rule 4: Add no-new-privileges flag
- Rule 5: Disable inter-container communication
- Rule 6: Use Linux Security Module
- Rule 7: Limit resources
- Rule 8: Set filesystem and volumes to read-only
- Rule 9: Use static analysis tools
- Rule 10: Set log level to info

## Compliance Mappings

### PCI DSS v4.0
- Req 2.2: Develop configuration standards for all system components
- Req 2.2.1: System hardening procedures

### SOC 2
- CC6.1: Logical and physical access controls
- CC8.1: Change management

### FedRAMP
- CM-6: Configuration Settings
- CM-7: Least Functionality
