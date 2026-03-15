# Standards Reference - Docker Container Hardening

## CIS Docker Benchmark v1.8.0

### Section 1: Host Configuration
- 1.1.1: Ensure a separate partition for containers has been created
- 1.1.2: Ensure only trusted users are allowed to control Docker daemon
- 1.1.3-1.1.18: Ensure Docker daemon audit configuration

### Section 2: Docker Daemon Configuration
- 2.1: Run the Docker daemon as non-root user (rootless mode)
- 2.2: Ensure network traffic is restricted between containers (--icc=false)
- 2.3: Ensure logging level is set to info
- 2.4: Ensure Docker is allowed to make changes to iptables
- 2.5: Ensure insecure registries are not used
- 2.6: Ensure aufs storage driver is not used
- 2.7: Ensure TLS authentication for Docker daemon is configured
- 2.8: Ensure default ulimit is configured appropriately
- 2.9: Enable user namespace support
- 2.10: Ensure default cgroup usage has been confirmed
- 2.11: Ensure base device size is not changed until needed
- 2.12: Ensure centralized and remote logging is configured
- 2.13: Ensure live restore is enabled
- 2.14: Ensure Userland Proxy is disabled
- 2.15: Ensure daemon-wide custom seccomp profile is applied
- 2.16: Ensure experimental features are not used in production
- 2.17: Ensure containers are restricted from acquiring new privileges

### Section 4: Container Images and Build Files
- 4.1: Ensure that a user for the container has been created
- 4.2: Ensure containers use trusted base images
- 4.3: Ensure unnecessary packages are not installed
- 4.4: Ensure images are scanned for vulnerabilities
- 4.5: Ensure Content trust for Docker is enabled
- 4.6: Ensure HEALTHCHECK instructions have been added to container images
- 4.7: Ensure update instructions are not used alone in the Dockerfile
- 4.8: Ensure setuid and setgid permissions are removed
- 4.9: Ensure COPY is used instead of ADD
- 4.10: Ensure secrets are not stored in Dockerfiles
- 4.11: Ensure only verified packages are installed

### Section 5: Container Runtime
- 5.1: Ensure AppArmor profile is enabled
- 5.2: Ensure SELinux security options are set
- 5.3: Ensure Linux kernel capabilities are restricted
- 5.4: Ensure privileged containers are not used
- 5.5: Ensure sensitive host system directories are not mounted
- 5.6: Ensure sshd is not running within containers
- 5.7: Ensure privileged ports are not mapped within containers
- 5.8: Ensure only needed ports are open on the container
- 5.9: Ensure host network mode is not used
- 5.10: Ensure memory usage for container is limited
- 5.11: Ensure CPU priority is set appropriately
- 5.12: Ensure container root filesystem is mounted as read only
- 5.13: Ensure incoming container traffic is bound to a specific host interface
- 5.25: Ensure container is restricted from acquiring additional privileges

## NIST SP 800-190 - Application Container Security Guide

### Key Recommendations
- Use container-specific host OS (CoreOS, Flatcar, Bottlerocket)
- Segment container networks by sensitivity level
- Use container runtime with minimal attack surface
- Implement image signing and verification
- Harden container registries with access controls
- Monitor container runtime behavior for anomalies

## OWASP Docker Security Cheat Sheet

### Top Docker Security Risks
1. Unrestricted container access to host resources
2. Running containers in privileged mode
3. Running as root inside containers
4. Unverified or unscanned container images
5. Exposed Docker daemon socket
6. Insecure container networking
7. Secrets stored in images or environment variables
8. Missing resource limits
9. Outdated base images with known vulnerabilities
10. Insufficient logging and monitoring
