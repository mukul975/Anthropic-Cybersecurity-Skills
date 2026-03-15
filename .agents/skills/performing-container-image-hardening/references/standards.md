# Standards Reference: Container Image Hardening

## CIS Docker Benchmark v1.6.0 - Image Controls

- 4.1: Create a user for the container
- 4.2: Use trusted base images
- 4.3: Do not install unnecessary packages
- 4.4: Scan and rebuild images for security patches
- 4.6: Add HEALTHCHECK instruction
- 4.7: Do not use update instructions alone
- 4.9: Use COPY instead of ADD
- 4.10: Do not store secrets in Dockerfiles
- 4.11: Install verified packages only

## NIST SP 800-190 Application Container Security Guide

### Image Hardening (Section 4.1)
- Use minimal base images to reduce attack surface
- Remove unnecessary tools, shells, and package managers
- Scan images for vulnerabilities before deployment
- Sign images for integrity verification

## OWASP Docker Security Cheat Sheet

- Use multi-stage builds
- Run as non-root user
- Use read-only root filesystem
- Pin base images to digests
- Drop all Linux capabilities
- Enable seccomp profile
