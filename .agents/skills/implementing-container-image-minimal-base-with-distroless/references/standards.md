# Standards - Distroless Container Images

## NIST SP 800-190
- Section 3.1.1: Minimize image content to reduce attack surface
- Section 4.1.1: Use minimal base images for container builds

## CIS Docker Benchmark v1.6
- 4.1: Ensure a user for the container has been created
- 4.2: Ensure containers use trusted base images
- 4.6: Ensure HEALTHCHECK instructions have been added
- 4.9: Ensure COPY is used instead of ADD

## OWASP Docker Security
- D2: Patch Management Strategies (fewer packages = fewer patches)
- D3: Network Segmentation and Firewalling
- D4: Secure Defaults and Hardening (no shell = hardened by default)
