# Standards Reference: Container Scanning with Trivy

## NIST SP 800-190 - Application Container Security Guide

### Image Vulnerabilities (Section 3.1)
- Scan all container images for known vulnerabilities before deployment
- Establish organizational policies for maximum acceptable vulnerability severity
- Monitor images in registries for newly discovered vulnerabilities
- Maintain an up-to-date vulnerability database for scanning tools

### Image Configuration Defects (Section 3.2)
- Verify images follow CIS Docker Benchmark configuration guidelines
- Ensure images run as non-root users unless operationally required
- Remove unnecessary packages, shells, and utilities from production images

## CIS Docker Benchmark v1.6.0

### Image Level Controls
- 4.1: Ensure a user for the container has been created (maps to Trivy DS002)
- 4.2: Ensure containers use trusted base images
- 4.3: Ensure unnecessary packages are not installed in the container
- 4.6: Ensure HEALTHCHECK instructions have been added (maps to Trivy DS026)
- 4.7: Ensure update instructions are not used alone in the Dockerfile
- 4.9: Ensure COPY is used instead of ADD in Dockerfiles (maps to Trivy DS005)

## OWASP Docker Security Cheat Sheet

### Vulnerability Management
- Scan images in the CI/CD pipeline before pushing to registries
- Use `--ignore-unfixed` to focus on actionable vulnerabilities
- Implement SBOM generation for full component visibility
- Re-scan images on a schedule to catch newly published CVEs

### Dockerfile Security
- Use minimal base images (distroless, Alpine, slim variants)
- Pin base image versions with digest for reproducibility
- Run containers as non-root with explicit USER instruction
- Use multi-stage builds to exclude build tools from production images

## NIST SSDF (SP 800-218)

### PW.4: Reuse Existing, Well-Secured Software
- PW.4.1: Use automated tools to check for known vulnerabilities in dependencies
- Map to Trivy's OS package and language dependency scanning capabilities

### PS.1: Protect All Forms of Code
- PS.1.1: Store all forms of code in a code repository protected by access controls
- Container images in registries should be scanned and signed before use

## SLSA Framework Alignment

### Source Level
- Trivy filesystem scanning validates source dependencies before build
- Git repository scanning detects secrets and vulnerable dependencies in source

### Build Level
- Trivy image scanning validates the build output for vulnerabilities
- SBOM generation creates a verifiable bill of materials for the built artifact

### Deployment Level
- Admission controllers can verify Trivy scan results before pod scheduling
- Harbor registry integration enforces scan-before-pull policies
