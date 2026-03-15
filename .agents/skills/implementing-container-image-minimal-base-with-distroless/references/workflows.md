# Workflows - Distroless Container Images

## Migration Workflow
1. Identify current base image and its package footprint
2. Select appropriate distroless variant for your runtime
3. Create multi-stage Dockerfile with build and runtime stages
4. Test application functionality with distroless base
5. Scan both old and new images to compare CVE counts
6. Update debugging procedures (ephemeral containers, debug variants)
7. Deploy to staging and validate
8. Roll out to production

## Image Build Pipeline
1. Build application in builder stage (full SDK image)
2. Copy only runtime artifacts to distroless stage
3. Set non-root user via `:nonroot` tag
4. Scan final image with Trivy/Grype
5. Sign image with cosign
6. Push to registry with digest pinning
