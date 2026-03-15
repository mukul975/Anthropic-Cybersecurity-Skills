# Workflows - Supply Chain Security with in-toto

## Implementation Workflow

### Phase 1: Layout Design
1. Map your CI/CD pipeline steps (source, build, test, scan, package, push)
2. Identify functionaries for each step (CI runner, scanner, reviewer)
3. Define artifact flow between steps (what inputs/outputs)
4. Generate signing keys for each functionary
5. Create and sign the supply chain layout

### Phase 2: Pipeline Integration
1. Wrap each CI/CD step with `in-toto-run` to generate link metadata
2. Configure key management (Vault, KMS, or Sigstore keyless)
3. Store link metadata alongside build artifacts
4. Verify supply chain at end of pipeline before push to registry
5. Attach attestations to container images via cosign

### Phase 3: Deployment Verification
1. Deploy admission webhook for in-toto verification
2. Configure policy engine to require valid attestations
3. Test with known-good and known-bad attestation chains
4. Enable enforcement mode to block unverified images
5. Monitor verification failures and alert on anomalies

## CI/CD Pipeline Integration

### GitHub Actions Example
```yaml
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - name: Record checkout step
        run: |
          in-toto-run --step-name checkout \
            --key ${{ secrets.BUILDER_KEY }} \
            --products Dockerfile src/* \
            -- echo "checkout complete"
      - name: Build and record
        run: |
          in-toto-run --step-name build \
            --key ${{ secrets.BUILDER_KEY }} \
            --materials Dockerfile src/* \
            --products image-digest.txt \
            -- docker build -t app:${{ github.sha }} .
      - name: Scan and record
        run: |
          in-toto-run --step-name scan \
            --key ${{ secrets.SCANNER_KEY }} \
            --materials image-digest.txt \
            --products vuln-report.json sbom.json \
            -- trivy image app:${{ github.sha }}
      - name: Verify chain
        run: |
          in-toto-verify --layout root.layout \
            --layout-key keys/owner.pub
```

## Key Rotation Workflow

1. Generate new key pair for the functionary
2. Update the supply chain layout with new public key
3. Re-sign the layout with the owner key
4. Distribute new private key to the functionary (via secrets manager)
5. Revoke the old key after transition period
6. Verify builds use new key going forward

## Incident Response Workflow

### Supply Chain Compromise Detected
1. Identify which step's attestation is invalid or missing
2. Check if functionary key was compromised
3. Review link metadata for the affected step
4. Compare artifact hashes against known-good builds
5. If compromise confirmed: revoke affected keys, rebuild from verified source
6. Update layout to add additional verification requirements
