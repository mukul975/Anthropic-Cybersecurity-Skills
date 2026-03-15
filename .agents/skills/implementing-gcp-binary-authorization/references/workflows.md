# Workflows - GCP Binary Authorization

## Attestation Pipeline
```
1. Developer pushes code
2. Cloud Build triggers container build
3. Vulnerability scan runs on built image
4. If scan passes → Create cryptographic attestation
5. Push attested image to registry
6. GKE validates attestation at deploy time
7. Continuous validation monitors running pods
```

## Break-Glass Procedure
```
1. Emergency identified → Create incident ticket
2. Apply break-glass annotation to pod spec
3. Deploy with override documented
4. Alert security team of break-glass usage
5. Post-incident: Review and attest emergency image
6. Remove break-glass annotation
```
