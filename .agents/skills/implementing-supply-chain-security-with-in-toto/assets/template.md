# in-toto Supply Chain Security Assessment Template

## Project Information

| Field | Value |
|-------|-------|
| Project Name | |
| Repository | |
| Container Registry | |
| in-toto Version | |
| Assessment Date | |
| Assessed By | |

## Supply Chain Layout

### Pipeline Steps

| Step | Functionary | Key Type | Threshold | Artifacts |
|------|-------------|----------|-----------|-----------|
| checkout | | | | |
| build | | | | |
| test | | | | |
| scan | | | | |
| push | | | | |

### Key Management

- [ ] Signing keys generated for all functionaries
- [ ] Keys stored in secrets manager (Vault, KMS)
- [ ] Key rotation schedule defined
- [ ] Layout signed by project owner key
- [ ] Backup keys secured offline

## Verification Checklist

- [ ] All required steps produce link metadata
- [ ] Artifact hashes chain correctly between steps
- [ ] Signatures verified against trusted functionaries
- [ ] Inspections pass (no critical vulnerabilities)
- [ ] Layout expiration date is current

## SLSA Compliance

| Level | Requirement | Status |
|-------|-------------|--------|
| L1 | Build process documented | |
| L2 | Signed provenance from hosted build | |
| L3 | Hardened build platform | |
| L4 | Two-party review + hermetic build | |

## Sign-Off

| Role | Name | Date |
|------|------|------|
| Security Engineer | | |
| Release Manager | | |
