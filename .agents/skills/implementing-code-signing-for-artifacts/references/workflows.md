# Workflow Reference: Code Signing for Artifacts

## Signing Pipeline Flow

```
Build Artifacts
       │
       ▼
┌──────────────────┐
│ Generate          │
│ Checksums         │
└──────┬───────────┘
       │
       ├──────────────────────┐
       ▼                      ▼
┌──────────────┐    ┌──────────────┐
│ GPG Sign     │    │ Sigstore     │
│ (detached)   │    │ Keyless Sign │
└──────┬───────┘    └──────┬───────┘
       │                    │
       │                    ▼
       │            ┌──────────────┐
       │            │ Rekor Log    │
       │            │ Entry        │
       │            └──────┬───────┘
       │                    │
       └──────────┬─────────┘
                  ▼
       ┌──────────────────┐
       │ Publish Release  │
       │ + Signatures     │
       └──────────────────┘
```

## Signing Methods Comparison

| Method | Key Management | Identity | Verification | Best For |
|--------|---------------|----------|--------------|----------|
| GPG | Manual key lifecycle | Key fingerprint | gpg --verify | Traditional projects |
| Sigstore Keyless | No keys to manage | OIDC identity | cosign verify-blob | Modern CI/CD |
| Code Signing Cert | CA-issued certificate | Organization name | Platform-specific | Windows/macOS apps |
| npm Provenance | Automated | GitHub Actions OIDC | npm audit signatures | npm packages |
