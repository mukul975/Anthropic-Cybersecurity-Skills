# API Reference: Threat Modeling with OWASP Threat Dragon

## Threat Dragon JSON Model Structure

| Field | Description |
|-------|-------------|
| `version` | Threat Dragon version (e.g., "2.2.0") |
| `summary.title` | Threat model name |
| `summary.owner` | Model owner |
| `detail.diagrams[]` | Array of DFD diagrams |
| `detail.diagrams[].cells[]` | DFD elements within a diagram |
| `detail.diagrams[].diagramType` | Methodology (STRIDE, LINDDUN, CIA) |

## DFD Element Types

| Type | Threat Dragon Class | STRIDE Categories |
|------|--------------------|--------------------|
| Process | `tm.Process` | S, T, R, I, D, E |
| Data Store | `tm.Store` | T, I, D |
| Data Flow | `tm.Flow` | T, I, D |
| External Entity | `tm.Actor` | S, R |
| Trust Boundary | `tm.Boundary` | N/A |

## STRIDE Categories

| Letter | Threat | Mitigation |
|--------|--------|------------|
| S | Spoofing | Strong authentication, MFA |
| T | Tampering | Integrity checks, HMAC |
| R | Repudiation | Audit logging |
| I | Information Disclosure | Encryption, least privilege |
| D | Denial of Service | Rate limiting, auto-scaling |
| E | Elevation of Privilege | RBAC, authorization checks |

## Threat Status Values

| Status | Description |
|--------|-------------|
| Open | Threat needs mitigation |
| Mitigated | Controls address the threat |
| Not Applicable | Threat does not apply |

## Docker Deployment

```bash
docker run -p 3000:3000 \
  -e ENCRYPTION_JWT_SIGNING_KEY=$(openssl rand -hex 32) \
  -e ENCRYPTION_JWT_REFRESH_SIGNING_KEY=$(openssl rand -hex 32) \
  owasp/threat-dragon:latest
```

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `json` | stdlib | Threat Dragon model serialization |
| `uuid` | stdlib | Generate unique element IDs |

## References

- OWASP Threat Dragon: https://owasp.org/www-project-threat-dragon/
- Threat Dragon GitHub: https://github.com/OWASP/threat-dragon
- STRIDE Model: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- LINDDUN: https://www.linddun.org/
