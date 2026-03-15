# SSL Certificate Lifecycle Management Template

## Certificate Inventory Template

| Domain | Type | CA | Issued | Expires | Days Left | Status |
|--------|------|-----|--------|---------|-----------|--------|
| example.com | DV | Let's Encrypt | 2024-01-01 | 2024-04-01 | 90 | OK |
| api.example.com | DV | DigiCert | 2024-01-01 | 2025-01-01 | 365 | OK |

## Monitoring Thresholds

```yaml
monitoring:
  ok_threshold: 30        # days
  warning_threshold: 15   # days
  critical_threshold: 7   # days
  check_interval: 86400   # seconds (daily)
  notification:
    email: security@example.com
    slack: "#cert-alerts"
```

## CSR Generation Command

```bash
# ECDSA (recommended)
openssl ecparam -genkey -name prime256v1 -out server.key
openssl req -new -key server.key -out server.csr -subj "/CN=example.com"

# RSA 4096
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr -subj "/CN=example.com"
```

## Renewal Automation (certbot)

```bash
# Initial issuance
certbot certonly --nginx -d example.com -d www.example.com

# Auto-renewal (cron)
0 0 * * * certbot renew --quiet --deploy-hook "systemctl reload nginx"
```

## Revocation Checklist

- [ ] Identify affected certificate(s)
- [ ] Contact CA to initiate revocation
- [ ] Provide revocation reason (key compromise, cessation, etc.)
- [ ] Verify revocation in CRL/OCSP
- [ ] Issue replacement certificate
- [ ] Deploy replacement to all affected servers
- [ ] Update certificate inventory
- [ ] Document incident
