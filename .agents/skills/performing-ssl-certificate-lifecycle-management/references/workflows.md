# Workflows - SSL Certificate Lifecycle Management

## Workflow 1: Certificate Request and Issuance

```
[Generate Private Key] (ECDSA P-256 or RSA 4096)
      |
[Create CSR] (PKCS#10)
(CN, SAN, Organization, etc.)
      |
[Submit CSR to CA]
      |
[CA Validates Domain/Org]
(DNS, HTTP, or Email challenge)
      |
[CA Issues Certificate]
      |
[Download Certificate + Chain]
      |
[Verify Certificate Chain]
      |
[Deploy to Server]
```

## Workflow 2: Expiration Monitoring

```
[Certificate Inventory] (list of all domains/endpoints)
      |
[For Each Endpoint]:
  [Connect and retrieve certificate]
  [Parse notAfter field]
  [Calculate days remaining]
      |
[Apply Threshold Rules]:
  > 30 days: OK
  15-30 days: WARNING
  < 15 days: CRITICAL
  Expired: ALERT
      |
[Generate Report / Send Alerts]
```

## Workflow 3: Automated Renewal (ACME)

```
[Cron Job / Scheduler]
      |
[Check Certificate Expiry]
      |
[< 30 days remaining?]
  NO  --> Sleep
  YES --> [Initiate ACME Renewal]
              |
          [Complete Challenge]
          (HTTP-01, DNS-01, TLS-ALPN-01)
              |
          [Receive New Certificate]
              |
          [Deploy and Reload Server]
              |
          [Verify New Certificate Works]
```

## Workflow 4: Certificate Revocation

```
[Security Incident Detected]
(key compromise, CA breach, etc.)
      |
[Revoke Certificate with CA]
(provide reason code)
      |
[Verify in CRL / OCSP]
      |
[Issue Replacement Certificate]
      |
[Deploy Replacement]
      |
[Update Certificate Inventory]
```
