# Workflows: Analyzing Phishing Email Headers

## Workflow 1: Rapid Header Triage

```
START: Suspicious email reported
  |
  v
[Extract raw headers from email client]
  |
  v
[Check Authentication-Results header]
  |
  +-- SPF=pass, DKIM=pass, DMARC=pass --> Lower suspicion, check content
  |
  +-- Any FAIL --> High suspicion
       |
       v
  [Compare From vs Return-Path vs Reply-To]
       |
       +-- All match --> Check Received chain
       +-- Mismatch --> LIKELY PHISHING - escalate
            |
            v
       [Document findings, block sender, alert SOC]
```

## Workflow 2: Full Header Forensic Analysis

### Phase 1: Collection
1. Obtain raw email source (.eml file or copy full headers)
2. Preserve original message with headers as evidence
3. Calculate hash of original .eml file for chain of custody

### Phase 2: Authentication Analysis
1. Extract SPF result from Authentication-Results
2. Verify SPF by querying sender domain's TXT record: `dig TXT _spf.example.com`
3. Extract DKIM result and verify signature domain
4. Check DMARC alignment (identifier alignment between SPF/DKIM and From domain)
5. Document all authentication pass/fail results

### Phase 3: Route Analysis
1. Parse all Received headers (bottom to top)
2. For each hop:
   - Extract server hostname and IP
   - Note timestamp
   - Calculate time delta between hops
3. Flag any:
   - Unexpected relay servers
   - Geographic anomalies (IP in unexpected country)
   - Excessive delays (possible queuing for mass send)
   - Internal-only hostnames appearing in external mail

### Phase 4: Sender Investigation
1. WHOIS lookup on sending domain
   - Domain age < 30 days = high risk
   - Registrar known for abuse = medium risk
2. Reverse DNS on originating IP
3. AbuseIPDB / VirusTotal lookup on originating IP
4. Check if sending domain appears in known phishing feeds

### Phase 5: Indicator Extraction
1. Extract all URLs from message body and headers
2. Extract all IP addresses from Received chain
3. Extract domain names from all relevant fields
4. Create IOC list for threat intelligence platform

## Workflow 3: Automated Pipeline

```
Email received --> MTA logs header -->
  SIEM ingestion -->
    Automated header parsing -->
      Authentication check -->
        IF fail: Create alert + enrich with TI -->
          SOC analyst review -->
            Confirm/dismiss -->
              IF confirmed: Block + hunt similar
```

## Decision Matrix

| Authentication | Route | Sender Rep | Action |
|---|---|---|---|
| All Pass | Normal | Good | Deliver normally |
| SPF Fail | Normal | Good | Quarantine, investigate |
| DKIM Fail | Normal | Unknown | Quarantine, investigate |
| DMARC Fail | Anomalous | Bad | Block, create IOC |
| All Fail | Anomalous | Bad | Block, escalate, hunt |
