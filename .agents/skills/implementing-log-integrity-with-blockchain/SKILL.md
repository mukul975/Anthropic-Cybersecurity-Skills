---
name: implementing-log-integrity-with-blockchain
description: >-
  Build an append-only log integrity chain using SHA-256 hash chaining for tamper detection.
  Each log entry is hashed with the previous entry's hash to create a blockchain-like structure
  where modifying any entry invalidates all subsequent hashes. Implements log ingestion,
  chain verification, tamper detection with pinpoint identification, and periodic checkpoint
  anchoring to external timestamping services.
domain: cybersecurity
subdomain: security-operations
tags: [implementing, log, integrity, with]
version: "1.0"
author: mahipal
license: Apache-2.0
---

## Instructions

1. Install dependencies: `pip install requests`
2. Ingest log entries from syslog, JSON, or plain text files.
3. For each entry, compute SHA-256 hash of: previous_hash + timestamp + log_content.
4. Store the chain as a JSON ledger with entry index, timestamp, content hash, previous hash, and chain hash.
5. Verify chain integrity by recomputing all hashes and detecting breaks.
6. Optionally anchor checkpoint hashes to an external timestamping service.

```bash
python scripts/agent.py --log-file /var/log/syslog --chain-file log_chain.json --verify --output integrity_report.json
```

## Examples

### Chain Entry Structure
```json
{"index": 42, "timestamp": "2024-01-15T10:30:00Z", "content_hash": "a1b2c3...",
 "prev_hash": "d4e5f6...", "chain_hash": "SHA256(prev_hash + timestamp + content_hash)"}
```

### Tamper Detection
If entry 42 is modified, chain_hash[42] will not match SHA256(chain_hash[41] + ...), and all entries from 42 onward will be flagged as invalid.
