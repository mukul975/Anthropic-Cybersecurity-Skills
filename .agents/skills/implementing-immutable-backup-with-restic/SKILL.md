---
name: implementing-immutable-backup-with-restic
description: >
  Implements immutable backup strategy using restic with S3-compatible storage
  and object lock for ransomware-resistant data protection. Automates backup
  creation, integrity verification via restic check --read-data, snapshot
  retention policy enforcement, and restore testing. Integrates with AWS S3
  Object Lock, MinIO, and Backblaze B2 for WORM (Write Once Read Many) storage
  that prevents backup deletion or encryption by ransomware actors.
domain: cybersecurity
subdomain: ransomware-defense
tags: [restic, backup, immutable, ransomware, s3, object-lock, worm, recovery]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Implementing Immutable Backup with Restic

## When to Use

- Establishing ransomware-resistant backup infrastructure with cryptographic integrity verification
- Implementing 3-2-1-1-0 backup strategy where the extra 1 is an immutable copy
- Automating backup verification workflows that test restore capability on a schedule
- Protecting backup repositories from deletion or modification by compromised admin accounts
- Meeting compliance requirements for data retention with tamper-proof storage

**Do not use** as the sole backup solution without also maintaining offline/air-gapped copies. Object lock protects against logical deletion but not physical storage failure.

## Prerequisites

- restic binary installed (https://restic.readthedocs.io/)
- S3-compatible storage with Object Lock enabled (AWS S3, MinIO, Backblaze B2)
- Python 3.8+ with subprocess module
- AWS CLI or MinIO client (mc) configured for bucket access
- Sufficient storage for backup repository (typically 2-3x source data with deduplication)

## Workflow

### Step 1: Initialize Restic Repository with Encryption

Create an encrypted restic repository on S3-compatible storage with object lock enabled. Restic uses AES-256-CTR for encryption with Poly1305-AES for authentication, ensuring backup data is both confidential and tamper-evident.

### Step 2: Configure Object Lock Retention

Enable S3 Object Lock in Compliance mode on the backup bucket to prevent any principal (including root) from deleting or modifying objects during the retention period. Set retention to match your backup window requirements (typically 30-90 days).

### Step 3: Automate Backup and Verification

Schedule backup operations with post-backup integrity verification using `restic check --read-data` which downloads and verifies every data blob against its stored checksum. Log results and alert on any integrity failures.

### Step 4: Test Restore Procedures

Periodically restore random files from backup snapshots to a temporary location and compare checksums against the original to validate end-to-end backup integrity. Document restore times for RTO planning.

## Key Concepts

| Term | Definition |
|------|------------|
| **Object Lock** | S3 feature that prevents object deletion or overwrite for a specified retention period |
| **Compliance Mode** | Object Lock mode where even the root account cannot delete objects before retention expires |
| **Deduplication** | Restic stores data in content-addressable chunks, deduplicating across all snapshots |
| **3-2-1-1-0** | 3 copies, 2 media types, 1 offsite, 1 immutable, 0 errors in verification |

## Tools & Systems

- **restic**: Fast, secure, cross-platform backup tool with built-in encryption and deduplication
- **resticpy**: Python wrapper for restic CLI operations
- **AWS S3 Object Lock**: WORM storage for tamper-proof backup retention
- **MinIO**: Self-hosted S3-compatible storage with Object Lock support

## Output Format

```
BACKUP VERIFICATION REPORT
===========================
Repository: s3:s3.amazonaws.com/company-backups-immutable
Snapshots: 45
Total Size: 2.3 TiB (deduplicated from 8.7 TiB)
Last Backup: 2026-03-11T02:00:00Z
Integrity Check: PASSED (all packs verified)
Object Lock: Compliance mode, 90-day retention
Restore Test: PASSED (15 files verified)
```
