---
name: data-protection
description:
  Designs data protection and privacy controls. Use when designing data classification, DLP, encryption, or data
  governance. Expert in Zero Trust data pillar.
domain: cybersecurity
subdomain: compliance-governance
tags: [data-classification, dlp, encryption, data-governance, zero-trust]
version: "1.0"
author: HRD-Security
license: Apache-2.0
---

# Data Protection Skill

## Overview

You are a data security architect specializing in Zero Trust data protection and privacy controls.
This skill covers data classification, encryption strategies, data loss prevention, privacy compliance,
and key management aligned with Zero Trust data pillar principles.

## Prerequisites

- Understanding of data classification frameworks
- Familiarity with encryption standards and key management
- Knowledge of privacy regulations (GDPR, CCPA)
- Understanding of DLP concepts and tooling

## Key Concepts

### Core Expertise

- **Data Classification**: Sensitivity levels, labeling
- **Encryption**: At rest, in transit, key management
- **DLP**: Data loss prevention policies and enforcement
- **Privacy**: GDPR, CCPA, data minimization
- **Gaming Data**: PCI, player data, gaming records

### Zero Trust Data Principles

#### 1. Know Your Data

- Classify all data by sensitivity
- Understand data flows
- Inventory data stores

#### 2. Protect Data Everywhere

- Encryption at rest and in transit
- Access controls based on classification
- DLP to prevent exfiltration

#### 3. Monitor Data Access

- Log all data access
- Detect anomalous access patterns
- Alert on policy violations

## Practical Steps

### Data Classification Scheme

#### Classification Levels

| Level            | Description         | Examples                  | Controls                         |
| ---------------- | ------------------- | ------------------------- | -------------------------------- |
| **Restricted**   | Maximum sensitivity | PCI data, passwords, keys | Encryption, strict access, audit |
| **Confidential** | High sensitivity    | Player PII, gaming data   | Encryption, role-based access    |
| **Internal**     | Business sensitive  | Internal documents        | Access controls                  |
| **Public**       | No sensitivity      | Marketing materials       | None required                    |

#### Gaming Data Types

| Data Type          | Classification | Regulations         | Retention      |
| ------------------ | -------------- | ------------------- | -------------- |
| Player PII         | Confidential   | GDPR, state privacy | Per regulation |
| Payment data       | Restricted     | PCI DSS             | Per PCI        |
| Betting history    | Confidential   | GLI-33              | 5+ years       |
| Player credentials | Restricted     | Security policy     | N/A (hashed)   |
| Session tokens     | Restricted     | Security policy     | Session only   |
| Audit logs         | Internal       | GLI-19/33           | 5+ years       |

### Data Protection Architecture

#### 1. Sensitivity Labels

```text
Data Protection Platform
├── Sensitivity Labels
│   ├── Restricted
│   ├── Confidential
│   ├── Internal
│   └── Public
├── Data Loss Prevention
│   ├── Endpoint DLP
│   ├── Email DLP
│   ├── Collaboration DLP
│   └── Cloud DLP
├── Information Barriers
│   └── Segment sensitive access
└── Data Lifecycle
    ├── Retention policies
    └── Disposition
```

#### 2. Data Discovery

```text
Data Discovery Platform
├── Data Discovery
│   ├── Cloud data stores
│   ├── SaaS applications
│   └── On-premises data
├── Classification
│   ├── AI-powered classification
│   └── Pattern matching
└── Access Intelligence
    ├── Who has access
    └── Access anomalies
```

#### 3. Encryption Strategy

```text
Encryption at Rest
├── Database (TDE)
├── Storage (Server-side)
│   ├── AWS S3 (SSE-KMS)
│   ├── Azure Blob (CMK)
│   └── GCP GCS (CMEK)
├── Disk (BitLocker/FileVault)
└── Backup (Encrypted)

Encryption in Transit
├── TLS 1.3 everywhere
├── mTLS for services
└── Certificate management
```

### DLP Policy Framework

#### Policy Structure

| Policy          | Scope        | Detection       | Action       |
| --------------- | ------------ | --------------- | ------------ |
| PCI Data        | All channels | Card patterns   | Block, alert |
| SSN/National ID | All channels | ID patterns     | Block, alert |
| Player PII      | External     | Name + Email    | Warn, log    |
| Financial Data  | External     | Account numbers | Warn, log    |
| Source Code     | External     | Code patterns   | Block, alert |

#### DLP Channels

| Channel    | Capability         |
| ---------- | ------------------ |
| Email      | Block/encrypt/warn |
| Chat       | Block/warn         |
| Endpoints  | Block/audit        |
| Cloud Apps | Block/warn         |
| Web        | Filter             |

### PCI DSS Compliance

```text
Cardholder Data Environment (CDE)
├── Network Segmentation
│   └── Isolated payment network
├── Data Storage
│   └── Tokenization (no PANs stored)
├── Transmission
│   └── TLS 1.2+ only
└── Access Control
    └── Minimal access, MFA
```

### Player Data Protection

- Personal information encrypted
- Access logged and monitored
- Consent management
- Data subject requests support
- Retention per regulation

### Gaming Record Integrity

- Immutable audit logs
- Cryptographic verification
- 5+ year retention
- Regulator access support

### Key Management

#### Key Hierarchy

```text
Key Management
├── Master Keys (HSM)
│   ├── AWS KMS
│   └── Azure Key Vault
├── Data Encryption Keys
│   └── Auto-rotated
└── Application Keys
    └── Secrets Manager
```

#### Key Rotation

| Key Type     | Rotation  | Method        |
| ------------ | --------- | ------------- |
| Master keys  | Annual    | Manual        |
| Data keys    | Automatic | Auto-rotation |
| API keys     | 90 days   | Automated     |
| Certificates | 1 year    | Auto-renewal  |

### Data Access Monitoring

#### Access Logging

```text
Data Access Logs
├── Who accessed
├── What was accessed
├── When accessed
├── From where
├── What action
└── Outcome
```

#### Anomaly Detection

- Unusual access volumes
- Access outside hours
- Bulk data exports
- New access patterns
- Geographic anomalies

### Privacy Requirements

#### GDPR Compliance

| Requirement         | Implementation     |
| ------------------- | ------------------ |
| Lawful basis        | Documented consent |
| Data minimization   | Collection review  |
| Storage limitation  | Retention policies |
| Subject rights      | Request process    |
| Breach notification | 72-hour process    |

#### Data Subject Rights

| Right         | Support             |
| ------------- | ------------------- |
| Access        | Self-service portal |
| Rectification | Account update      |
| Erasure       | Deletion process    |
| Portability   | Export function     |
| Objection     | Preference center   |

## Verification

### Data Protection Design Output

```markdown
# Data Protection Architecture

## 1. Data Inventory
[Data types and classifications]

## 2. Classification Scheme
[Levels and criteria]

## 3. Encryption Strategy
[At rest, in transit]

## 4. DLP Policies
[Detection and response]

## 5. Access Controls
[Data-centric access]

## 6. Monitoring
[Access logging, anomaly detection]

## 7. Privacy
[GDPR, consent, rights]

## 8. Zero Trust Alignment
[Data pillar maturity]
```
