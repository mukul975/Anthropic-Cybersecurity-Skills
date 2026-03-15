---
name: performing-threat-modeling-with-owasp-threat-dragon
description: Use OWASP Threat Dragon to create data flow diagrams, identify threats using STRIDE and LINDDUN methodologies, and generate threat model reports for secure design review.
domain: cybersecurity
subdomain: devsecops
tags: [threat-modeling, owasp, threat-dragon, stride, linddun, secure-design, dfd, data-flow]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Threat Modeling with OWASP Threat Dragon

## Overview

OWASP Threat Dragon is an open-source threat modeling tool that enables security teams and developers to create threat model diagrams, identify threats using established methodologies (STRIDE, LINDDUN, CIA, DIE, PLOT4ai), and generate comprehensive reports. Threat Dragon runs as both a web application and desktop application (Windows, macOS, Linux), supporting distributed teams working collaboratively on threat models. Version 2.x provides drag-and-drop diagram creation, an auto-generation rule engine for threats and mitigations, and PDF report output for documentation and GRC compliance.

## Prerequisites

- OWASP Threat Dragon desktop application or web instance
- Understanding of data flow diagram (DFD) notation
- Familiarity with STRIDE or LINDDUN threat classification
- Application architecture documentation and network diagrams
- Stakeholder access for design review sessions

## Threat Modeling Methodologies

### STRIDE

| Category | Threat Type | Description | Example |
|----------|-------------|-------------|---------|
| S | Spoofing | Impersonating a user or system | Stolen session tokens |
| T | Tampering | Modifying data in transit or at rest | SQL injection altering records |
| R | Repudiation | Denying an action occurred | Missing audit logs |
| I | Information Disclosure | Exposing sensitive data | API returning excessive fields |
| D | Denial of Service | Making a service unavailable | Resource exhaustion attack |
| E | Elevation of Privilege | Gaining unauthorized access | Broken access control |

### LINDDUN (Privacy-Focused)

| Category | Threat Type | Description |
|----------|-------------|-------------|
| L | Linkability | Associating data items across contexts |
| I | Identifiability | Identifying an individual from data |
| N | Non-repudiation | Inability to deny an action (privacy risk) |
| D | Detectability | Determining if data about a subject exists |
| D | Disclosure | Exposing personal information |
| U | Unawareness | User unaware of data collection |
| N | Non-compliance | Violating privacy regulations |

## Implementation Steps

### Step 1 --- Install Threat Dragon

**Desktop Application:**
Download the installer from the [OWASP Threat Dragon releases](https://github.com/OWASP/threat-dragon/releases) page for Windows (.exe), macOS (.dmg), or Linux (.AppImage/.deb/.rpm).

**Web Application (Docker):**
```bash
docker run -p 3000:3000 \
  -e ENCRYPTION_JWT_SIGNING_KEY=$(openssl rand -hex 32) \
  -e ENCRYPTION_JWT_REFRESH_SIGNING_KEY=$(openssl rand -hex 32) \
  -e ENCRYPTION_KEYS='[{"isPrimary":true,"id":0,"value":"'$(openssl rand -hex 16)'"}]' \
  -e NODE_ENV=production \
  owasp/threat-dragon:latest
```

### Step 2 --- Define the Scope

Before creating diagrams, document the scope:
- System name and description
- Assets being protected (user data, credentials, payment info)
- External dependencies (third-party APIs, cloud services)
- Compliance requirements (GDPR, HIPAA, PCI DSS)
- Trust boundaries (network segments, authentication zones)

### Step 3 --- Create Data Flow Diagrams

In Threat Dragon, create a new threat model and add diagrams using the following DFD elements:

**Processes**: Applications, microservices, API endpoints that transform data. Represented as circles/rounded rectangles.

**Data Stores**: Databases, file systems, caches, message queues that persist data. Represented as parallel lines.

**External Entities**: Users, external systems, third-party services outside the trust boundary. Represented as rectangles.

**Data Flows**: Communication channels between elements showing data direction. Represented as arrows with labels describing the data.

**Trust Boundaries**: Dashed lines separating zones of different trust levels (internet/DMZ/internal network, user/admin).

### Step 4 --- Identify Threats

For each DFD element, apply the STRIDE methodology:

| Element Type | Applicable STRIDE Categories |
|-------------|------------------------------|
| External Entity | Spoofing, Repudiation |
| Process | Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege |
| Data Store | Tampering, Information Disclosure, DoS |
| Data Flow | Tampering, Information Disclosure, DoS |

Threat Dragon's rule engine automatically suggests threats based on element types. Review each suggestion and mark as:
- **Mitigated**: Existing controls address the threat
- **Not Applicable**: Threat does not apply to this context
- **Open**: Threat needs to be addressed (assign priority and owner)

### Step 5 --- Define Mitigations

For each open threat, document:
- Mitigation strategy (prevent, detect, respond, transfer)
- Specific technical controls (encryption, authentication, rate limiting)
- Owner responsible for implementation
- Priority and timeline for remediation

### Step 6 --- Generate Reports

Threat Dragon produces PDF reports containing:
- Executive summary of the threat model
- Data flow diagrams with annotations
- Threat inventory with severity ratings
- Mitigation status and recommendations
- Compliance mapping where applicable

### Step 7 --- Integrate into SDLC

- Conduct threat modeling during the design phase of new features
- Update threat models when architecture changes occur
- Review threat models during security design reviews
- Store threat model files in version control alongside code
- Reference threat model findings in security acceptance criteria

## Threat Model File Format

Threat Dragon uses JSON format for threat models, enabling version control and programmatic manipulation:

```json
{
  "version": "2.2.0",
  "summary": {
    "title": "E-Commerce Application",
    "owner": "Security Team",
    "description": "Threat model for the checkout flow"
  },
  "detail": {
    "contributors": [
      {"name": "Security Architect"}
    ],
    "diagrams": [
      {
        "id": 0,
        "title": "Checkout Flow",
        "diagramType": "STRIDE",
        "cells": []
      }
    ]
  }
}
```

## CycloneDX TMBOM Integration

Threat Dragon participates in the CycloneDX Threat Model Bill of Materials (TMBOM) effort, enabling export to a common format that can be consumed by other threat modeling tools and GRC platforms, preventing vendor lock-in.

## Best Practices

1. **Start simple**: Begin with high-level DFDs (Level 0) before decomposing into detailed diagrams
2. **Involve developers**: Include development team members in threat modeling sessions for realistic threat assessment
3. **Time-box sessions**: Limit initial sessions to 90 minutes; iterate in follow-up sessions
4. **Prioritize by risk**: Use severity ratings (Critical, High, Medium, Low) to prioritize mitigations
5. **Living documents**: Treat threat models as living documents that evolve with the system
6. **Automate where possible**: Use the rule engine for initial threat generation, then refine manually

## References

- [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/)
- [Threat Dragon GitHub Repository](https://github.com/OWASP/threat-dragon)
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [STRIDE Threat Model](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [LINDDUN Privacy Threat Modeling](https://www.linddun.org/)
