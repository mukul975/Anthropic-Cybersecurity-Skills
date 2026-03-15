---
name: implementing-api-security-posture-management
description: Implement API Security Posture Management to continuously discover, classify, and score APIs based on risk while enforcing security policies across the API lifecycle.
domain: cybersecurity
subdomain: api-security
tags: [api-security, aspm, api-posture-management, api-discovery, risk-scoring, api-governance, continuous-monitoring, api-inventory]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing API Security Posture Management

## Overview

API Security Posture Management (API-SPM) provides continuous visibility into an organization's API attack surface by automatically discovering, classifying, and risk-scoring all APIs including internal, external, partner, and shadow endpoints. Unlike point-in-time testing tools, API-SPM operates continuously to detect configuration drift, policy violations, missing security controls, sensitive data exposure, and compliance gaps. It aggregates findings from DAST, SAST, SCA, and runtime monitoring tools to provide a unified view of API risk posture across the organization.

## Prerequisites

- API gateway with traffic logging (Kong, AWS API Gateway, Apigee, Envoy)
- OpenAPI specifications for documented APIs
- SIEM or log aggregation platform (Splunk, Elastic)
- CI/CD pipeline access for shift-left integration
- Cloud provider APIs for infrastructure discovery
- Python 3.8+ for custom posture assessment tooling

## Core Components

### 1. API Discovery and Inventory

```python
#!/usr/bin/env python3
"""API Security Posture Management Engine

Continuously discovers, classifies, and risk-scores APIs
to maintain a comprehensive security posture inventory.
"""

import json
import re
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

class APIClassification(Enum):
    EXTERNAL = "external"
    INTERNAL = "internal"
    PARTNER = "partner"
    SHADOW = "shadow"
    DEPRECATED = "deprecated"

class RiskLevel(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

@dataclass
class SecurityControl:
    name: str
    present: bool
    required: bool
    severity: RiskLevel
    details: str = ""

@dataclass
class APIEndpoint:
    api_id: str
    method: str
    path: str
    service_name: str
    classification: APIClassification
    owner: Optional[str] = None
    version: Optional[str] = None
    first_discovered: str = ""
    last_seen: str = ""
    documented: bool = False
    security_controls: List[SecurityControl] = field(default_factory=list)
    risk_score: float = 0.0
    sensitive_data_types: Set[str] = field(default_factory=set)
    compliance_tags: Set[str] = field(default_factory=set)
    traffic_volume_daily: int = 0

class APIPostureManager:
    SENSITIVE_PATTERNS = {
        "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        "credit_card": re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'),
        "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        "api_key": re.compile(r'\b[A-Za-z0-9]{32,}\b'),
        "jwt": re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
        "phone": re.compile(r'\b\+?1?\d{10,15}\b'),
    }

    def __init__(self):
        self.inventory: Dict[str, APIEndpoint] = {}
        self.policy_rules: List[dict] = []

    def generate_api_id(self, method: str, path: str, service: str) -> str:
        raw = f"{service}:{method}:{path}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def register_api(self, method: str, path: str, service_name: str,
                     classification: APIClassification,
                     documented: bool = False, owner: str = None) -> APIEndpoint:
        api_id = self.generate_api_id(method, path, service_name)
        now = datetime.now().isoformat()

        if api_id in self.inventory:
            endpoint = self.inventory[api_id]
            endpoint.last_seen = now
            return endpoint

        endpoint = APIEndpoint(
            api_id=api_id,
            method=method,
            path=path,
            service_name=service_name,
            classification=classification,
            owner=owner,
            first_discovered=now,
            last_seen=now,
            documented=documented
        )
        self.inventory[api_id] = endpoint
        return endpoint

    def assess_security_controls(self, endpoint: APIEndpoint,
                                  traffic_sample: dict) -> List[SecurityControl]:
        """Evaluate security controls present on an API endpoint."""
        controls = []

        # Authentication check
        has_auth = any(h in traffic_sample.get('request_headers', {})
                      for h in ['Authorization', 'X-API-Key', 'Cookie'])
        controls.append(SecurityControl(
            name="authentication",
            present=has_auth,
            required=True,
            severity=RiskLevel.CRITICAL,
            details="No authentication mechanism detected" if not has_auth else "Authentication present"
        ))

        # TLS/HTTPS check
        is_https = traffic_sample.get('scheme', '').lower() == 'https'
        controls.append(SecurityControl(
            name="transport_encryption",
            present=is_https,
            required=True,
            severity=RiskLevel.CRITICAL,
            details="API accessible over HTTP without TLS" if not is_https else "HTTPS enforced"
        ))

        # Rate limiting check
        has_rate_limit = any(h.startswith('X-RateLimit') or h == 'Retry-After'
                           for h in traffic_sample.get('response_headers', {}).keys())
        controls.append(SecurityControl(
            name="rate_limiting",
            present=has_rate_limit,
            required=True,
            severity=RiskLevel.HIGH,
            details="No rate limiting headers detected" if not has_rate_limit else "Rate limiting active"
        ))

        # CORS policy check
        cors_origin = traffic_sample.get('response_headers', {}).get('Access-Control-Allow-Origin', '')
        has_strict_cors = cors_origin and cors_origin != '*'
        controls.append(SecurityControl(
            name="cors_policy",
            present=has_strict_cors,
            required=endpoint.classification == APIClassification.EXTERNAL,
            severity=RiskLevel.HIGH if cors_origin == '*' else RiskLevel.MEDIUM,
            details=f"CORS origin: {cors_origin}" if cors_origin else "No CORS headers"
        ))

        # Security headers
        sec_headers = traffic_sample.get('response_headers', {})
        required_headers = {
            'X-Content-Type-Options': 'nosniff',
            'Strict-Transport-Security': None,
            'X-Frame-Options': None,
            'Cache-Control': 'no-store',
        }
        missing = [h for h in required_headers if h not in sec_headers]
        controls.append(SecurityControl(
            name="security_headers",
            present=len(missing) == 0,
            required=True,
            severity=RiskLevel.MEDIUM,
            details=f"Missing headers: {', '.join(missing)}" if missing else "All security headers present"
        ))

        # Input validation (check for schema validation errors in logs)
        has_validation = traffic_sample.get('has_schema_validation', False)
        controls.append(SecurityControl(
            name="input_validation",
            present=has_validation,
            required=True,
            severity=RiskLevel.HIGH,
            details="No schema validation detected" if not has_validation else "Input validation active"
        ))

        endpoint.security_controls = controls
        return controls

    def calculate_risk_score(self, endpoint: APIEndpoint) -> float:
        """Calculate a composite risk score (0-100) for an API endpoint."""
        score = 0.0
        max_score = 0.0

        # Security controls scoring
        for control in endpoint.security_controls:
            weight = control.severity.value * 5
            max_score += weight
            if not control.present and control.required:
                score += weight

        # Classification risk multiplier
        classification_weights = {
            APIClassification.EXTERNAL: 1.5,
            APIClassification.PARTNER: 1.3,
            APIClassification.SHADOW: 2.0,
            APIClassification.DEPRECATED: 1.8,
            APIClassification.INTERNAL: 1.0,
        }
        multiplier = classification_weights.get(endpoint.classification, 1.0)

        # Documentation penalty
        if not endpoint.documented:
            score += 10

        # Sensitive data penalty
        score += len(endpoint.sensitive_data_types) * 5

        # Normalize to 0-100
        if max_score > 0:
            normalized = min(100, (score / max_score) * 100 * multiplier)
        else:
            normalized = 0

        endpoint.risk_score = round(normalized, 1)
        return endpoint.risk_score

    def generate_posture_report(self) -> dict:
        """Generate organization-wide API security posture report."""
        total = len(self.inventory)
        if total == 0:
            return {"error": "No APIs in inventory"}

        risk_distribution = {level.name: 0 for level in RiskLevel}
        classification_counts = {c.value: 0 for c in APIClassification}
        undocumented = 0
        missing_auth = 0
        missing_tls = 0

        for endpoint in self.inventory.values():
            self.calculate_risk_score(endpoint)

            if endpoint.risk_score >= 75:
                risk_distribution["CRITICAL"] += 1
            elif endpoint.risk_score >= 50:
                risk_distribution["HIGH"] += 1
            elif endpoint.risk_score >= 25:
                risk_distribution["MEDIUM"] += 1
            else:
                risk_distribution["LOW"] += 1

            classification_counts[endpoint.classification.value] += 1

            if not endpoint.documented:
                undocumented += 1

            for control in endpoint.security_controls:
                if control.name == "authentication" and not control.present:
                    missing_auth += 1
                if control.name == "transport_encryption" and not control.present:
                    missing_tls += 1

        avg_risk = sum(e.risk_score for e in self.inventory.values()) / total

        return {
            "report_date": datetime.now().isoformat(),
            "total_apis": total,
            "average_risk_score": round(avg_risk, 1),
            "risk_distribution": risk_distribution,
            "classification": classification_counts,
            "undocumented_apis": undocumented,
            "missing_authentication": missing_auth,
            "missing_tls": missing_tls,
            "top_risks": sorted(
                [{"api_id": e.api_id, "method": e.method, "path": e.path,
                  "service": e.service_name, "risk_score": e.risk_score,
                  "classification": e.classification.value}
                 for e in self.inventory.values()],
                key=lambda x: x["risk_score"],
                reverse=True
            )[:20]
        }
```

### 2. Policy Enforcement

Define and enforce security policies across all APIs:

```yaml
# api-security-policies.yaml
policies:
  - name: require-authentication
    description: All external APIs must require authentication
    scope:
      classification: [external, partner]
    rule:
      control: authentication
      required: true
    severity: critical
    remediation: "Add OAuth2, API key, or JWT authentication"

  - name: enforce-tls
    description: All APIs must use HTTPS
    scope:
      classification: [external, internal, partner]
    rule:
      control: transport_encryption
      required: true
    severity: critical
    remediation: "Configure TLS certificates and redirect HTTP to HTTPS"

  - name: require-rate-limiting
    description: External APIs must implement rate limiting
    scope:
      classification: [external]
    rule:
      control: rate_limiting
      required: true
    severity: high
    remediation: "Configure rate limiting at API gateway level"

  - name: no-wildcard-cors
    description: APIs must not use wildcard CORS origins
    scope:
      classification: [external]
    rule:
      control: cors_policy
      condition: "origin != '*'"
    severity: high
    remediation: "Specify explicit allowed origins in CORS configuration"

  - name: documentation-required
    description: All APIs must have OpenAPI documentation
    scope:
      classification: [external, partner]
    rule:
      documented: true
    severity: medium
    remediation: "Create and publish OpenAPI specification"

  - name: deprecation-sunset
    description: Deprecated APIs must have sunset headers
    scope:
      classification: [deprecated]
    rule:
      header_present: "Sunset"
    severity: medium
    remediation: "Add Sunset header with planned removal date"
```

## Continuous Monitoring Dashboard Metrics

| Metric | Description | Target |
|--------|------------|--------|
| API Discovery Coverage | % of APIs with documentation | > 95% |
| Average Risk Score | Mean risk score across all APIs | < 25 |
| Critical Findings | Number of critical-risk APIs | 0 |
| Shadow API Count | Undocumented/unmanaged APIs | 0 |
| Authentication Coverage | % of APIs with auth controls | 100% |
| TLS Coverage | % of APIs using HTTPS | 100% |
| Policy Compliance | % of APIs meeting all policies | > 90% |
| Mean Time to Remediate | Average days to fix findings | < 7 days |

## References

- OX Security ASPM Guide 2025: https://www.ox.security/blog/application-security-posture-management-aspm/
- IBM ASPM Overview: https://www.ibm.com/think/topics/aspm
- StackHawk Best ASPM Tools: https://www.stackhawk.com/blog/best-aspm-tools/
- AppSentinels API Security Posture Management: https://appsentinels.ai/blog/api-security-posture-management-from-reactive-protection-to-continuous-governance/
- Palo Alto Networks ASPM: https://www.paloaltonetworks.com/cyberpedia/aspm-application-security-posture-management
