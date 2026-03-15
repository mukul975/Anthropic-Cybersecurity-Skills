---
name: detecting-broken-object-property-level-authorization
description: Detect and test for OWASP API3:2023 Broken Object Property Level Authorization vulnerabilities including excessive data exposure and mass assignment attacks.
domain: cybersecurity
subdomain: api-security
tags: [api-security, bopla, owasp-api3, mass-assignment, excessive-data-exposure, property-level-authorization, api-testing, penetration-testing]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting Broken Object Property Level Authorization

## Overview

Broken Object Property Level Authorization (BOPLA), classified as API3:2023 in the OWASP API Security Top 10, combines two related vulnerability classes: Excessive Data Exposure (API returning more data than needed) and Mass Assignment (API accepting more data than intended). Even when APIs enforce object-level authorization correctly, they may fail to control which specific properties of an object a user can read or modify. Attackers exploit this by reading sensitive properties from API responses or injecting additional properties into request bodies to modify fields they should not have access to.

## Prerequisites

- Target API with endpoints that return or accept object data
- API documentation or schema (OpenAPI spec preferred)
- Burp Suite or Postman for API request manipulation
- Multiple user accounts with different privilege levels
- Python 3.8+ with requests library for automated testing
- Authorization to perform security testing

## Vulnerability Patterns

### Excessive Data Exposure

The API returns object properties the client does not need:

```json
// GET /api/v1/users/123
// Response includes sensitive fields the UI doesn't display:
{
  "id": 123,
  "username": "john_doe",
  "email": "john@example.com",
  "name": "John Doe",
  "ssn": "123-45-6789",           // Sensitive - not needed by UI
  "salary": 95000,                 // Sensitive - not needed by UI
  "internal_notes": "VIP client",  // Internal - should not be exposed
  "password_hash": "$2b$12...",    // Critical - never expose
  "role": "admin",                 // May enable privilege discovery
  "created_by": "system_admin",   // Internal metadata
  "credit_card_last4": "4242"     // PCI compliance violation
}
```

### Mass Assignment

The API binds client-supplied data to internal object properties without filtering:

```http
// Normal user update request
PUT /api/v1/users/123
Content-Type: application/json

{
  "name": "John Updated",
  "email": "new@example.com",
  "role": "admin",           // Attacker-injected: privilege escalation
  "is_verified": true,       // Attacker-injected: bypass verification
  "discount_rate": 100,      // Attacker-injected: business logic abuse
  "account_balance": 999999  // Attacker-injected: financial fraud
}
```

## Testing Methodology

```python
#!/usr/bin/env python3
"""BOPLA Vulnerability Scanner

Tests APIs for Broken Object Property Level Authorization
including Excessive Data Exposure and Mass Assignment.
"""

import requests
import json
import sys
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from copy import deepcopy

@dataclass
class BOPLAFinding:
    endpoint: str
    method: str
    vulnerability_type: str  # "excessive_exposure" or "mass_assignment"
    severity: str
    property_name: str
    details: str

class BOPLAScanner:
    SENSITIVE_PROPERTY_PATTERNS = {
        "critical": [
            "password", "password_hash", "secret", "token", "api_key",
            "private_key", "secret_key", "access_token", "refresh_token",
        ],
        "high": [
            "ssn", "social_security", "tax_id", "credit_card", "card_number",
            "cvv", "bank_account", "routing_number",
        ],
        "medium": [
            "salary", "income", "internal_notes", "admin_notes",
            "created_by", "modified_by", "ip_address", "session_id",
            "role", "permissions", "is_admin", "is_superuser", "privilege",
        ],
        "low": [
            "phone", "address", "date_of_birth", "dob", "age",
            "gender", "ethnicity", "religion",
        ]
    }

    MASS_ASSIGNMENT_FIELDS = [
        ("role", "admin"),
        ("is_admin", True),
        ("is_verified", True),
        ("is_active", True),
        ("email_verified", True),
        ("account_type", "premium"),
        ("discount_rate", 100),
        ("credit_limit", 999999),
        ("permissions", ["admin", "write", "delete"]),
        ("account_balance", 999999),
        ("subscription_tier", "enterprise"),
        ("rate_limit", 999999),
    ]

    def __init__(self, base_url: str, auth_headers: Dict[str, str]):
        self.base_url = base_url.rstrip('/')
        self.auth_headers = auth_headers
        self.findings: List[BOPLAFinding] = []

    def test_excessive_data_exposure(self, endpoint: str,
                                      expected_fields: Set[str]) -> List[BOPLAFinding]:
        """Test if API response contains more fields than expected."""
        findings = []
        url = f"{self.base_url}{endpoint}"

        try:
            response = requests.get(url, headers=self.auth_headers, timeout=10)
            if response.status_code != 200:
                return findings

            data = response.json()

            # Handle both single object and list responses
            objects = data if isinstance(data, list) else [data]
            if isinstance(data, dict) and "data" in data:
                objects = data["data"] if isinstance(data["data"], list) else [data["data"]]

            for obj in objects[:5]:  # Check first 5 objects
                if not isinstance(obj, dict):
                    continue

                response_fields = set(self._flatten_keys(obj))
                unexpected_fields = response_fields - expected_fields

                for field_name in unexpected_fields:
                    severity = self._classify_sensitivity(field_name)
                    if severity:
                        finding = BOPLAFinding(
                            endpoint=endpoint,
                            method="GET",
                            vulnerability_type="excessive_exposure",
                            severity=severity,
                            property_name=field_name,
                            details=f"Unexpected sensitive field '{field_name}' in response"
                        )
                        findings.append(finding)
                        self.findings.append(finding)

        except (requests.exceptions.RequestException, json.JSONDecodeError):
            pass

        return findings

    def test_mass_assignment(self, endpoint: str, method: str = "PUT",
                              original_data: Optional[dict] = None) -> List[BOPLAFinding]:
        """Test if API accepts and processes additional injected properties."""
        findings = []
        url = f"{self.base_url}{endpoint}"

        # First, get the current object state
        if original_data is None:
            try:
                response = requests.get(url, headers=self.auth_headers, timeout=10)
                if response.status_code == 200:
                    original_data = response.json()
                else:
                    original_data = {}
            except (requests.exceptions.RequestException, json.JSONDecodeError):
                original_data = {}

        # Test each mass assignment field
        for field_name, injected_value in self.MASS_ASSIGNMENT_FIELDS:
            if field_name in original_data:
                # Field exists - test if we can modify it
                original_value = original_data[field_name]
                if original_value == injected_value:
                    continue  # Already has this value

            test_data = deepcopy(original_data)
            test_data[field_name] = injected_value

            headers = {**self.auth_headers, "Content-Type": "application/json"}

            try:
                if method == "PUT":
                    response = requests.put(url, json=test_data,
                                          headers=headers, timeout=10)
                elif method == "PATCH":
                    response = requests.patch(url, json={field_name: injected_value},
                                            headers=headers, timeout=10)
                elif method == "POST":
                    response = requests.post(url, json=test_data,
                                           headers=headers, timeout=10)

                if response.status_code in (200, 201, 204):
                    # Verify the field was actually modified
                    verify_response = requests.get(url, headers=self.auth_headers, timeout=10)
                    if verify_response.status_code == 200:
                        updated_data = verify_response.json()
                        if updated_data.get(field_name) == injected_value:
                            finding = BOPLAFinding(
                                endpoint=endpoint,
                                method=method,
                                vulnerability_type="mass_assignment",
                                severity="CRITICAL" if field_name in ["role", "is_admin", "permissions"]
                                         else "HIGH",
                                property_name=field_name,
                                details=f"Successfully injected '{field_name}={injected_value}'"
                            )
                            findings.append(finding)
                            self.findings.append(finding)

                            # Restore original value if possible
                            if field_name in original_data:
                                restore_data = {field_name: original_data[field_name]}
                                requests.patch(url, json=restore_data,
                                             headers=headers, timeout=10)

            except requests.exceptions.RequestException:
                continue

        return findings

    def test_graphql_property_exposure(self, graphql_endpoint: str,
                                        query: str) -> List[BOPLAFinding]:
        """Test GraphQL APIs for property-level authorization issues."""
        findings = []
        url = f"{self.base_url}{graphql_endpoint}"

        # Introspection query to discover available fields
        introspection = """
        {
          __schema {
            types {
              name
              fields {
                name
                type { name kind }
              }
            }
          }
        }
        """

        try:
            response = requests.post(
                url,
                json={"query": introspection},
                headers=self.auth_headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                if "errors" not in data:
                    finding = BOPLAFinding(
                        endpoint=graphql_endpoint,
                        method="POST",
                        vulnerability_type="excessive_exposure",
                        severity="MEDIUM",
                        property_name="__schema",
                        details="GraphQL introspection enabled - full schema exposed"
                    )
                    findings.append(finding)
                    self.findings.append(finding)

        except requests.exceptions.RequestException:
            pass

        return findings

    def _flatten_keys(self, obj: dict, prefix: str = "") -> List[str]:
        """Recursively flatten nested dictionary keys."""
        keys = []
        for key, value in obj.items():
            full_key = f"{prefix}.{key}" if prefix else key
            keys.append(full_key)
            if isinstance(value, dict):
                keys.extend(self._flatten_keys(value, full_key))
        return keys

    def _classify_sensitivity(self, field_name: str) -> Optional[str]:
        """Classify the sensitivity level of a field name."""
        lower_name = field_name.lower().split('.')[-1]
        for severity, patterns in self.SENSITIVE_PROPERTY_PATTERNS.items():
            for pattern in patterns:
                if pattern in lower_name:
                    return severity.upper()
        return None

    def generate_report(self) -> dict:
        return {
            "total_findings": len(self.findings),
            "by_type": {
                "excessive_exposure": len([f for f in self.findings
                                          if f.vulnerability_type == "excessive_exposure"]),
                "mass_assignment": len([f for f in self.findings
                                       if f.vulnerability_type == "mass_assignment"]),
            },
            "by_severity": {
                "CRITICAL": len([f for f in self.findings if f.severity == "CRITICAL"]),
                "HIGH": len([f for f in self.findings if f.severity == "HIGH"]),
                "MEDIUM": len([f for f in self.findings if f.severity == "MEDIUM"]),
                "LOW": len([f for f in self.findings if f.severity == "LOW"]),
            },
            "findings": [
                {
                    "endpoint": f.endpoint,
                    "method": f.method,
                    "type": f.vulnerability_type,
                    "severity": f.severity,
                    "property": f.property_name,
                    "details": f.details,
                }
                for f in self.findings
            ]
        }
```

## Mitigation

```python
# Server-side: Explicit property allowlists
class UserSerializer:
    # Only expose these fields - never use to_json() or to_dict()
    PUBLIC_FIELDS = ['id', 'username', 'name', 'avatar_url']
    OWNER_FIELDS = PUBLIC_FIELDS + ['email', 'phone', 'preferences']
    ADMIN_FIELDS = OWNER_FIELDS + ['role', 'created_at', 'last_login']

    def serialize(self, user, requesting_user):
        if requesting_user.is_admin:
            fields = self.ADMIN_FIELDS
        elif requesting_user.id == user.id:
            fields = self.OWNER_FIELDS
        else:
            fields = self.PUBLIC_FIELDS

        return {field: getattr(user, field) for field in fields}

# Mass assignment protection - explicit allowlist for writable fields
WRITABLE_FIELDS = {'name', 'email', 'phone', 'avatar_url', 'preferences'}

def update_user(user_id, request_data, requesting_user):
    # Filter out any fields not in the allowlist
    safe_data = {k: v for k, v in request_data.items() if k in WRITABLE_FIELDS}
    # Apply updates only with safe data
    User.objects.filter(id=user_id).update(**safe_data)
```

## References

- OWASP API3:2023: https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- Salt Security BOPLA Analysis: https://salt.security/blog/api3-2023-broken-object-property-level-authorization
- Wallarm BOPLA Guide: https://lab.wallarm.com/api32023-broken-object-property-level-authorization/
- API Security News BOPLA: https://apisecurity.io/owasp-api-security-top-10/api3-2023-broken-object-property-level-authorization/
- CloudDefense BOPLA: https://www.clouddefense.ai/owasp/2023/3
