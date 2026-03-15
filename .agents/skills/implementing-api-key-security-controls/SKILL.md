---
name: implementing-api-key-security-controls
description: >
  Implements secure API key generation, storage, rotation, and revocation controls to protect
  API authentication credentials from leakage, brute force, and abuse. The engineer designs
  API key formats with sufficient entropy, implements secure hashing for storage, enforces
  per-key scoping and rate limiting, monitors for leaked keys in public repositories, and
  builds key rotation workflows. Activates for requests involving API key management, API
  key security, key rotation policy, or API credential protection.
domain: cybersecurity
subdomain: api-security
tags: [api-security, api-keys, credential-management, key-rotation, secret-management]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Implementing API Key Security Controls

## When to Use

- Designing secure API key generation with sufficient entropy and identifiable prefixes for leak detection
- Implementing server-side API key hashing (never storing keys in plaintext) with SHA-256 or bcrypt
- Building key rotation workflows that allow zero-downtime key replacement for API consumers
- Configuring per-key scoping to limit each API key to specific endpoints, IP ranges, and rate limits
- Setting up automated monitoring for API key leakage in GitHub repos, logs, and client-side code

**Do not use** API keys as the sole authentication mechanism for user-facing applications. API keys are best suited for server-to-server communication and developer access.

## Prerequisites

- Secure random number generator (os.urandom, secrets module) for key generation
- Database with proper encryption at rest for storing hashed API keys
- Redis or similar store for key-to-metadata caching and rate limiting
- Secret scanning tools (GitHub secret scanning, truffleHog, gitleaks)
- Monitoring and alerting infrastructure for key usage anomalies

## Workflow

### Step 1: Secure API Key Generation

```python
import secrets
import hashlib
import hmac
import time
import json
from datetime import datetime, timedelta

class APIKeyManager:
    """Manages secure API key lifecycle: generation, storage, validation, rotation."""

    # Key format: prefix_base64random (e.g., sk_live_a1b2c3d4e5f6...)
    # Prefix identifies the key type and environment for leak detection
    KEY_PREFIXES = {
        "live_secret": "sk_live_",
        "test_secret": "sk_test_",
        "live_public": "pk_live_",
        "test_public": "pk_test_",
    }

    def __init__(self, db_connection, redis_connection):
        self.db = db_connection
        self.redis = redis_connection

    def generate_key(self, key_type="live_secret", owner_id=None, scopes=None,
                     rate_limit=None, ip_allowlist=None, expires_days=365):
        """Generate a new API key with metadata."""
        prefix = self.KEY_PREFIXES.get(key_type, "sk_live_")

        # Generate 32 bytes (256 bits) of randomness
        random_bytes = secrets.token_bytes(32)
        key_body = secrets.token_urlsafe(32)  # Base64url-encoded

        # Full API key that the client receives (shown only once)
        full_key = f"{prefix}{key_body}"

        # Hash the key for storage (never store the raw key)
        key_hash = hashlib.sha256(full_key.encode()).hexdigest()

        # Create a short key ID for reference (first 8 chars)
        key_id = f"{prefix}{key_body[:8]}..."

        # Store the hashed key with metadata
        key_metadata = {
            "key_hash": key_hash,
            "key_id": key_id,
            "key_type": key_type,
            "owner_id": owner_id,
            "scopes": scopes or ["read"],
            "rate_limit": rate_limit or {"requests": 1000, "window": 3600},
            "ip_allowlist": ip_allowlist or [],
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(days=expires_days)).isoformat(),
            "last_used": None,
            "is_active": True,
            "usage_count": 0,
        }

        # Store in database
        self.db.execute(
            "INSERT INTO api_keys (key_hash, key_id, metadata) VALUES (?, ?, ?)",
            (key_hash, key_id, json.dumps(key_metadata))
        )

        # Cache in Redis for fast validation
        self.redis.setex(
            f"apikey:{key_hash}",
            86400,  # 24-hour cache TTL
            json.dumps(key_metadata)
        )

        return {
            "api_key": full_key,       # Show to user ONCE
            "key_id": key_id,          # For reference/management
            "scopes": key_metadata["scopes"],
            "expires_at": key_metadata["expires_at"],
        }

    def validate_key(self, api_key):
        """Validate an API key and return its metadata."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        # Check Redis cache first
        cached = self.redis.get(f"apikey:{key_hash}")
        if cached:
            metadata = json.loads(cached)
        else:
            # Fall back to database
            row = self.db.execute(
                "SELECT metadata FROM api_keys WHERE key_hash = ?",
                (key_hash,)
            ).fetchone()
            if not row:
                return None, "invalid_key"
            metadata = json.loads(row[0])
            # Refresh cache
            self.redis.setex(f"apikey:{key_hash}", 86400, row[0])

        # Validation checks
        if not metadata.get("is_active"):
            return None, "key_revoked"

        if metadata.get("expires_at"):
            if datetime.fromisoformat(metadata["expires_at"]) < datetime.utcnow():
                return None, "key_expired"

        # Update last used
        metadata["last_used"] = datetime.utcnow().isoformat()
        metadata["usage_count"] = metadata.get("usage_count", 0) + 1
        self.redis.setex(f"apikey:{key_hash}", 86400, json.dumps(metadata))

        return metadata, "valid"

    def revoke_key(self, key_id):
        """Immediately revoke an API key."""
        row = self.db.execute(
            "SELECT key_hash, metadata FROM api_keys WHERE key_id = ?",
            (key_id,)
        ).fetchone()
        if row:
            key_hash = row[0]
            metadata = json.loads(row[1])
            metadata["is_active"] = False
            metadata["revoked_at"] = datetime.utcnow().isoformat()

            self.db.execute(
                "UPDATE api_keys SET metadata = ? WHERE key_id = ?",
                (json.dumps(metadata), key_id)
            )
            # Invalidate cache immediately
            self.redis.delete(f"apikey:{key_hash}")
            return True
        return False

    def rotate_key(self, old_key_id, grace_period_hours=24):
        """Rotate an API key with a grace period where both old and new keys work."""
        old_row = self.db.execute(
            "SELECT key_hash, metadata FROM api_keys WHERE key_id = ?",
            (old_key_id,)
        ).fetchone()
        if not old_row:
            return None, "key_not_found"

        old_metadata = json.loads(old_row[1])

        # Generate new key with same settings
        new_key_data = self.generate_key(
            key_type=old_metadata["key_type"],
            owner_id=old_metadata["owner_id"],
            scopes=old_metadata["scopes"],
            rate_limit=old_metadata["rate_limit"],
            ip_allowlist=old_metadata["ip_allowlist"],
        )

        # Schedule old key revocation after grace period
        revoke_at = datetime.utcnow() + timedelta(hours=grace_period_hours)
        old_metadata["scheduled_revocation"] = revoke_at.isoformat()
        self.db.execute(
            "UPDATE api_keys SET metadata = ? WHERE key_id = ?",
            (json.dumps(old_metadata), old_key_id)
        )

        return {
            "new_key": new_key_data,
            "old_key_id": old_key_id,
            "old_key_revokes_at": revoke_at.isoformat(),
            "message": f"Old key will be revoked in {grace_period_hours} hours"
        }, "success"
```

### Step 2: API Key Validation Middleware

```python
from flask import Flask, request, jsonify, g
from functools import wraps

app = Flask(__name__)

def require_api_key(required_scopes=None):
    """Middleware to validate API key and check scopes."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Extract API key from header
            api_key = request.headers.get("X-API-Key")
            if not api_key:
                # Also check Authorization: Bearer <key>
                auth_header = request.headers.get("Authorization", "")
                if auth_header.startswith("Bearer "):
                    api_key = auth_header[7:]

            if not api_key:
                return jsonify({"error": "missing_api_key"}), 401

            # Validate the key
            metadata, status = key_manager.validate_key(api_key)
            if status != "valid":
                return jsonify({"error": status}), 401

            # Check IP allowlist
            if metadata.get("ip_allowlist"):
                client_ip = request.remote_addr
                if client_ip not in metadata["ip_allowlist"]:
                    return jsonify({"error": "ip_not_allowed"}), 403

            # Check scopes
            if required_scopes:
                key_scopes = set(metadata.get("scopes", []))
                if not key_scopes.intersection(required_scopes):
                    return jsonify({"error": "insufficient_scope"}), 403

            # Attach metadata to request context
            g.api_key_metadata = metadata
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.route('/api/v1/data', methods=['GET'])
@require_api_key(required_scopes=["read", "admin"])
def get_data():
    return jsonify({"data": "sensitive information"})

@app.route('/api/v1/data', methods=['POST'])
@require_api_key(required_scopes=["write", "admin"])
def create_data():
    return jsonify({"created": True})
```

### Step 3: Automated Key Leakage Detection

```bash
# Scan GitHub repositories for leaked API keys using gitleaks
gitleaks detect --source=/path/to/repo --config=gitleaks.toml --report-path=leaks.json

# Custom gitleaks configuration for API key prefix detection
# gitleaks.toml
cat <<'EOF'
[[rules]]
id = "company-api-key-live"
description = "Company Live API Key"
regex = '''sk_live_[A-Za-z0-9_-]{32,}'''
tags = ["api-key", "live", "critical"]

[[rules]]
id = "company-api-key-test"
description = "Company Test API Key"
regex = '''sk_test_[A-Za-z0-9_-]{32,}'''
tags = ["api-key", "test"]

[[rules]]
id = "company-public-key"
description = "Company Public API Key"
regex = '''pk_live_[A-Za-z0-9_-]{32,}'''
tags = ["api-key", "public"]
EOF
```

```python
# Automated leaked key revocation
import json

def process_leaked_keys(leaks_file):
    """Automatically revoke API keys detected in public repositories."""
    with open(leaks_file) as f:
        leaks = json.load(f)

    for leak in leaks:
        key_match = leak.get("match", "")
        # Extract the key from the match
        for prefix in ["sk_live_", "sk_test_", "pk_live_"]:
            if prefix in key_match:
                start = key_match.index(prefix)
                potential_key = key_match[start:start+50]  # Max key length
                # Validate and revoke
                metadata, status = key_manager.validate_key(potential_key)
                if status == "valid":
                    key_manager.revoke_key(metadata["key_id"])
                    print(f"[REVOKED] Key {metadata['key_id']} leaked in {leak.get('file')}")
                    # Notify the key owner
                    notify_owner(metadata["owner_id"], metadata["key_id"], leak)
```

## Key Concepts

| Term | Definition |
|------|------------|
| **API Key** | A secret string used to authenticate API requests, typically passed in headers or query parameters |
| **Key Hashing** | Storing only the hash (SHA-256) of the API key in the database, never the plaintext key, similar to password hashing |
| **Key Rotation** | Replacing an API key with a new one while maintaining a grace period where both keys work, ensuring zero-downtime transition |
| **Key Scoping** | Limiting each API key to specific endpoints, HTTP methods, IP ranges, and rate limits to minimize blast radius |
| **Key Prefix** | An identifiable prefix (e.g., sk_live_) that enables automated detection of leaked keys in logs, code, and public repositories |
| **Secret Scanning** | Automated monitoring of repositories, logs, and public sources for exposed API keys and credentials |

## Tools & Systems

- **GitHub Secret Scanning**: Built-in GitHub feature that detects exposed secrets in repositories and alerts key providers
- **gitleaks**: Open-source tool for detecting secrets in git repositories using customizable regex patterns
- **truffleHog**: Secret scanning tool that searches entire git history for high-entropy strings and known secret patterns
- **HashiCorp Vault**: Enterprise secret management system for API key storage, rotation, and dynamic credential generation
- **AWS Secrets Manager**: Managed secret storage with automatic rotation support for API keys and credentials

## Common Scenarios

### Scenario: API Key Security Program for Developer Platform

**Context**: A developer platform provides public APIs authenticated with API keys. The platform has 10,000+ API consumers generating 50M+ requests per day. Keys are frequently leaked in public GitHub repositories.

**Approach**:
1. Implement prefixed API keys (sk_live_, sk_test_) with 256-bit entropy for leak detection
2. Store only SHA-256 hashes of keys in the database, cache validated keys in Redis
3. Implement per-key scoping: each key restricted to specific endpoints, rate limits, and optional IP allowlists
4. Build key rotation API with 24-hour grace period for seamless transitions
5. Integrate with GitHub Secret Scanning to automatically detect and revoke leaked keys within minutes
6. Run gitleaks in CI/CD pipelines to prevent key commits in first place
7. Implement anomaly detection: alert on keys used from unusual IPs or with abnormal traffic patterns
8. Add key expiration policy: all keys expire after 365 days with 30-day advance notification

**Pitfalls**:
- Storing API keys in plaintext in the database (use SHA-256 hashing)
- Using predictable or low-entropy key generation (use cryptographically secure random generators)
- Not implementing key prefixes, making it impossible to identify leaked keys in automated scans
- Allowing API keys in URL query parameters where they leak in logs, browser history, and Referer headers
- Not implementing rate limiting per key, allowing a single compromised key to abuse the entire API

## Output Format

```
## API Key Security Implementation Report

**Platform**: Developer API v3
**Total Active Keys**: 12,450
**Daily Key Validations**: 52M

### Security Controls

| Control | Implementation | Status |
|---------|---------------|--------|
| Key Entropy | 256-bit (secrets.token_urlsafe(32)) | Implemented |
| Key Format | sk_live_/sk_test_ prefixed | Implemented |
| Storage | SHA-256 hashed, Redis cached | Implemented |
| Scoping | Per-key endpoint/IP/rate limits | Implemented |
| Rotation | 24-hour grace period API | Implemented |
| Expiration | 365-day max TTL | Implemented |
| Leak Detection | GitHub Secret Scanning + gitleaks | Active |
| Auto-Revocation | Leaked keys revoked within 5 min | Active |

### Key Leakage Stats (Last 30 Days)
- Keys detected in public repos: 23
- Average time to revocation: 3.2 minutes
- Keys detected in CI/CD pre-commit: 7 (prevented)
```
