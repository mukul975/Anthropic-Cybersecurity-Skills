---
name: implementing-scim-provisioning-with-okta
description: Implement automated user provisioning and deprovisioning using SCIM 2.0 protocol with Okta as the identity provider.
domain: cybersecurity
subdomain: identity-access-management
tags: [scim, okta, provisioning, identity-management, automation, sso, lifecycle-management]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing SCIM Provisioning with Okta

## Overview

SCIM (System for Cross-domain Identity Management) is an open standard protocol (RFC 7644) that automates the exchange of user identity information between identity providers like Okta and service providers. This skill covers building a SCIM 2.0-compliant API endpoint and integrating it with Okta for automated user lifecycle management including provisioning, deprovisioning, profile updates, and group management.

## Prerequisites

- Okta tenant with admin access (Developer or Production)
- Application with REST API capable of user management
- TLS-secured endpoint (HTTPS required)
- Okta API token or OAuth 2.0 client credentials
- Python 3.9+ with Flask or FastAPI

## Core Concepts

### SCIM 2.0 Protocol

SCIM defines a standard schema for representing users and groups via JSON, with a RESTful API for CRUD operations:

| Operation | HTTP Method | Endpoint | Description |
|-----------|-------------|----------|-------------|
| Create User | POST | /scim/v2/Users | Provisions a new user account |
| Read User | GET | /scim/v2/Users/{id} | Retrieves user details |
| Update User | PUT/PATCH | /scim/v2/Users/{id} | Modifies user attributes |
| Delete User | DELETE | /scim/v2/Users/{id} | Removes user account |
| List Users | GET | /scim/v2/Users | Lists users with filtering |
| Create Group | POST | /scim/v2/Groups | Creates a group |
| Manage Group | PATCH | /scim/v2/Groups/{id} | Add/remove group members |

### Okta SCIM Integration Architecture

```
Okta (IdP) ──SCIM 2.0 over HTTPS──> SCIM Server ──> Application Database
     │                                     │
     ├── User Assignment                   ├── Create/Update User
     ├── User Unassignment                 ├── Deactivate User
     ├── Profile Push                      ├── Sync Attributes
     └── Group Push                        └── Manage Groups
```

### Required SCIM Endpoints

1. **ServiceProviderConfig** (`/scim/v2/ServiceProviderConfig`): Advertises SCIM capabilities
2. **ResourceTypes** (`/scim/v2/ResourceTypes`): Describes supported resource types
3. **Schemas** (`/scim/v2/Schemas`): Publishes the SCIM schema definitions
4. **Users** (`/scim/v2/Users`): User lifecycle operations
5. **Groups** (`/scim/v2/Groups`): Group management operations

## Implementation Steps

### Step 1: Build SCIM 2.0 API Server

Create a Flask-based SCIM server that implements the core endpoints. The server must handle:

- **User CRUD**: Create, read, update, delete, and list users
- **Filtering**: Support `eq` filter on `userName` (required by Okta)
- **Pagination**: Return `startIndex`, `itemsPerPage`, and `totalResults`
- **Authentication**: Bearer token validation on all endpoints

```python
from flask import Flask, request, jsonify
import uuid
from datetime import datetime

app = Flask(__name__)

# Bearer token for Okta authentication
SCIM_BEARER_TOKEN = "your-secure-token-here"

def require_auth(f):
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != SCIM_BEARER_TOKEN:
            return jsonify({"detail": "Unauthorized"}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route("/scim/v2/Users", methods=["POST"])
@require_auth
def create_user():
    data = request.json
    user_id = str(uuid.uuid4())
    user = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": user_id,
        "userName": data.get("userName"),
        "name": data.get("name", {}),
        "emails": data.get("emails", []),
        "active": True,
        "meta": {
            "resourceType": "User",
            "created": datetime.utcnow().isoformat() + "Z",
            "lastModified": datetime.utcnow().isoformat() + "Z",
            "location": f"/scim/v2/Users/{user_id}"
        }
    }
    # Persist user to database
    return jsonify(user), 201

@app.route("/scim/v2/Users", methods=["GET"])
@require_auth
def list_users():
    filter_param = request.args.get("filter", "")
    start_index = int(request.args.get("startIndex", 1))
    count = int(request.args.get("count", 100))
    # Parse filter: userName eq "john@example.com"
    # Query database with filter
    return jsonify({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 0,
        "startIndex": start_index,
        "itemsPerPage": count,
        "Resources": []
    })
```

### Step 2: Configure Okta Application

1. **Create SCIM App Integration**:
   - Navigate to Okta Admin Console > Applications > Create App Integration
   - Select SWA or SAML 2.0 as sign-on method
   - In the General tab, select SCIM for Provisioning

2. **Configure SCIM Connection**:
   - SCIM connector base URL: `https://your-app.com/scim/v2`
   - Unique identifier field: `userName`
   - Supported provisioning actions: Push New Users, Push Profile Updates, Push Groups
   - Authentication Mode: HTTP Header (Bearer Token)

3. **Enable Provisioning Features**:
   - To App: Create Users, Update User Attributes, Deactivate Users
   - Configure attribute mappings between Okta profile and SCIM schema

### Step 3: Map Attributes

Map Okta user profile attributes to your SCIM schema:

| Okta Attribute | SCIM Attribute | Direction |
|---------------|----------------|-----------|
| login | userName | Okta -> App |
| firstName | name.givenName | Okta -> App |
| lastName | name.familyName | Okta -> App |
| email | emails[type eq "work"].value | Okta -> App |
| department | urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department | Okta -> App |

### Step 4: Implement Error Handling

SCIM specifies standard error response format:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "detail": "User already exists",
  "status": "409",
  "scimType": "uniqueness"
}
```

Common error codes: 400 (Bad Request), 401 (Unauthorized), 404 (Not Found), 409 (Conflict), 500 (Internal Server Error).

### Step 5: Test with Runscope/Okta SCIM Validator

Okta provides an automated SCIM test suite (via Runscope/BlazeMeter) that validates your SCIM implementation against all required operations:

1. Import the Okta SCIM 2.0 test suite from the OIN submission portal
2. Configure the base URL and authentication token
3. Run the full test suite covering user CRUD, filtering, and pagination
4. Fix any failing tests before submitting to OIN

## Validation Checklist

- [ ] SCIM server accessible over HTTPS with valid TLS certificate
- [ ] Bearer token authentication enforced on all endpoints
- [ ] User creation returns 201 with full user representation
- [ ] User search by `userName eq "..."` filter works correctly
- [ ] Pagination parameters (`startIndex`, `count`) handled properly
- [ ] User deactivation sets `active: false` (not hard delete)
- [ ] PATCH operations support `add`, `replace`, `remove` ops
- [ ] Group push creates and manages group memberships
- [ ] Okta SCIM validator test suite passes all tests
- [ ] Error responses conform to SCIM error schema

## References

- [SCIM 2.0 Protocol RFC 7644](https://tools.ietf.org/html/rfc7644)
- [Okta SCIM Developer Guide](https://developer.okta.com/docs/guides/scim-provisioning-integration-overview/main/)
- [Build a SCIM API Service - Okta](https://developer.okta.com/docs/guides/scim-provisioning-integration-prepare/main/)
- [SCIM Core Schema RFC 7643](https://tools.ietf.org/html/rfc7643)
