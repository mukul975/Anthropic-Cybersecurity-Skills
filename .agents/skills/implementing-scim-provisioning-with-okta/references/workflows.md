# SCIM Provisioning Workflows

## User Provisioning Workflow

```
1. Admin assigns user to Okta application
       │
2. Okta checks if user exists (GET /Users?filter=userName eq "user@domain.com")
       │
       ├── User NOT found → Okta sends POST /Users with user attributes
       │       │
       │       └── SCIM server creates user → Returns 201 Created
       │
       └── User found → Okta sends PUT /Users/{id} to update attributes
               │
               └── SCIM server updates user → Returns 200 OK
```

## User Deprovisioning Workflow

```
1. Admin unassigns user from Okta application (or user deactivated in Okta)
       │
2. Okta sends PATCH /Users/{id}
       Body: {"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
              "Operations":[{"op":"replace","value":{"active":false}}]}
       │
3. SCIM server deactivates user (sets active=false, revokes sessions)
       │
4. Returns 200 OK with updated user object
```

## Group Push Workflow

```
1. Admin enables Group Push for Okta group
       │
2. Okta sends POST /Groups with group name and initial members
       │
3. When group membership changes in Okta:
       │
       ├── Member added → PATCH /Groups/{id}
       │     Op: add, path: members, value: [{value: userId}]
       │
       └── Member removed → PATCH /Groups/{id}
             Op: remove, path: members[value eq "userId"]
```

## Profile Sync Workflow

```
1. User profile updated in Okta (e.g., department change)
       │
2. Okta sends PUT /Users/{id} or PATCH /Users/{id}
       Body includes updated attributes
       │
3. SCIM server updates user attributes in local database
       │
4. Returns 200 OK with full updated user representation
```

## Error Recovery Workflow

```
1. SCIM operation fails (network timeout, server error)
       │
2. Okta logs failed task in Provisioning > Tasks
       │
3. Admin can retry individual failed tasks
       │
4. For persistent failures:
       ├── Check SCIM server logs for error details
       ├── Verify network connectivity and TLS certificate
       ├── Validate bearer token has not expired
       └── Review attribute mapping for data format issues
```

## Implementation Testing Workflow

```
1. Deploy SCIM server to staging environment
       │
2. Configure Okta SCIM integration with staging URL
       │
3. Run Okta SCIM validator test suite
       │
4. Test manual operations:
       ├── Assign test user → verify account created
       ├── Update user profile → verify attributes synced
       ├── Unassign user → verify account deactivated
       └── Push group → verify group and members created
       │
5. Review provisioning logs in Okta Admin Console
       │
6. Promote to production with production SCIM URL
```
