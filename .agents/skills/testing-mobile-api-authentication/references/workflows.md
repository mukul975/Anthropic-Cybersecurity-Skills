# Workflows: Mobile API Authentication Testing

## Workflow 1: Authentication Assessment

```
[Intercept traffic] --> [Map auth endpoints] --> [Analyze token format]
                                                        |
                                          +-------------+-------------+
                                          |             |             |
                                    [JWT analysis] [OAuth flow]  [Session mgmt]
                                    [None alg]     [PKCE check]  [Expiration]
                                    [Key brute]    [Redirect URI] [Logout invalidation]
                                          |             |             |
                                          +-------------+-------------+
                                                        |
                                                 [IDOR testing]
                                                 [Privilege escalation]
                                                 [Report findings]
```

## Decision Matrix: Token Vulnerability Testing

| Token Type | Primary Tests | Tools |
|-----------|--------------|-------|
| JWT (HS256) | Key brute force, none algorithm, claim manipulation | jwt_tool, hashcat |
| JWT (RS256) | Algorithm confusion, public key retrieval, key ID manipulation | jwt_tool |
| Opaque | Entropy analysis, predictability, server-side invalidation | Burp Sequencer |
| OAuth Bearer | Scope escalation, redirect URI manipulation, PKCE enforcement | Burp, Postman |
