# Workflows — NoSQL Injection Exploitation

## Detection Workflow
1. Identify application technology stack (check for MongoDB, CouchDB indicators)
2. Map all input points accepting JSON data or query parameters
3. Submit operator payloads ($ne, $gt, $regex) in each parameter
4. Monitor responses for authentication bypass or data leakage
5. Test for JavaScript injection via $where operator
6. Document all vulnerable endpoints with proof-of-concept payloads

## Blind Extraction Workflow
1. Confirm boolean-based injection by comparing true/false responses
2. Determine password/field length using $regex with length patterns
3. Extract characters one at a time using $regex "^<known_chars><test>"
4. Automate extraction with Python script using binary search
5. Validate extracted data by attempting authentication

## Automated Scanning Workflow
1. Configure proxy (Burp Suite) to intercept target traffic
2. Run NoSQLMap against identified endpoints
3. Use nuclei with NoSQL injection templates for broad coverage
4. Manually verify automated findings with crafted payloads
5. Escalate confirmed findings to data extraction or RCE attempts
