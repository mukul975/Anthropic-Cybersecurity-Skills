# Workflows - AWS GuardDuty Findings Automation

## Automated Response Workflow
```
1. GuardDuty detects threat → Generates finding
2. EventBridge receives finding event
3. EventBridge routes to Lambda based on severity/type
4. Lambda executes automated response:
   - EC2: Quarantine instance, snapshot volumes
   - IAM: Deactivate keys, apply deny policy
   - S3: Block public access, enable versioning
5. SNS notifies security team
6. Finding synced to Security Hub
7. Analyst reviews and confirms actions
```

## Triage Workflow
```
1. HIGH (7-8.9): Immediate auto-response + page on-call
2. MEDIUM (4-6.9): Auto-notify + queue for review
3. LOW (1-3.9): Log and batch review weekly
```
