#!/usr/bin/env python3
# For authorized security assessments and defensive monitoring only
"""Serverless Function Injection Detection Agent - Scans Lambda functions for injection vulnerabilities, layer hijacking, and IAM escalation paths."""

import argparse
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("ERROR: boto3 required. Install with: pip install boto3")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Dangerous function patterns by runtime
INJECTION_PATTERNS = {
    "python": [
        {"pattern": r"\beval\s*\(", "sink": "eval()", "severity": "critical", "cwe": "CWE-95"},
        {"pattern": r"\bexec\s*\(", "sink": "exec()", "severity": "critical", "cwe": "CWE-95"},
        {"pattern": r"\bos\.system\s*\(", "sink": "os.system()", "severity": "critical", "cwe": "CWE-78"},
        {"pattern": r"\bos\.popen\s*\(", "sink": "os.popen()", "severity": "critical", "cwe": "CWE-78"},
        {"pattern": r"\bsubprocess\.call\s*\(.*shell\s*=\s*True", "sink": "subprocess.call(shell=True)", "severity": "critical", "cwe": "CWE-78"},
        {"pattern": r"\bsubprocess\.run\s*\(.*shell\s*=\s*True", "sink": "subprocess.run(shell=True)", "severity": "critical", "cwe": "CWE-78"},
        {"pattern": r"\bsubprocess\.Popen\s*\(.*shell\s*=\s*True", "sink": "subprocess.Popen(shell=True)", "severity": "critical", "cwe": "CWE-78"},
        {"pattern": r"\bpickle\.loads\s*\(", "sink": "pickle.loads()", "severity": "high", "cwe": "CWE-502"},
        {"pattern": r"\byaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)", "sink": "yaml.load() without SafeLoader", "severity": "high", "cwe": "CWE-502"},
        {"pattern": r"\bjinja2\.Template\s*\(.*event", "sink": "jinja2.Template() with event data", "severity": "high", "cwe": "CWE-1336"},
        {"pattern": r"\b__import__\s*\(", "sink": "__import__()", "severity": "high", "cwe": "CWE-95"},
        {"pattern": r"f['\"].*\{.*event.*\}.*['\"].*\.execute\(", "sink": "SQL via f-string with event data", "severity": "critical", "cwe": "CWE-89"},
        {"pattern": r"['\"].*%s.*['\"].*%.*event", "sink": "SQL via string formatting with event data", "severity": "critical", "cwe": "CWE-89"},
    ],
    "nodejs": [
        {"pattern": r"\beval\s*\(", "sink": "eval()", "severity": "critical", "cwe": "CWE-95"},
        {"pattern": r"\bnew\s+Function\s*\(", "sink": "new Function()", "severity": "critical", "cwe": "CWE-95"},
        {"pattern": r"\bchild_process\.exec\s*\(", "sink": "child_process.exec()", "severity": "critical", "cwe": "CWE-78"},
        {"pattern": r"\bchild_process\.execSync\s*\(", "sink": "child_process.execSync()", "severity": "critical", "cwe": "CWE-78"},
        {"pattern": r"\bexecSync\s*\(", "sink": "execSync()", "severity": "critical", "cwe": "CWE-78"},
        {"pattern": r"\bexec\s*\((?!ute)", "sink": "exec()", "severity": "high", "cwe": "CWE-78"},
        {"pattern": r"\bvm\.runInNewContext\s*\(", "sink": "vm.runInNewContext()", "severity": "critical", "cwe": "CWE-95"},
        {"pattern": r"\bvm\.runInThisContext\s*\(", "sink": "vm.runInThisContext()", "severity": "critical", "cwe": "CWE-95"},
        {"pattern": r"\brequire\s*\(\s*['\"]child_process['\"]\s*\)", "sink": "require('child_process')", "severity": "medium", "cwe": "CWE-78"},
        {"pattern": r"`.*\$\{.*event.*\}`.*exec", "sink": "Template literal command injection", "severity": "critical", "cwe": "CWE-78"},
    ],
}

EVENT_DATA_ACCESSORS = [
    r"event\s*\[",
    r"event\s*\.",
    r"event\.get\s*\(",
    r"event\[.Records.\]",
    r"event\.body",
    r"event\.headers",
    r"event\.queryStringParameters",
    r"event\.pathParameters",
    r"event\.requestContext",
]


def detect_runtime_family(runtime):
    """Map Lambda runtime to language family."""
    if not runtime:
        return "unknown"
    runtime_lower = runtime.lower()
    if "python" in runtime_lower:
        return "python"
    if "node" in runtime_lower:
        return "nodejs"
    if "java" in runtime_lower:
        return "java"
    if "go" in runtime_lower:
        return "go"
    if "ruby" in runtime_lower:
        return "ruby"
    if "dotnet" in runtime_lower:
        return "dotnet"
    return "unknown"


def enumerate_functions(lambda_client):
    """Enumerate all Lambda functions with their configurations."""
    functions = []
    paginator = lambda_client.get_paginator("list_functions")
    for page in paginator.paginate():
        for func in page["Functions"]:
            func_info = {
                "function_name": func["FunctionName"],
                "function_arn": func["FunctionArn"],
                "runtime": func.get("Runtime", "container"),
                "runtime_family": detect_runtime_family(func.get("Runtime")),
                "handler": func.get("Handler"),
                "role": func["Role"],
                "memory_size": func.get("MemorySize"),
                "timeout": func.get("Timeout"),
                "last_modified": func.get("LastModified"),
                "layers": [l["Arn"] for l in func.get("Layers", [])],
                "environment_variables": list(func.get("Environment", {}).get("Variables", {}).keys()),
                "has_function_url": False,
                "has_secrets_in_env": False,
            }

            # Check for secrets in environment variable names
            secret_patterns = ["KEY", "SECRET", "PASSWORD", "TOKEN", "CREDENTIAL", "API_KEY", "PRIVATE"]
            for var_name in func_info["environment_variables"]:
                if any(pat in var_name.upper() for pat in secret_patterns):
                    func_info["has_secrets_in_env"] = True
                    break

            # Check for function URL
            try:
                url_config = lambda_client.get_function_url_config(FunctionName=func["FunctionName"])
                func_info["has_function_url"] = True
                func_info["function_url_auth"] = url_config.get("AuthType", "UNKNOWN")
            except ClientError:
                pass

            functions.append(func_info)

    logger.info("Enumerated %d Lambda functions", len(functions))
    return functions


def get_event_source_mappings(lambda_client):
    """Get all event source mappings to identify injection entry points."""
    mappings = []
    paginator = lambda_client.get_paginator("list_event_source_mappings")
    for page in paginator.paginate():
        for mapping in page["EventSourceMappings"]:
            source_arn = mapping.get("EventSourceArn", "")
            source_type = "unknown"
            if ":sqs:" in source_arn:
                source_type = "SQS"
            elif ":dynamodb:" in source_arn:
                source_type = "DynamoDB Stream"
            elif ":kinesis:" in source_arn:
                source_type = "Kinesis Stream"
            elif ":kafka" in source_arn:
                source_type = "Kafka"
            elif ":mq:" in source_arn:
                source_type = "MQ"

            mappings.append({
                "function_arn": mapping.get("FunctionArn"),
                "event_source_arn": source_arn,
                "source_type": source_type,
                "state": mapping.get("State"),
                "batch_size": mapping.get("BatchSize"),
            })

    logger.info("Found %d event source mappings", len(mappings))
    return mappings


def download_and_scan_function(lambda_client, function_name, runtime_family, work_dir):
    """Download function code and scan for injection patterns."""
    findings = []
    try:
        response = lambda_client.get_function(FunctionName=function_name)
        code_location = response["Code"]["Location"]

        import urllib.request
        zip_path = os.path.join(work_dir, f"{function_name}.zip")
        req = urllib.request.Request(code_location)
        with urllib.request.urlopen(req, timeout=60) as resp, open(zip_path, "wb") as out:
            out.write(resp.read())

        extract_dir = os.path.join(work_dir, function_name)
        os.makedirs(extract_dir, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_dir)

        # Determine file extensions to scan
        extensions = {
            "python": [".py"],
            "nodejs": [".js", ".mjs", ".ts"],
            "java": [".java"],
            "go": [".go"],
            "ruby": [".rb"],
        }
        target_exts = extensions.get(runtime_family, [".py", ".js"])

        patterns = INJECTION_PATTERNS.get(runtime_family, [])

        for root, dirs, files in os.walk(extract_dir):
            # Skip node_modules and vendor directories
            dirs[:] = [d for d in dirs if d not in ("node_modules", "vendor", "__pycache__", ".git")]

            for filename in files:
                if not any(filename.endswith(ext) for ext in target_exts):
                    continue

                filepath = os.path.join(root, filename)
                relative_path = os.path.relpath(filepath, extract_dir)

                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except Exception:
                    continue

                for line_num, line in enumerate(lines, 1):
                    for pattern_info in patterns:
                        if re.search(pattern_info["pattern"], line):
                            # Check if event data flows into this sink
                            context_start = max(0, line_num - 10)
                            context_lines = lines[context_start:line_num]
                            context_text = "".join(context_lines)

                            event_data_involved = any(
                                re.search(accessor, context_text)
                                for accessor in EVENT_DATA_ACCESSORS
                            )

                            findings.append({
                                "function_name": function_name,
                                "file": relative_path,
                                "line": line_num,
                                "code": line.strip()[:200],
                                "sink": pattern_info["sink"],
                                "severity": pattern_info["severity"],
                                "cwe": pattern_info["cwe"],
                                "event_data_flow": event_data_involved,
                                "confidence": "high" if event_data_involved else "medium",
                            })

    except ClientError as e:
        logger.warning("Cannot download %s: %s", function_name, e)
    except Exception as e:
        logger.warning("Error scanning %s: %s", function_name, e)

    return findings


def audit_layers(lambda_client, functions):
    """Audit Lambda layers for security issues."""
    findings = []
    layer_accounts = {}
    account_id = None

    for func in functions:
        for layer_arn in func.get("layers", []):
            # Extract account ID from layer ARN
            parts = layer_arn.split(":")
            if len(parts) >= 5:
                layer_account = parts[4]
                if account_id is None:
                    # Get our own account ID from function ARN
                    func_parts = func["function_arn"].split(":")
                    if len(func_parts) >= 5:
                        account_id = func_parts[4]

                if layer_account != account_id and account_id:
                    findings.append({
                        "type": "external_layer",
                        "function_name": func["function_name"],
                        "layer_arn": layer_arn,
                        "layer_account": layer_account,
                        "severity": "high",
                        "description": f"Function uses layer from external account {layer_account}",
                    })

                layer_accounts.setdefault(layer_arn, []).append(func["function_name"])

    # Check for layers used by many functions (high-impact if compromised)
    for layer_arn, func_names in layer_accounts.items():
        if len(func_names) >= 5:
            findings.append({
                "type": "high_impact_layer",
                "layer_arn": layer_arn,
                "affected_functions": func_names,
                "severity": "medium",
                "description": f"Layer is shared across {len(func_names)} functions - compromise would be high impact",
            })

    return findings


def detect_privilege_escalation_paths(iam_client, functions):
    """Identify Lambda functions with overprivileged execution roles."""
    findings = []
    checked_roles = {}

    dangerous_actions = [
        "iam:PassRole", "iam:CreateUser", "iam:CreateRole", "iam:AttachRolePolicy",
        "iam:AttachUserPolicy", "iam:PutRolePolicy", "iam:PutUserPolicy",
        "iam:CreateAccessKey", "iam:UpdateAssumeRolePolicy",
        "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration",
        "lambda:CreateFunction", "lambda:InvokeFunction",
        "sts:AssumeRole",
    ]

    for func in functions:
        role_arn = func["role"]
        role_name = role_arn.split("/")[-1]

        if role_name in checked_roles:
            role_findings = checked_roles[role_name]
        else:
            role_findings = {"dangerous_permissions": [], "has_wildcard_resource": False, "has_admin": False}

            try:
                # Check attached policies
                attached = iam_client.list_attached_role_policies(RoleName=role_name)
                for policy in attached["AttachedPolicies"]:
                    if policy["PolicyName"] in ("AdministratorAccess", "PowerUserAccess"):
                        role_findings["has_admin"] = True

                    try:
                        policy_info = iam_client.get_policy(PolicyArn=policy["PolicyArn"])
                        version_id = policy_info["Policy"]["DefaultVersionId"]
                        policy_doc = iam_client.get_policy_version(
                            PolicyArn=policy["PolicyArn"], VersionId=version_id
                        )
                        for stmt in policy_doc["PolicyVersion"]["Document"].get("Statement", []):
                            if stmt.get("Effect") != "Allow":
                                continue
                            actions = stmt.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            resources = stmt.get("Resource", [])
                            if isinstance(resources, str):
                                resources = [resources]

                            if "*" in actions:
                                role_findings["has_admin"] = True
                            if "*" in resources:
                                role_findings["has_wildcard_resource"] = True

                            for action in actions:
                                if action in dangerous_actions or action == "*":
                                    role_findings["dangerous_permissions"].append(action)
                    except ClientError:
                        continue

                # Check inline policies
                inline = iam_client.list_role_policies(RoleName=role_name)
                for policy_name in inline["PolicyNames"]:
                    try:
                        policy_doc = iam_client.get_role_policy(
                            RoleName=role_name, PolicyName=policy_name
                        )
                        for stmt in policy_doc["PolicyDocument"].get("Statement", []):
                            if stmt.get("Effect") != "Allow":
                                continue
                            actions = stmt.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            for action in actions:
                                if action in dangerous_actions or action == "*":
                                    role_findings["dangerous_permissions"].append(action)
                    except ClientError:
                        continue

            except ClientError as e:
                logger.warning("Cannot audit role %s: %s", role_name, e)

            checked_roles[role_name] = role_findings

        if role_findings["has_admin"]:
            findings.append({
                "type": "admin_execution_role",
                "function_name": func["function_name"],
                "role": role_name,
                "severity": "critical",
                "description": "Function has administrative execution role - any code modification grants full account access",
            })
        elif role_findings["dangerous_permissions"]:
            findings.append({
                "type": "dangerous_permissions",
                "function_name": func["function_name"],
                "role": role_name,
                "permissions": list(set(role_findings["dangerous_permissions"])),
                "severity": "high",
                "description": f"Execution role has dangerous permissions: {', '.join(set(role_findings['dangerous_permissions']))}",
            })

    return findings


def check_cloudtrail_for_modifications(cloudtrail_client, days_back=7):
    """Search CloudTrail for suspicious Lambda modifications."""
    findings = []
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days_back)

    suspicious_events = [
        "UpdateFunctionCode20150331v2",
        "UpdateFunctionConfiguration20150331v2",
        "PublishLayerVersion20181031",
        "AddLayerVersionPermission20181031",
        "CreateFunction20150331",
    ]

    for event_name in suspicious_events:
        try:
            response = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {"AttributeKey": "EventName", "AttributeValue": event_name}
                ],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50,
            )
            for event in response.get("Events", []):
                ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
                req_params = ct_event.get("requestParameters", {})

                finding = {
                    "event_name": event_name,
                    "time": event["EventTime"].isoformat(),
                    "user": event.get("Username"),
                    "source_ip": ct_event.get("sourceIPAddress"),
                    "user_agent": ct_event.get("userAgent", "")[:100],
                    "function_name": req_params.get("functionName"),
                    "suspicious": False,
                    "indicators": [],
                }

                # Flag suspicious patterns
                user_agent = ct_event.get("userAgent", "")
                if "console.amazonaws.com" not in user_agent and "cloudformation" not in user_agent.lower():
                    if "UpdateFunctionCode" in event_name:
                        finding["suspicious"] = True
                        finding["indicators"].append("Function code updated outside console/CloudFormation")

                # Check for role changes
                if "role" in req_params and "UpdateFunctionConfiguration" in event_name:
                    finding["suspicious"] = True
                    finding["indicators"].append(f"Execution role changed to: {req_params['role']}")

                # Check for layer additions
                if "layers" in req_params and "UpdateFunctionConfiguration" in event_name:
                    finding["suspicious"] = True
                    finding["indicators"].append(f"Layers modified: {req_params['layers']}")

                # Off-hours modification
                event_hour = event["EventTime"].hour
                if event_hour < 6 or event_hour > 22:
                    finding["indicators"].append(f"Modification at unusual hour: {event_hour}:00 UTC")

                findings.append(finding)

        except ClientError as e:
            logger.warning("CloudTrail query failed for %s: %s", event_name, e)

    return findings


def check_function_url_security(lambda_client, functions):
    """Check Lambda function URLs for insecure authentication."""
    findings = []
    for func in functions:
        if func.get("has_function_url") and func.get("function_url_auth") == "NONE":
            findings.append({
                "type": "unauthenticated_function_url",
                "function_name": func["function_name"],
                "severity": "high",
                "description": "Function URL has AuthType=NONE - publicly accessible without authentication",
            })
    return findings


def generate_report(functions, event_sources, injection_findings, layer_findings,
                    escalation_findings, cloudtrail_findings, url_findings):
    """Generate comprehensive serverless injection detection report."""

    all_findings = []
    for f in injection_findings:
        f["category"] = "code_injection"
        all_findings.append(f)
    for f in layer_findings:
        f["category"] = "layer_security"
        all_findings.append(f)
    for f in escalation_findings:
        f["category"] = "privilege_escalation"
        all_findings.append(f)
    for f in cloudtrail_findings:
        if f.get("suspicious"):
            f["category"] = "suspicious_modification"
            f["severity"] = "high"
            all_findings.append(f)
    for f in url_findings:
        f["category"] = "function_url"
        all_findings.append(f)

    critical = [f for f in all_findings if f.get("severity") == "critical"]
    high = [f for f in all_findings if f.get("severity") == "high"]

    report = {
        "report_type": "Serverless Function Injection Assessment",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "functions_analyzed": len(functions),
            "event_source_mappings": len(event_sources),
            "total_findings": len(all_findings),
            "critical_findings": len(critical),
            "high_findings": len(high),
            "injection_sinks_found": len(injection_findings),
            "layer_issues": len(layer_findings),
            "escalation_paths": len(escalation_findings),
            "suspicious_modifications": len([f for f in cloudtrail_findings if f.get("suspicious")]),
        },
        "findings": all_findings,
        "functions": functions,
        "event_source_mappings": event_sources,
        "cloudtrail_events": cloudtrail_findings,
    }

    return report


def main():
    parser = argparse.ArgumentParser(description="Serverless Function Injection Detection Agent")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--functions", nargs="+", help="Specific function names to scan (default: all)")
    parser.add_argument("--scan-code", action="store_true", help="Download and scan function code for injection sinks")
    parser.add_argument("--cloudtrail-days", type=int, default=7, help="Days of CloudTrail history to search")
    parser.add_argument("--output", default="serverless_injection_report.json", help="Output report file")
    args = parser.parse_args()

    session = boto3.Session(region_name=args.region)
    lambda_client = session.client("lambda")
    iam_client = session.client("iam")
    cloudtrail_client = session.client("cloudtrail")

    logger.info("Starting serverless function injection detection in %s", args.region)

    # Step 1: Enumerate functions
    all_functions = enumerate_functions(lambda_client)
    if args.functions:
        all_functions = [f for f in all_functions if f["function_name"] in args.functions]

    # Step 2: Get event source mappings
    event_sources = get_event_source_mappings(lambda_client)

    # Step 3: Scan code for injection patterns
    injection_findings = []
    if args.scan_code:
        work_dir = tempfile.mkdtemp(prefix="lambda_scan_")
        try:
            for func in all_functions:
                if func["runtime_family"] in INJECTION_PATTERNS:
                    logger.info("Scanning %s (%s)", func["function_name"], func["runtime"])
                    findings = download_and_scan_function(
                        lambda_client, func["function_name"],
                        func["runtime_family"], work_dir
                    )
                    injection_findings.extend(findings)
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    # Step 4: Audit layers
    layer_findings = audit_layers(lambda_client, all_functions)

    # Step 5: Detect privilege escalation paths
    escalation_findings = detect_privilege_escalation_paths(iam_client, all_functions)

    # Step 6: Check CloudTrail for suspicious modifications
    cloudtrail_findings = check_cloudtrail_for_modifications(cloudtrail_client, args.cloudtrail_days)

    # Step 7: Check function URL security
    url_findings = check_function_url_security(lambda_client, all_functions)

    # Generate report
    report = generate_report(
        all_functions, event_sources, injection_findings, layer_findings,
        escalation_findings, cloudtrail_findings, url_findings
    )

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report saved to %s", args.output)

    summary = report["summary"]
    logger.info(
        "Assessment complete: %d functions, %d findings (%d critical, %d high)",
        summary["functions_analyzed"],
        summary["total_findings"],
        summary["critical_findings"],
        summary["high_findings"],
    )

    if summary["critical_findings"] > 0:
        logger.warning("CRITICAL FINDINGS DETECTED:")
        for f in report["findings"]:
            if f.get("severity") == "critical":
                logger.warning("  [%s] %s: %s", f.get("category", ""), f.get("function_name", ""), f.get("sink", f.get("description", "")))

    return 0 if summary["critical_findings"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
