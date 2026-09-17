#!/usr/bin/env python3
"""Agent for performing cloud log forensics using AWS Athena.

Automates Athena table creation with partition projection and runs forensic
SQL queries against CloudTrail, VPC Flow Logs, S3 access logs, and ALB logs.
"""

import json
import time
import argparse
from datetime import datetime, timedelta

import boto3


CLOUDTRAIL_DDL = """
CREATE EXTERNAL TABLE IF NOT EXISTS {database}.cloudtrail_logs (
    eventVersion STRING,
    userIdentity STRUCT<
        type: STRING,
        principalId: STRING,
        arn: STRING,
        accountId: STRING,
        invokedBy: STRING,
        accessKeyId: STRING,
        userName: STRING,
        sessionContext: STRUCT<
            attributes: STRUCT<
                mfaAuthenticated: STRING,
                creationDate: STRING>,
            sessionIssuer: STRUCT<
                type: STRING,
                principalId: STRING,
                arn: STRING,
                accountId: STRING,
                userName: STRING>,
            ec2RoleDelivery: STRING,
            webIdFederationData: STRUCT<
                federatedProvider: STRING,
                attributes: MAP<STRING, STRING>>>>,
    eventTime STRING,
    eventSource STRING,
    eventName STRING,
    awsRegion STRING,
    sourceIPAddress STRING,
    userAgent STRING,
    errorCode STRING,
    errorMessage STRING,
    requestParameters STRING,
    responseElements STRING,
    additionalEventData STRING,
    requestId STRING,
    eventId STRING,
    readOnly STRING,
    resources ARRAY<STRUCT<
        arn: STRING,
        accountId: STRING,
        type: STRING>>,
    eventType STRING,
    apiVersion STRING,
    recipientAccountId STRING,
    serviceEventDetails STRING,
    sharedEventID STRING,
    vpcEndpointId STRING,
    tlsDetails STRUCT<
        tlsVersion: STRING,
        cipherSuite: STRING,
        clientProvidedHostHeader: STRING>
)
COMMENT 'CloudTrail logs with partition projection for forensic analysis'
PARTITIONED BY (
    `account` STRING,
    `region` STRING,
    `timestamp` STRING
)
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://{bucket}/AWSLogs/'
TBLPROPERTIES (
    'projection.enabled' = 'true',
    'projection.account.type' = 'enum',
    'projection.account.values' = '{account_id}',
    'projection.region.type' = 'enum',
    'projection.region.values' = '{regions}',
    'projection.timestamp.type' = 'date',
    'projection.timestamp.format' = 'yyyy/MM/dd',
    'projection.timestamp.range' = '2020/01/01,NOW',
    'projection.timestamp.interval' = '1',
    'projection.timestamp.interval.unit' = 'DAYS',
    'storage.location.template' = 's3://{bucket}/AWSLogs/${{account}}/CloudTrail/${{region}}/${{timestamp}}'
)
"""

VPC_FLOW_DDL = """
CREATE EXTERNAL TABLE IF NOT EXISTS {database}.vpc_flow_logs (
    version INT,
    account_id STRING,
    interface_id STRING,
    srcaddr STRING,
    dstaddr STRING,
    srcport INT,
    dstport INT,
    protocol BIGINT,
    packets BIGINT,
    bytes BIGINT,
    start BIGINT,
    `end` BIGINT,
    action STRING,
    log_status STRING,
    vpc_id STRING,
    subnet_id STRING,
    az_id STRING,
    sublocation_type STRING,
    sublocation_id STRING,
    pkt_srcaddr STRING,
    pkt_dstaddr STRING,
    region STRING,
    pkt_src_aws_service STRING,
    pkt_dst_aws_service STRING,
    flow_direction STRING,
    traffic_path INT
)
PARTITIONED BY (
    `date` STRING
)
ROW FORMAT DELIMITED
FIELDS TERMINATED BY ' '
LOCATION 's3://{bucket}/AWSLogs/{account_id}/vpcflowlogs/'
TBLPROPERTIES (
    'skip.header.line.count' = '1',
    'projection.enabled' = 'true',
    'projection.date.type' = 'date',
    'projection.date.format' = 'yyyy/MM/dd',
    'projection.date.range' = '2020/01/01,NOW',
    'projection.date.interval' = '1',
    'projection.date.interval.unit' = 'DAYS',
    'storage.location.template' = 's3://{bucket}/AWSLogs/{account_id}/vpcflowlogs/{primary_region}/${{date}}'
)
"""

S3_ACCESS_DDL = """
CREATE EXTERNAL TABLE IF NOT EXISTS {database}.s3_access_logs (
    bucket_owner STRING,
    bucket_name STRING,
    request_datetime STRING,
    remote_ip STRING,
    requester STRING,
    request_id STRING,
    operation STRING,
    key STRING,
    request_uri STRING,
    http_status INT,
    error_code STRING,
    bytes_sent BIGINT,
    object_size BIGINT,
    total_time INT,
    turn_around_time INT,
    referrer STRING,
    user_agent STRING,
    version_id STRING,
    host_id STRING,
    signature_version STRING,
    cipher_suite STRING,
    authentication_type STRING,
    host_header STRING,
    tls_version STRING,
    access_point_arn STRING,
    acl_required STRING
)
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.RegexSerDe'
WITH SERDEPROPERTIES (
    'serialization.format' = '1',
    'input.regex' = '([^ ]*) ([^ ]*) \\\\[(.*?)\\\\] ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) (\"[^\"]*\"|-) (-|[0-9]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) (\"[^\"]*\"|-) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*)'
)
STORED AS INPUTFORMAT 'org.apache.hadoop.mapred.TextInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://{bucket}/logs/'
"""

ALB_ACCESS_DDL = """
CREATE EXTERNAL TABLE IF NOT EXISTS {database}.alb_access_logs (
    type STRING,
    time STRING,
    elb STRING,
    client_ip STRING,
    client_port INT,
    target_ip STRING,
    target_port INT,
    request_processing_time DOUBLE,
    target_processing_time DOUBLE,
    response_processing_time DOUBLE,
    elb_status_code INT,
    target_status_code STRING,
    received_bytes BIGINT,
    sent_bytes BIGINT,
    request_verb STRING,
    request_url STRING,
    request_proto STRING,
    user_agent STRING,
    ssl_cipher STRING,
    ssl_protocol STRING,
    target_group_arn STRING,
    trace_id STRING,
    domain_name STRING,
    chosen_cert_arn STRING,
    matched_rule_priority STRING,
    request_creation_time STRING,
    actions_executed STRING,
    redirect_url STRING,
    lambda_error_reason STRING,
    target_port_list STRING,
    target_status_code_list STRING,
    classification STRING,
    classification_reason STRING,
    conn_trace_id STRING
)
PARTITIONED BY (
    `day` STRING
)
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.RegexSerDe'
WITH SERDEPROPERTIES (
    'serialization.format' = '1',
    'input.regex' = '([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[0-9]*) (-|[0-9]*) ([-0-9]*) ([-0-9]*) \"([^ ]*) (.*) (- |[^ ]*)\" \"([^\"]*)\" ([A-Z0-9-_]+) ([A-Za-z0-9.-]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^\"]*)\" ([-.0-9]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^ ]*)\" \"([^\"]*)\" \"([^ ]*)\" \"([^ ]*)\" \"([^ ]*)\"'
)
STORED AS INPUTFORMAT 'org.apache.hadoop.mapred.TextInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://{bucket}/AWSLogs/{account_id}/elasticloadbalancing/{primary_region}/'
TBLPROPERTIES (
    'projection.enabled' = 'true',
    'projection.day.type' = 'date',
    'projection.day.format' = 'yyyy/MM/dd',
    'projection.day.range' = '2020/01/01,NOW',
    'projection.day.interval' = '1',
    'projection.day.interval.unit' = 'DAYS',
    'storage.location.template' = 's3://{bucket}/AWSLogs/{account_id}/elasticloadbalancing/{primary_region}/${{day}}'
)
"""

FORENSIC_QUERIES = {
    "unauthorized_access": """
        SELECT
            eventtime,
            useridentity.arn AS caller_arn,
            useridentity.accountid AS account,
            eventsource,
            eventname,
            errorcode,
            errormessage,
            sourceipaddress,
            useragent
        FROM {database}.cloudtrail_logs
        WHERE errorcode IN ('AccessDenied', 'UnauthorizedAccess', 'Client.UnauthorizedAccess')
            AND timestamp BETWEEN '{start_date}' AND '{end_date}'
        ORDER BY eventtime DESC
        LIMIT 1000
    """,
    "privilege_escalation": """
        SELECT
            eventtime,
            useridentity.arn AS actor,
            eventname,
            eventsource,
            CASE
                WHEN eventname IN ('AttachUserPolicy','AttachRolePolicy','AttachGroupPolicy')
                    THEN json_extract_scalar(requestparameters, '$.policyArn')
                WHEN eventname IN ('CreateAccessKey','CreateLoginProfile','UpdateLoginProfile')
                    THEN json_extract_scalar(requestparameters, '$.userName')
                WHEN eventname = 'AssumeRole'
                    THEN json_extract_scalar(requestparameters, '$.roleArn')
                ELSE requestparameters
            END AS target_resource,
            sourceipaddress,
            errorcode
        FROM {database}.cloudtrail_logs
        WHERE eventname IN (
            'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy',
            'PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy',
            'CreatePolicyVersion', 'SetDefaultPolicyVersion',
            'AddUserToGroup', 'UpdateAssumeRolePolicy',
            'CreateAccessKey', 'CreateLoginProfile',
            'UpdateLoginProfile', 'AssumeRole',
            'PassRole', 'CreateRole'
        )
            AND timestamp BETWEEN '{start_date}' AND '{end_date}'
        ORDER BY eventtime DESC
    """,
    "data_exfiltration_s3": """
        SELECT
            eventtime,
            useridentity.arn AS actor,
            eventname,
            json_extract_scalar(requestparameters, '$.bucketName') AS bucket,
            json_extract_scalar(requestparameters, '$.key') AS object_key,
            sourceipaddress,
            useragent
        FROM {database}.cloudtrail_logs
        WHERE eventsource = 's3.amazonaws.com'
            AND eventname IN ('GetObject', 'CopyObject', 'SelectObjectContent',
                              'PutBucketPolicy', 'PutBucketAcl', 'PutObjectAcl',
                              'DeleteBucketEncryption', 'PutBucketPublicAccessBlock')
            AND sourceipaddress NOT LIKE '10.%'
            AND sourceipaddress NOT LIKE '172.1%'
            AND sourceipaddress NOT LIKE '172.2%'
            AND sourceipaddress NOT LIKE '172.3%'
            AND sourceipaddress NOT LIKE '192.168.%'
            AND timestamp BETWEEN '{start_date}' AND '{end_date}'
        ORDER BY eventtime DESC
    """,
    "lateral_movement_vpc": """
        SELECT
            srcaddr,
            dstaddr,
            dstport,
            protocol,
            SUM(packets) AS total_packets,
            SUM(bytes) AS total_bytes,
            COUNT(*) AS connection_count,
            MIN(from_unixtime(start)) AS first_seen,
            MAX(from_unixtime("end")) AS last_seen
        FROM {database}.vpc_flow_logs
        WHERE action = 'ACCEPT'
            AND srcaddr LIKE '10.%'
            AND dstport IN (22, 3389, 5985, 5986, 445, 135, 139, 5900, 4444, 8080)
            AND date BETWEEN '{start_date}' AND '{end_date}'
        GROUP BY srcaddr, dstaddr, dstport, protocol
        HAVING COUNT(*) > 50
        ORDER BY connection_count DESC
    """,
    "port_scanning": """
        SELECT
            srcaddr,
            COUNT(DISTINCT dstport) AS unique_ports_scanned,
            COUNT(DISTINCT dstaddr) AS unique_targets,
            SUM(packets) AS total_packets,
            MIN(from_unixtime(start)) AS first_seen,
            MAX(from_unixtime("end")) AS last_seen
        FROM {database}.vpc_flow_logs
        WHERE action = 'REJECT'
            AND date BETWEEN '{start_date}' AND '{end_date}'
        GROUP BY srcaddr
        HAVING COUNT(DISTINCT dstport) > 25
        ORDER BY unique_ports_scanned DESC
    """,
    "s3_bulk_download": """
        SELECT
            remote_ip,
            requester,
            bucket_name,
            COUNT(*) AS request_count,
            SUM(bytes_sent) AS total_bytes_downloaded,
            COUNT(DISTINCT key) AS unique_objects,
            MIN(request_datetime) AS first_request,
            MAX(request_datetime) AS last_request
        FROM {database}.s3_access_logs
        WHERE operation LIKE '%GET%'
            AND http_status = 200
        GROUP BY remote_ip, requester, bucket_name
        HAVING COUNT(*) > 500
        ORDER BY total_bytes_downloaded DESC
    """,
    "alb_injection_attempts": """
        SELECT
            time,
            client_ip,
            request_verb,
            request_url,
            elb_status_code,
            target_status_code,
            user_agent
        FROM {database}.alb_access_logs
        WHERE (
            request_url LIKE '%UNION%SELECT%'
            OR request_url LIKE '%<script%'
            OR request_url LIKE '%../../../%'
            OR request_url LIKE '%/etc/passwd%'
            OR request_url LIKE '%cmd.exe%'
            OR request_url LIKE '%/proc/self%'
            OR request_url LIKE '%SLEEP(%'
            OR request_url LIKE '%WAITFOR%'
            OR request_url LIKE '%0x%'
            OR request_url LIKE '%/admin%'
        )
            AND day BETWEEN '{start_date}' AND '{end_date}'
        ORDER BY time DESC
    """,
    "console_login_anomalies": """
        SELECT
            eventtime,
            useridentity.arn AS user_arn,
            useridentity.username AS username,
            sourceipaddress,
            useragent,
            json_extract_scalar(responseelements, '$.ConsoleLogin') AS login_result,
            json_extract_scalar(additionaleventdata, '$.MFAUsed') AS mfa_used,
            json_extract_scalar(additionaleventdata, '$.LoginTo') AS login_target
        FROM {database}.cloudtrail_logs
        WHERE eventname = 'ConsoleLogin'
            AND timestamp BETWEEN '{start_date}' AND '{end_date}'
        ORDER BY eventtime DESC
    """,
    "security_group_changes": """
        SELECT
            eventtime,
            useridentity.arn AS actor,
            eventname,
            json_extract_scalar(requestparameters, '$.groupId') AS security_group_id,
            requestparameters,
            sourceipaddress
        FROM {database}.cloudtrail_logs
        WHERE eventname IN (
            'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress',
            'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress',
            'CreateSecurityGroup', 'DeleteSecurityGroup',
            'ModifySecurityGroupRules'
        )
            AND timestamp BETWEEN '{start_date}' AND '{end_date}'
        ORDER BY eventtime DESC
    """,
    "cross_log_correlation": """
        WITH suspicious_ips AS (
            SELECT DISTINCT sourceipaddress AS ip
            FROM {database}.cloudtrail_logs
            WHERE errorcode IN ('AccessDenied', 'UnauthorizedAccess')
                AND timestamp BETWEEN '{start_date}' AND '{end_date}'
        )
        SELECT
            v.srcaddr,
            v.dstaddr,
            v.dstport,
            v.protocol,
            SUM(v.bytes) AS total_bytes,
            COUNT(*) AS flow_count,
            MIN(from_unixtime(v.start)) AS first_seen,
            MAX(from_unixtime(v."end")) AS last_seen
        FROM {database}.vpc_flow_logs v
        JOIN suspicious_ips s ON v.srcaddr = s.ip
        WHERE v.date BETWEEN '{start_date}' AND '{end_date}'
        GROUP BY v.srcaddr, v.dstaddr, v.dstport, v.protocol
        ORDER BY total_bytes DESC
        LIMIT 500
    """,
}


class AthenaForensicsAgent:
    """Runs forensic investigations against AWS logs via Athena."""

    def __init__(self, database, output_location, region="us-east-1"):
        self.database = database
        self.output_location = output_location
        self.region = region
        self.client = boto3.client("athena", region_name=region)
        self.s3_client = boto3.client("s3", region_name=region)

    def execute_query(self, query, wait=True, timeout=300):
        """Execute an Athena query and optionally wait for results."""
        response = self.client.start_query_execution(
            QueryString=query,
            QueryExecutionContext={"Database": self.database},
            ResultConfiguration={"OutputLocation": self.output_location},
        )
        execution_id = response["QueryExecutionId"]
        print(f"[+] Query execution started: {execution_id}")

        if not wait:
            return execution_id

        start_time = time.time()
        while True:
            status = self.client.get_query_execution(QueryExecutionId=execution_id)
            state = status["QueryExecution"]["Status"]["State"]

            if state == "SUCCEEDED":
                print(f"[+] Query completed in {time.time() - start_time:.1f}s")
                return self._get_results(execution_id)
            elif state in ("FAILED", "CANCELLED"):
                reason = status["QueryExecution"]["Status"].get(
                    "StateChangeReason", "Unknown"
                )
                print(f"[-] Query {state}: {reason}")
                return None

            if time.time() - start_time > timeout:
                print(f"[-] Query timed out after {timeout}s")
                self.client.stop_query_execution(QueryExecutionId=execution_id)
                return None

            time.sleep(2)

    def _get_results(self, execution_id):
        """Fetch query results and return as list of dicts."""
        results = []
        paginator = self.client.get_paginator("get_query_results")
        page_iterator = paginator.paginate(QueryExecutionId=execution_id)

        headers = None
        for page in page_iterator:
            rows = page["ResultSet"]["Rows"]
            for i, row in enumerate(rows):
                values = [col.get("VarCharValue", "") for col in row["Data"]]
                if headers is None:
                    headers = values
                    continue
                results.append(dict(zip(headers, values)))

        print(f"[+] Retrieved {len(results)} rows")
        return results

    def setup_database(self):
        """Create the forensics database if it does not exist."""
        query = f"CREATE DATABASE IF NOT EXISTS {self.database}"
        self.execute_query(query)
        print(f"[+] Database '{self.database}' ready")

    def create_cloudtrail_table(self, bucket, account_id, regions):
        """Create CloudTrail table with partition projection."""
        ddl = CLOUDTRAIL_DDL.format(
            database=self.database,
            bucket=bucket,
            account_id=account_id,
            regions=",".join(regions) if isinstance(regions, list) else regions,
        )
        self.execute_query(ddl)
        print("[+] CloudTrail table created with partition projection")

    def create_vpc_flow_table(self, bucket, account_id, primary_region):
        """Create VPC Flow Logs table with partition projection."""
        ddl = VPC_FLOW_DDL.format(
            database=self.database,
            bucket=bucket,
            account_id=account_id,
            primary_region=primary_region,
        )
        self.execute_query(ddl)
        print("[+] VPC Flow Logs table created with partition projection")

    def create_s3_access_table(self, bucket):
        """Create S3 access logs table."""
        ddl = S3_ACCESS_DDL.format(database=self.database, bucket=bucket)
        self.execute_query(ddl)
        print("[+] S3 access logs table created")

    def create_alb_table(self, bucket, account_id, primary_region):
        """Create ALB access logs table with partition projection."""
        ddl = ALB_ACCESS_DDL.format(
            database=self.database,
            bucket=bucket,
            account_id=account_id,
            primary_region=primary_region,
        )
        self.execute_query(ddl)
        print("[+] ALB access logs table created with partition projection")

    def run_forensic_query(self, query_name, start_date, end_date):
        """Run a named forensic query with date range."""
        if query_name not in FORENSIC_QUERIES:
            available = ", ".join(FORENSIC_QUERIES.keys())
            print(f"[-] Unknown query: {query_name}. Available: {available}")
            return None

        query = FORENSIC_QUERIES[query_name].format(
            database=self.database,
            start_date=start_date.replace("-", "/"),
            end_date=end_date.replace("-", "/"),
        )
        print(f"[+] Running forensic query: {query_name}")
        return self.execute_query(query)

    def run_full_investigation(self, start_date, end_date):
        """Run all forensic queries and compile a comprehensive report."""
        report = {
            "investigation_id": f"inv-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "generated_at": datetime.utcnow().isoformat(),
            "date_range": {"start": start_date, "end": end_date},
            "findings": {},
            "summary": {},
        }

        query_categories = {
            "access_control": [
                "unauthorized_access",
                "privilege_escalation",
                "console_login_anomalies",
            ],
            "data_security": [
                "data_exfiltration_s3",
                "s3_bulk_download",
            ],
            "network_activity": [
                "lateral_movement_vpc",
                "port_scanning",
            ],
            "web_attacks": [
                "alb_injection_attempts",
            ],
            "infrastructure_changes": [
                "security_group_changes",
            ],
            "correlation": [
                "cross_log_correlation",
            ],
        }

        total_findings = 0
        for category, queries in query_categories.items():
            report["findings"][category] = {}
            for query_name in queries:
                print(f"\n{'='*60}")
                print(f"[*] Category: {category} | Query: {query_name}")
                print(f"{'='*60}")
                results = self.run_forensic_query(query_name, start_date, end_date)
                if results is not None:
                    report["findings"][category][query_name] = results
                    total_findings += len(results)
                    print(f"[+] Found {len(results)} results")
                else:
                    report["findings"][category][query_name] = []
                    print("[!] Query returned no results or failed")

        report["summary"] = {
            "total_findings": total_findings,
            "categories_analyzed": len(query_categories),
            "queries_executed": sum(len(v) for v in query_categories.values()),
        }

        # Generate severity assessment
        critical_indicators = []
        if report["findings"].get("access_control", {}).get("privilege_escalation"):
            critical_indicators.append("Privilege escalation activity detected")
        if report["findings"].get("data_security", {}).get("data_exfiltration_s3"):
            critical_indicators.append("Potential S3 data exfiltration detected")
        if report["findings"].get("network_activity", {}).get("lateral_movement_vpc"):
            critical_indicators.append("Lateral movement patterns detected in VPC")
        if report["findings"].get("correlation", {}).get("cross_log_correlation"):
            critical_indicators.append(
                "Cross-log correlation confirms suspicious activity"
            )

        report["summary"]["critical_indicators"] = critical_indicators
        report["summary"]["overall_severity"] = (
            "CRITICAL"
            if len(critical_indicators) >= 3
            else "HIGH"
            if len(critical_indicators) >= 2
            else "MEDIUM"
            if len(critical_indicators) >= 1
            else "LOW"
        )

        return report

    def generate_timeline(self, start_date, end_date):
        """Generate a forensic timeline from all log sources."""
        timeline_query = """
            SELECT
                eventtime AS timestamp,
                'cloudtrail' AS source,
                eventsource || ':' || eventname AS event,
                useridentity.arn AS actor,
                sourceipaddress AS source_ip,
                errorcode
            FROM {database}.cloudtrail_logs
            WHERE timestamp BETWEEN '{start_date}' AND '{end_date}'
                AND (
                    errorcode IS NOT NULL
                    OR eventname IN (
                        'ConsoleLogin', 'AssumeRole', 'CreateAccessKey',
                        'AttachUserPolicy', 'AttachRolePolicy',
                        'RunInstances', 'StopInstances', 'TerminateInstances',
                        'CreateBucket', 'DeleteBucket', 'PutBucketPolicy'
                    )
                )
            ORDER BY eventtime ASC
            LIMIT 5000
        """.format(
            database=self.database,
            start_date=start_date.replace("-", "/"),
            end_date=end_date.replace("-", "/"),
        )
        print("[+] Generating forensic timeline...")
        return self.execute_query(timeline_query)


def main():
    parser = argparse.ArgumentParser(
        description="AWS Athena Cloud Log Forensics Agent"
    )
    parser.add_argument(
        "--action",
        required=True,
        choices=[
            "setup_tables",
            "unauthorized_access",
            "privilege_escalation",
            "data_exfiltration_s3",
            "lateral_movement_vpc",
            "port_scanning",
            "s3_bulk_download",
            "alb_injection_attempts",
            "console_login_anomalies",
            "security_group_changes",
            "cross_log_correlation",
            "full_investigation",
            "timeline",
        ],
    )
    parser.add_argument("--database", default="cloud_forensics")
    parser.add_argument(
        "--output-location",
        default="s3://athena-forensics-output/results/",
        help="S3 location for Athena query results",
    )
    parser.add_argument("--start-date", help="Start date YYYY-MM-DD")
    parser.add_argument("--end-date", help="End date YYYY-MM-DD")
    parser.add_argument("--output", default="forensics_report.json")
    parser.add_argument("--region", default="us-east-1")

    # Table setup arguments
    parser.add_argument("--cloudtrail-bucket", help="CloudTrail S3 bucket name")
    parser.add_argument("--vpc-flow-bucket", help="VPC Flow Logs S3 bucket name")
    parser.add_argument("--s3-access-bucket", help="S3 access logs bucket name")
    parser.add_argument("--alb-bucket", help="ALB access logs bucket name")
    parser.add_argument("--account-id", help="AWS account ID")
    parser.add_argument(
        "--regions",
        default="us-east-1",
        help="Comma-separated AWS regions",
    )

    args = parser.parse_args()

    if not args.start_date:
        args.start_date = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
    if not args.end_date:
        args.end_date = datetime.utcnow().strftime("%Y-%m-%d")

    agent = AthenaForensicsAgent(
        database=args.database,
        output_location=args.output_location,
        region=args.region,
    )

    if args.action == "setup_tables":
        if not args.account_id:
            print("[-] --account-id is required for table setup")
            return
        agent.setup_database()
        regions_list = args.regions.split(",")
        primary_region = regions_list[0]

        if args.cloudtrail_bucket:
            agent.create_cloudtrail_table(
                args.cloudtrail_bucket, args.account_id, regions_list
            )
        if args.vpc_flow_bucket:
            agent.create_vpc_flow_table(
                args.vpc_flow_bucket, args.account_id, primary_region
            )
        if args.s3_access_bucket:
            agent.create_s3_access_table(args.s3_access_bucket)
        if args.alb_bucket:
            agent.create_alb_table(args.alb_bucket, args.account_id, primary_region)

        print("\n[+] Table setup complete")
        return

    if args.action == "full_investigation":
        report = agent.run_full_investigation(args.start_date, args.end_date)
    elif args.action == "timeline":
        results = agent.generate_timeline(args.start_date, args.end_date)
        report = {
            "investigation_type": "timeline",
            "generated_at": datetime.utcnow().isoformat(),
            "date_range": {"start": args.start_date, "end": args.end_date},
            "timeline_events": results or [],
        }
    else:
        results = agent.run_forensic_query(
            args.action, args.start_date, args.end_date
        )
        report = {
            "investigation_type": args.action,
            "generated_at": datetime.utcnow().isoformat(),
            "date_range": {"start": args.start_date, "end": args.end_date},
            "findings": results or [],
            "finding_count": len(results) if results else 0,
        }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[+] Report saved to {args.output}")

    if "summary" in report:
        print(f"\n{'='*60}")
        print("INVESTIGATION SUMMARY")
        print(f"{'='*60}")
        summary = report["summary"]
        print(f"Total findings: {summary.get('total_findings', 0)}")
        print(f"Overall severity: {summary.get('overall_severity', 'N/A')}")
        for indicator in summary.get("critical_indicators", []):
            print(f"  [!] {indicator}")


if __name__ == "__main__":
    main()
