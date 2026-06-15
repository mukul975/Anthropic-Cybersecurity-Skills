---
name: performing-cloud-log-forensics-with-athena
description: 'Uses AWS Athena to query CloudTrail, VPC Flow Logs, S3 access logs,
  and ALB logs for forensic investigation. Covers CREATE TABLE DDL with partition
  projection, forensic SQL queries for detecting unauthorized access, data exfiltration,
  lateral movement, and privilege escalation. Use when investigating AWS security
  incidents or building cloud-native forensic workflows at scale.

  '
domain: cybersecurity
subdomain: cloud-security
tags:
- cloud
- forensics
- athena
- aws
- cloudtrail
- vpc-flow-logs
- s3
- alb
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
mitre_attack:
- T1078.004
- T1530
- T1537
- T1580
- T1021
---

# Performing Cloud Log Forensics with AWS Athena

## When to Use

- When investigating AWS security incidents that require querying massive volumes of cloud logs
- When performing forensic analysis across CloudTrail, VPC Flow Logs, S3 access logs, and ALB logs
- When building reusable Athena tables with partition projection for ongoing incident response
- When hunting for indicators of compromise across multiple AWS log sources simultaneously
- When creating evidence-grade SQL queries for compliance audits or legal proceedings

## Prerequisites

- AWS account with Athena, S3, and Glue permissions
- CloudTrail configured to deliver logs to an S3 bucket
- VPC Flow Logs enabled and publishing to S3
- S3 server access logging enabled on target buckets
- ALB access logging enabled and publishing to S3
- Python 3.8+ with boto3 installed
- Appropriate IAM permissions for Athena queries and S3 access

## Instructions

### Phase 1: Create Athena Database and CloudTrail Table

Create a dedicated forensics database and CloudTrail table using partition projection
to automatically discover partitions without manual ALTER TABLE statements.

```sql
CREATE DATABASE IF NOT EXISTS cloud_forensics;

CREATE EXTERNAL TABLE cloud_forensics.cloudtrail_logs (
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
LOCATION 's3://YOUR-CLOUDTRAIL-BUCKET/AWSLogs/'
TBLPROPERTIES (
    'projection.enabled' = 'true',
    'projection.account.type' = 'enum',
    'projection.account.values' = 'YOUR_ACCOUNT_ID',
    'projection.region.type' = 'enum',
    'projection.region.values' = 'us-east-1,us-west-2,eu-west-1',
    'projection.timestamp.type' = 'date',
    'projection.timestamp.format' = 'yyyy/MM/dd',
    'projection.timestamp.range' = '2023/01/01,NOW',
    'projection.timestamp.interval' = '1',
    'projection.timestamp.interval.unit' = 'DAYS',
    'storage.location.template' = 's3://YOUR-CLOUDTRAIL-BUCKET/AWSLogs/${account}/CloudTrail/${region}/${timestamp}'
);
```

### Phase 2: Create VPC Flow Logs Table

```sql
CREATE EXTERNAL TABLE cloud_forensics.vpc_flow_logs (
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
LOCATION 's3://YOUR-VPC-FLOW-LOGS-BUCKET/AWSLogs/YOUR_ACCOUNT_ID/vpcflowlogs/'
TBLPROPERTIES (
    'skip.header.line.count' = '1',
    'projection.enabled' = 'true',
    'projection.date.type' = 'date',
    'projection.date.format' = 'yyyy/MM/dd',
    'projection.date.range' = '2023/01/01,NOW',
    'projection.date.interval' = '1',
    'projection.date.interval.unit' = 'DAYS',
    'storage.location.template' = 's3://YOUR-VPC-FLOW-LOGS-BUCKET/AWSLogs/YOUR_ACCOUNT_ID/vpcflowlogs/us-east-1/${date}'
);
```

### Phase 3: Create S3 Access Logs Table

```sql
CREATE EXTERNAL TABLE cloud_forensics.s3_access_logs (
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
    'input.regex' = '([^ ]*) ([^ ]*) \\[(.*?)\\] ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) (\"[^\"]*\"|-) (-|[0-9]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) (\"[^\"]*\"|-) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*)'
)
STORED AS INPUTFORMAT 'org.apache.hadoop.mapred.TextInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://YOUR-S3-ACCESS-LOGS-BUCKET/logs/';
```

### Phase 4: Create ALB Access Logs Table

```sql
CREATE EXTERNAL TABLE cloud_forensics.alb_access_logs (
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
LOCATION 's3://YOUR-ALB-LOGS-BUCKET/AWSLogs/YOUR_ACCOUNT_ID/elasticloadbalancing/us-east-1/'
TBLPROPERTIES (
    'projection.enabled' = 'true',
    'projection.day.type' = 'date',
    'projection.day.format' = 'yyyy/MM/dd',
    'projection.day.range' = '2023/01/01,NOW',
    'projection.day.interval' = '1',
    'projection.day.interval.unit' = 'DAYS',
    'storage.location.template' = 's3://YOUR-ALB-LOGS-BUCKET/AWSLogs/YOUR_ACCOUNT_ID/elasticloadbalancing/us-east-1/${day}'
);
```

### Phase 5: Forensic Investigation Queries

#### Detect Unauthorized API Calls

```sql
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
FROM cloud_forensics.cloudtrail_logs
WHERE errorcode IN ('AccessDenied', 'UnauthorizedAccess', 'Client.UnauthorizedAccess')
    AND timestamp BETWEEN '2024/01/01' AND '2024/12/31'
ORDER BY eventtime DESC
LIMIT 1000;
```

#### Detect Privilege Escalation Attempts

```sql
SELECT
    eventtime,
    useridentity.arn AS actor,
    eventname,
    eventsource,
    json_extract_scalar(requestparameters, '$.policyArn') AS policy_arn,
    json_extract_scalar(requestparameters, '$.roleName') AS role_name,
    json_extract_scalar(requestparameters, '$.userName') AS target_user,
    sourceipaddress
FROM cloud_forensics.cloudtrail_logs
WHERE eventname IN (
    'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy',
    'PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy',
    'CreatePolicyVersion', 'SetDefaultPolicyVersion',
    'AddUserToGroup', 'UpdateAssumeRolePolicy',
    'CreateAccessKey', 'CreateLoginProfile',
    'UpdateLoginProfile', 'AssumeRole'
)
    AND timestamp BETWEEN '2024/01/01' AND '2024/12/31'
ORDER BY eventtime DESC;
```

#### Detect Data Exfiltration via S3

```sql
SELECT
    eventtime,
    useridentity.arn AS actor,
    eventname,
    json_extract_scalar(requestparameters, '$.bucketName') AS bucket,
    json_extract_scalar(requestparameters, '$.key') AS object_key,
    sourceipaddress,
    useragent
FROM cloud_forensics.cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
    AND eventname IN ('GetObject', 'CopyObject', 'PutBucketPolicy',
                      'PutBucketAcl', 'PutObjectAcl', 'SelectObjectContent')
    AND sourceipaddress NOT LIKE '10.%'
    AND sourceipaddress NOT LIKE '172.%'
    AND sourceipaddress NOT LIKE '192.168.%'
    AND timestamp BETWEEN '2024/01/01' AND '2024/12/31'
ORDER BY eventtime DESC;
```

#### Detect Lateral Movement via VPC Flow Logs

```sql
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
FROM cloud_forensics.vpc_flow_logs
WHERE action = 'ACCEPT'
    AND srcaddr LIKE '10.%'
    AND dstport IN (22, 3389, 5985, 5986, 445, 135, 139)
    AND date BETWEEN '2024/06/01' AND '2024/06/30'
GROUP BY srcaddr, dstaddr, dstport, protocol
HAVING COUNT(*) > 100
ORDER BY connection_count DESC;
```

#### Detect Port Scanning Activity

```sql
SELECT
    srcaddr,
    COUNT(DISTINCT dstport) AS unique_ports_scanned,
    COUNT(DISTINCT dstaddr) AS unique_targets,
    SUM(packets) AS total_packets,
    MIN(from_unixtime(start)) AS first_seen,
    MAX(from_unixtime("end")) AS last_seen
FROM cloud_forensics.vpc_flow_logs
WHERE action = 'REJECT'
    AND date BETWEEN '2024/06/01' AND '2024/06/30'
GROUP BY srcaddr
HAVING COUNT(DISTINCT dstport) > 25
ORDER BY unique_ports_scanned DESC;
```

#### Detect Suspicious S3 Bulk Downloads

```sql
SELECT
    remote_ip,
    requester,
    bucket_name,
    COUNT(*) AS request_count,
    SUM(bytes_sent) AS total_bytes_downloaded,
    COUNT(DISTINCT key) AS unique_objects,
    MIN(request_datetime) AS first_request,
    MAX(request_datetime) AS last_request
FROM cloud_forensics.s3_access_logs
WHERE operation LIKE '%GET%'
    AND http_status = 200
GROUP BY remote_ip, requester, bucket_name
HAVING COUNT(*) > 500
ORDER BY total_bytes_downloaded DESC;
```

#### Detect ALB-Level Injection Attempts

```sql
SELECT
    time,
    client_ip,
    request_verb,
    request_url,
    elb_status_code,
    target_status_code,
    user_agent
FROM cloud_forensics.alb_access_logs
WHERE (
    request_url LIKE '%UNION%SELECT%'
    OR request_url LIKE '%<script%'
    OR request_url LIKE '%../../../%'
    OR request_url LIKE '%/etc/passwd%'
    OR request_url LIKE '%cmd.exe%'
    OR request_url LIKE '%/proc/self%'
    OR request_url LIKE '%SLEEP(%'
    OR request_url LIKE '%WAITFOR%'
)
    AND day BETWEEN '2024/06/01' AND '2024/06/30'
ORDER BY time DESC;
```

### Phase 6: Cross-Log Correlation

Correlate findings across log sources for comprehensive incident timelines.

```sql
-- Correlate suspicious CloudTrail actor with VPC Flow Logs
WITH suspicious_ips AS (
    SELECT DISTINCT sourceipaddress AS ip
    FROM cloud_forensics.cloudtrail_logs
    WHERE errorcode = 'AccessDenied'
        AND timestamp BETWEEN '2024/06/01' AND '2024/06/30'
)
SELECT
    v.srcaddr,
    v.dstaddr,
    v.dstport,
    v.protocol,
    SUM(v.bytes) AS total_bytes,
    COUNT(*) AS flow_count
FROM cloud_forensics.vpc_flow_logs v
JOIN suspicious_ips s ON v.srcaddr = s.ip
WHERE v.date BETWEEN '2024/06/01' AND '2024/06/30'
GROUP BY v.srcaddr, v.dstaddr, v.dstport, v.protocol
ORDER BY total_bytes DESC;
```

## Examples

```python
# Quick-start: run the forensics agent for a full investigation
python agent.py \
    --action full_investigation \
    --database cloud_forensics \
    --start-date 2024-06-01 \
    --end-date 2024-06-30 \
    --output forensics_report.json

# Run specific queries only
python agent.py \
    --action privilege_escalation \
    --database cloud_forensics \
    --start-date 2024-06-15 \
    --end-date 2024-06-16

# Create all forensic tables from scratch
python agent.py \
    --action setup_tables \
    --cloudtrail-bucket my-cloudtrail-logs \
    --vpc-flow-bucket my-vpc-flow-logs \
    --s3-access-bucket my-s3-access-logs \
    --alb-bucket my-alb-logs \
    --account-id 123456789012 \
    --regions us-east-1,us-west-2
```
