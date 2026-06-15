# AWS Athena API Reference

This reference covers the Amazon Athena API as used for cloud log forensics, primarily through the AWS SDK for Python (`boto3`) and the AWS CLI. Athena is a serverless, interactive query service that runs ANSI SQL (Trino/Presto engine) directly against data in Amazon S3.

## Authentication

Athena uses standard AWS authentication — there is no separate Athena API key. Credentials are resolved by the AWS SDK credential provider chain, in order:

1. Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
2. Shared credentials file: `~/.aws/credentials` (profile via `AWS_PROFILE`)
3. Shared config file: `~/.aws/config`
4. IAM role for Amazon EC2 / ECS task role / EKS IRSA / Lambda execution role
5. SSO / `aws sso login`

```python
import boto3

# Default credential chain
athena = boto3.client("athena", region_name="us-east-1")

# Explicit profile / assumed role session
session = boto3.Session(profile_name="ir-forensics", region_name="us-east-1")
athena = session.client("athena")
```

Required IAM permissions for forensic querying (least privilege):

| Action | Purpose |
|---|---|
| `athena:StartQueryExecution` | Submit a query |
| `athena:GetQueryExecution` | Poll query status |
| `athena:GetQueryResults` | Fetch result rows |
| `athena:StopQueryExecution` | Cancel a running query |
| `athena:GetWorkGroup` / `athena:ListWorkGroups` | Workgroup discovery |
| `glue:GetTable`, `glue:GetDatabase`, `glue:GetPartitions` | Read table metadata (Glue Data Catalog) |
| `s3:GetObject`, `s3:ListBucket` | Read source log data |
| `s3:PutObject`, `s3:GetObject` on the results bucket | Write/read query output |

## Key Methods (boto3 `athena` client / Athena API)

| Method | Description | Key Parameters |
|---|---|---|
| `start_query_execution` | Submit a SQL query (DDL or DML). Asynchronous — returns immediately. | `QueryString` (required), `QueryExecutionContext={Database, Catalog}`, `ResultConfiguration={OutputLocation, EncryptionConfiguration}`, `WorkGroup`, `ClientRequestToken` (idempotency, ≤128 chars), `ExecutionParameters` (list for `?` placeholders), `ResultReuseConfiguration` |
| `get_query_execution` | Poll a query's status, statistics, and engine details. | `QueryExecutionId` (required) |
| `get_query_results` | Retrieve result rows (paginated, max 1000 rows/page). | `QueryExecutionId` (required), `MaxResults` (1–1000), `NextToken`, `QueryResultType` |
| `stop_query_execution` | Cancel a running query. | `QueryExecutionId` (required) |
| `batch_get_query_execution` | Get details for up to 50 query IDs at once. | `QueryExecutionIds` (list, ≤50) |
| `list_query_executions` | List query IDs (most recent first). | `WorkGroup`, `MaxResults` (≤50), `NextToken` |
| `get_query_runtime_statistics` | Detailed per-stage execution stats. | `QueryExecutionId` |
| `create_work_group` / `get_work_group` | Manage workgroups (cost controls, result location, encryption). | `Name`, `Configuration` |
| `create_named_query` / `list_named_queries` | Save/list reusable saved queries. | `Name`, `Database`, `QueryString`, `WorkGroup` |
| `get_database` / `list_databases` / `list_table_metadata` | Inspect Data Catalog metadata. | `CatalogName`, `DatabaseName` |

### `start_query_execution` parameter detail

- `QueryString` — the SQL text. Up to 262,144 bytes (256 KB).
- `QueryExecutionContext` — `{"Database": "cloud_forensics", "Catalog": "AwsDataCatalog"}`. Sets the default database so unqualified table names resolve.
- `ResultConfiguration.OutputLocation` — `s3://aws-athena-query-results-.../` where the CSV result and metadata are written. Required unless the workgroup enforces an output location.
- `WorkGroup` — defaults to `primary`. Use a dedicated forensics workgroup to enforce encryption, a per-query data-scanned limit (`BytesScannedCutoffPerQuery`), and a fixed result location.
- `ExecutionParameters` — positional values for parameterized queries using `?` placeholders (prevents SQL injection when interpolating IOCs).
- `ResultReuseConfiguration` — `{"ResultReuseByAgeConfiguration": {"Enabled": true, "MaxAgeInMinutes": 60}}` reuses prior results to cut cost/latency.

## Python SDK

```python
# Installation
pip install boto3

import boto3
import time

athena = boto3.client("athena", region_name="us-east-1")

def run_query(sql, database="cloud_forensics",
              output="s3://aws-athena-query-results-acct-region/forensics/",
              workgroup="forensics", params=None):
    """Submit a query, poll to completion, return result rows."""
    kwargs = {
        "QueryString": sql,
        "QueryExecutionContext": {"Database": database},
        "ResultConfiguration": {"OutputLocation": output},
        "WorkGroup": workgroup,
    }
    if params:
        kwargs["ExecutionParameters"] = params  # for ? placeholders

    qid = athena.start_query_execution(**kwargs)["QueryExecutionId"]

    # Poll status
    while True:
        resp = athena.get_query_execution(QueryExecutionId=qid)
        state = resp["QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(1)

    if state != "SUCCEEDED":
        reason = resp["QueryExecution"]["Status"].get("StateChangeReason", "")
        raise RuntimeError(f"Query {state}: {reason}")

    # Paginate results
    rows = []
    paginator = athena.get_paginator("get_query_results")
    for page in paginator.paginate(QueryExecutionId=qid):
        rows.extend(page["ResultSet"]["Rows"])
    return rows

# Parameterized query — safe IOC lookup
run_query(
    "SELECT eventtime, eventname, sourceipaddress "
    "FROM cloudtrail_logs WHERE sourceipaddress = ? LIMIT 100",
    params=["203.0.113.45"],
)
```

CLI equivalents:

```bash
aws athena start-query-execution \
  --query-string "SELECT count(*) FROM cloud_forensics.cloudtrail_logs" \
  --query-execution-context Database=cloud_forensics \
  --result-configuration OutputLocation=s3://my-athena-results/ \
  --work-group forensics

aws athena get-query-execution --query-execution-id <id>
aws athena get-query-results   --query-execution-id <id>
```

## Common Response Fields

`get_query_execution` → `QueryExecution`:

| Field | Meaning |
|---|---|
| `QueryExecutionId` | Unique query ID |
| `Status.State` | `QUEUED` \| `RUNNING` \| `SUCCEEDED` \| `FAILED` \| `CANCELLED` |
| `Status.StateChangeReason` | Failure/cancel reason text |
| `Statistics.DataScannedInBytes` | Bytes scanned (drives cost — $5/TB scanned) |
| `Statistics.EngineExecutionTimeInMillis` | Execution time |
| `Statistics.TotalExecutionTimeInMillis` | Wall-clock including queue time |
| `ResultConfiguration.OutputLocation` | S3 path to the result CSV |

`get_query_results` → `ResultSet.Rows` (each `Row.Data` is a list of `{"VarCharValue": ...}`); the **first row is the column header**. `ResultSetMetadata.ColumnInfo` describes column names/types.

## Rate Limits / Service Quotas

These are default, adjustable AWS account-level quotas (per Region):

| Quota | Default |
|---|---|
| `StartQueryExecution` call rate (DML) | 20 calls/sec (burst), then throttled |
| `GetQueryExecution` call rate | 100 calls/sec |
| `GetQueryResults` call rate | 100 calls/sec |
| Active DML queries (running + queued) | 200 (Engine v3) |
| Active DDL queries | 20 |
| Query timeout (DML) | 30 minutes |
| DDL query timeout | 600 minutes |
| `QueryString` max size | 256 KB |
| Result page (`GetQueryResults`) | 1000 rows max |

Throttling surfaces as `TooManyRequestsException` / `ThrottlingException`. boto3 retries these automatically with exponential backoff (adaptive retry mode recommended for high-volume forensic batch jobs). Cost is billed by **bytes scanned**, so partition pruning and columnar formats (Parquet/ORC) drastically reduce both cost and the chance of hitting the per-query data-scan cutoff.

## Error Codes

| Error | Meaning |
|---|---|
| `InvalidRequestException` | Malformed request / invalid parameter |
| `TooManyRequestsException` | API call rate or concurrent-query quota exceeded |
| `ThrottlingException` | Service throttling; back off and retry |
| `ResourceNotFoundException` | Workgroup, catalog, or named query not found |
| `MetadataException` | Glue Data Catalog metadata error |
| Query `FAILED` with `HIVE_BAD_DATA` | Row doesn't match table schema/SerDe |
| Query `FAILED` with `HIVE_CURSOR_ERROR` | S3 object unreadable (permissions, corrupt file) |
| Query `FAILED` with `HIVE_PARTITION_SCHEMA_MISMATCH` | Partition schema differs from table |
| `AccessDeniedException` | Missing IAM permission for Athena, Glue, or S3 |

## Resources

- Athena API Reference: https://docs.aws.amazon.com/athena/latest/APIReference/Welcome.html
- boto3 Athena client: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/athena.html
- Athena service quotas: https://docs.aws.amazon.com/athena/latest/ug/service-limits.html
- Querying AWS service logs (CloudTrail, VPC Flow, ALB, S3) in Athena: https://docs.aws.amazon.com/athena/latest/ug/querying-aws-service-logs.html
- Partition projection: https://docs.aws.amazon.com/athena/latest/ug/partition-projection.html
