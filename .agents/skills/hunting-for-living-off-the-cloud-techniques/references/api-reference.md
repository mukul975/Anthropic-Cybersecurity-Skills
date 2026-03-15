# API Reference — Hunting for Living-off-the-Cloud Techniques

## Libraries Used
- **elasticsearch** (elasticsearch-py): Query Elastic SIEM for cloud abuse indicators
- **re**: Pattern matching against cloud C2 domain patterns in DNS logs

## CLI Interface

```
python agent.py hunt --es-host <url> --index <pattern> [--api-key <key>] [--hours <n>]
python agent.py dns --log-file <path>
```

## Core Functions

### `hunt_lotc_elastic(es_host, es_index, api_key=None, hours=24)`
Executes five pre-built hunting queries against Elasticsearch to detect cloud service abuse.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `es_host` | str | Elasticsearch host URL (e.g., `https://es:9200`) |
| `es_index` | str | Index pattern (default: `logs-*`) |
| `api_key` | str | Optional API key for authentication |
| `hours` | int | Lookback window in hours |

**Returns:** dict with `hunts` list (each with `name`, `description`, `hits`, `events`) and `total_hits`.

### `analyze_dns_logs(log_file)`
Scans DNS query log files for connections to known cloud services used for C2, staging, and exfiltration.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `log_file` | str | Path to DNS query log file |

**Returns:** dict with `total_matches`, `findings` list, and `cloud_services_detected`.

## Hunting Queries

| Query Name | MITRE Technique | Description |
|-----------|----------------|-------------|
| `azure_storage_exfil` | T1567.002 | Large uploads to Azure Blob Storage |
| `aws_s3_staging` | T1537 | Unusual S3 bucket creation or large PutObject |
| `saas_c2_channel` | T1102 | Outbound connections to SaaS APIs (Telegram, Slack, Discord) |
| `cloud_function_invoke` | T1584.007 | Cloud function invocation via LOLBins |
| `github_raw_download` | T1105 | Payload downloads from raw GitHub content |

## Elasticsearch API Calls
- `Elasticsearch(hosts=[url], api_key=key)` — Initialize client
- `es.search(index=pattern, body=query)` — Execute search query
- Response: `resp["hits"]["total"]["value"]`, `resp["hits"]["hits"][]._source`

## Dependencies
```
pip install elasticsearch>=8.0
```
