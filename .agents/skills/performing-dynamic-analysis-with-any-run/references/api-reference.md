# API Reference: Performing Dynamic Analysis with ANY.RUN

## ANY.RUN API v1

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/analysis` | POST | Submit file or URL for analysis |
| `/v1/analysis/{taskid}` | GET | Get full analysis report |
| `/v1/analysis/{taskid}/ioc` | GET | Get extracted IOCs |
| `/v1/analysis/{taskid}/download/{type}` | GET | Download PCAP, screenshots, or dropped files |

## Submission Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `file` | file | Malware sample to analyze (multipart upload) |
| `obj_url` | string | URL to analyze in browser |
| `env_os` | string | OS: `windows-7`, `windows-10`, `windows-11` |
| `env_bitness` | int | Architecture: 32 or 64 |
| `opt_privacy_type` | string | `public`, `private`, or `bylink` |
| `opt_timeout` | int | Analysis timeout in seconds (60-660) |
| `opt_network_connect` | bool | Allow internet access during analysis |
| `opt_network_fakenet` | bool | Use fake network services |

## Report Structure

| Field | Description |
|-------|-------------|
| `analysis.scores.verdict` | Overall verdict and threat level |
| `analysis.processes[]` | Process tree with command lines |
| `analysis.network.dnsRequests[]` | DNS queries made by sample |
| `analysis.network.httpRequests[]` | HTTP requests with URLs and methods |
| `analysis.network.connections[]` | TCP/UDP connections |
| `analysis.mitre[]` | Mapped MITRE ATT&CK techniques |
| `analysis.tags[]` | Malware family and behavior tags |

## Official Python SDK (anyrun-sdk)

| Class / Method | Description |
|----------------|-------------|
| `SandboxConnector.windows(api_key)` | Create sandbox connector for Windows analysis (context manager) |
| `SandboxConnector.linux(api_key)` | Create sandbox connector for Linux analysis (context manager) |
| `connector.run_file_analysis(filepath)` | Submit local file, returns `analysis_id` |
| `connector.run_url_analysis(url)` | Submit URL for browser analysis, returns `analysis_id` |
| `connector.get_task_status(analysis_id)` | Generator yielding status updates until completion |
| `connector.get_analysis_verdict(analysis_id)` | Returns verdict string (malicious/suspicious/clean) |
| `connector.get_analysis_report(analysis_id)` | Returns full analysis report dict |

## Key Libraries

- **anyrun-sdk** (`pip install anyrun-sdk`): Official ANY.RUN Python SDK with `SandboxConnector`
- **requests** (`pip install requests`): HTTP client for REST API fallback
- **time** (stdlib): Polling for analysis completion
- **json** (stdlib): Parse and export analysis results

## Configuration

| Variable | Description |
|----------|-------------|
| `ANYRUN_API_KEY` | ANY.RUN API key (from account settings) |

## Rate Limits

| Plan | Submissions/Day | API Calls/Minute |
|------|-----------------|------------------|
| Free | 5 public | 10 |
| Hunter | Unlimited private | 60 |
| Enterprise | Unlimited | 120 |

## References

- [ANY.RUN API Documentation](https://any.run/api-documentation/)
- [ANY.RUN Public Reports](https://app.any.run/submissions)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [ANY.RUN Blog](https://any.run/cybersecurity-blog/)
