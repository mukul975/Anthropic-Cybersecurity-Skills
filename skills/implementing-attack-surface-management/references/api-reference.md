# Attack Surface Management Tooling API Reference

This skill combines several external attack-surface tools. This reference documents the APIs/SDKs/CLIs for each: **Shodan**, **Censys**, and the **ProjectDiscovery** suite (`subfinder`, `httpx`, `nuclei`).

---

## 1. Shodan

### Authentication
Single API key, passed to the SDK constructor or `key` query parameter. Get it from the account page (https://account.shodan.io). The key encodes your plan and query credits.

```python
import shodan
api = shodan.Shodan("YOUR_SHODAN_API_KEY")
```
REST base URL: `https://api.shodan.io`. Key is sent as `?key=YOUR_KEY`.

### Key Methods / Endpoints
| SDK method | REST endpoint | Description | Parameters |
|---|---|---|---|
| `api.host(ip)` | `GET /shodan/host/{ip}` | All services/banners for one IP | `ip`, `history`, `minify` |
| `api.search(query)` | `GET /shodan/host/search` | Search the banner index | `query`, `page`, `facets`, `minify` |
| `api.count(query)` | `GET /shodan/host/count` | Result count + facets, **no query credits** | `query`, `facets` |
| `api.search_cursor(query)` | — | Generator that auto-paginates all results | `query`, `minify` |
| `api.scan(ips)` | `POST /shodan/scan` | Request on-demand scan of IPs/netblocks | `ips` |
| `api.dns.resolve(hosts)` | `GET /dns/resolve` | Hostname → IP | `hostnames` |
| `api.dns.reverse(ips)` | `GET /dns/reverse` | IP → hostname | `ips` |
| `api.info()` | `GET /api-info` | Remaining query/scan credits, plan | — |
| `api.exploits.search(q)` | (Exploits API) | Search Exploit DB / CVE / Metasploit | `query`, `facets` |

Search filters used in `query`: `org:`, `hostname:`, `net:`, `port:`, `ssl.cert.subject.cn:`, `ssl:`, `product:`, `vuln:`, `country:`, `http.title:`.

### Python SDK
```python
# pip install shodan
import shodan
api = shodan.Shodan("YOUR_SHODAN_API_KEY")

# Cheap count first (no query credit consumed)
print(api.count('org:"Example Corp"')["total"])

# Full search with vuln extraction
for svc in api.search('org:"Example Corp"')["matches"]:
    print(svc["ip_str"], svc["port"], svc.get("product"))
    for cve in svc.get("vulns", []):
        print("  ", cve)

# Per-host deep lookup
host = api.host("93.184.216.34")
print(host["ports"], host.get("vulns", []))
```

### Common Response Fields
`matches[]` items: `ip_str`, `port`, `transport`, `product`, `version`, `hostnames`, `org`, `isp`, `location` (`country_code`, `city`), `data` (raw banner), `vulns` (list of CVE IDs), `ssl`, `http`, `timestamp`.

### Rate Limits
- **1 request/second** is the hard REST API rate limit across the account (the SDK paces `search_cursor`).
- **Query credits**: 1 query credit is deducted per 100 results/pages of search (or per page of domain info). Every credit yields up to 100 results. **IP lookups (`host()`) and `count()` do NOT consume query credits.** Shodan Membership = 100 query credits/month; paid API plans range from 10,000 up to unlimited. Credits reset at the start of each month.
- **Scan credits**: separate monthly budget consumed by `api.scan()` — 1 scan credit per host requested.

### Error Codes
`401` invalid API key · `403` access denied / plan lacks feature · `429` rate-limit or out of credits · `404` IP not found in index. SDK raises `shodan.APIError` with the message.

### Resources
- API docs: https://developer.shodan.io/api
- Python lib: https://shodan.readthedocs.io
- Search filters: https://www.shodan.io/search/filters

---

## 2. Censys (Platform API)

### Authentication
Censys Platform uses a **Personal Access Token (PAT)** plus an **Organization ID** (the legacy Search API used an API ID + Secret with HTTP Basic auth). Configure via env vars `CENSYS_API_ID` / `CENSYS_API_SECRET` (legacy) or the Platform token. Credentials from https://platform.censys.io.

```python
from censys.search import CensysHosts   # legacy search SDK
hosts = CensysHosts()   # reads CENSYS_API_ID / CENSYS_API_SECRET from env
```

### Key Methods / Endpoints
| SDK | Description | Parameters |
|---|---|---|
| `CensysHosts().search(query)` | Search the hosts dataset (returns a paginated query object) | `query`, `per_page`, `pages`, `fields`, `sort` |
| `CensysHosts().view(ip)` | Full record for one host | `ip`, `at_time` |
| `CensysHosts().aggregate(query, field)` | Faceted aggregation/report | `query`, `field`, `num_buckets` |
| `CensysCerts().search(query)` | Search the certificates dataset | `query`, `per_page`, `pages` |
| `CensysCerts().view(fingerprint)` | Full cert record | `fingerprint` (SHA-256) |

Query language (Censys Query Language / CenQL) examples: `services.tls.certificates.leaf_data.subject.common_name: example.com`, `services.port: 443`, `services.service_name: HTTP`, `location.country: "United States"`.

### Python SDK
```python
# pip install censys
from censys.search import CensysHosts, CensysCerts

hosts = CensysHosts()
for page in hosts.search(
        "services.tls.certificates.leaf_data.subject.common_name: example.com",
        per_page=100, pages=2):
    for host in page:
        print(host["ip"])
        for s in host.get("services", []):
            print("  ", s["port"], s.get("service_name"))

certs = CensysCerts()
for page in certs.search("parsed.names: example.com"):
    for c in page:
        print(c["fingerprint_sha256"])
```

### Common Response Fields
Host: `ip`, `services[]` (`port`, `service_name`, `transport_protocol`, `software`, `tls`), `location`, `autonomous_system`, `dns`, `operating_system`.
Cert: `fingerprint_sha256`, `parsed.names`, `parsed.subject`, `parsed.issuer`, `parsed.validity`.

### Rate Limits
Tiered by plan. Free/community tier is limited (low queries/month and a modest requests-per-second cap); paid Platform tiers raise both. `429 Too Many Requests` when exceeded — the SDK backs off and retries.

### Error Codes
`401` bad credentials · `403` plan restriction · `404` not found · `422` malformed query · `429` rate limit.

### Resources
- Platform docs: https://docs.censys.com/
- Python SDK: https://censys-python.readthedocs.io
- CenQL reference: https://docs.censys.com/docs/censys-query-language

---

## 3. ProjectDiscovery Suite (CLI tools)

These are Go CLI tools, not REST APIs. They read stdin / files and write JSON. (ProjectDiscovery Cloud / `pdcp` offers a hosted API with an `PDCP_API_KEY`, but the core engines run locally and need no key.)

### Installation
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### subfinder — passive subdomain enumeration
| Flag | Purpose |
|---|---|
| `-d <domain>` | Target domain |
| `-dL <file>` | List of domains |
| `-all` | Use all sources (some need API keys in `~/.config/subfinder/provider-config.yaml`) |
| `-recursive` | Recursive enumeration |
| `-o <file>` / `-oJ` | Output file / JSON lines |
| `-silent` | Only output subdomains |
Provider keys (Shodan, Censys, VirusTotal, SecurityTrails, etc.) go in the provider config to expand passive sources.

### httpx — HTTP probing / fingerprinting
| Flag | Purpose |
|---|---|
| `-sc` | Status code |
| `-cl` | Content length |
| `-ct` | Content type |
| `-title` | Page title |
| `-tech-detect` | Wappalyzer tech fingerprint |
| `-favicon` / `-hash sha256` | Favicon hash / body hash |
| `-jarm` | JARM TLS fingerprint |
| `-cdn` / `-cname` | CDN + CNAME detection |
| `-json` / `-o` | JSON output / file |
| `-rl <n>` | Rate limit (requests/sec) |

### nuclei — template-based vulnerability scanning
| Flag | Purpose |
|---|---|
| `-u <url>` / `-l <file>` | Target(s) |
| `-t <path>` | Specific template(s) |
| `-tags <tags>` | Filter by tag (`cve,misconfig,exposure,panel`) |
| `-severity <levels>` | `critical,high,medium,low,info` |
| `-ut` / `-update-templates` | Update the template store |
| `-rl <n>` / `-c <n>` | Rate limit / concurrency |
| `-o` / `-json` / `-jsonl` | Output |

### Pipeline example
```bash
subfinder -d example.com -all -silent \
  | httpx -silent -tech-detect -json -o live.json
cat live.json | jq -r '.url' \
  | nuclei -severity critical,high -tags cve,exposure -jsonl -o findings.jsonl
```

### Rate Limits
No vendor-imposed API rate limit for local execution — you control load with `-rl` (requests/sec) and `-c` (concurrency). Respect target scope/authorization and any provider key limits (Shodan 1 req/s, Censys/SecurityTrails monthly quotas) consumed via subfinder's passive sources.

### Resources
- subfinder: https://github.com/projectdiscovery/subfinder
- httpx: https://github.com/projectdiscovery/httpx
- nuclei: https://github.com/projectdiscovery/nuclei
- nuclei templates: https://github.com/projectdiscovery/nuclei-templates
- ProjectDiscovery docs: https://docs.projectdiscovery.io/

---

## Scoring Methodology Note
The skill's exposure score derives from OWASP Attack Surface Analysis and the Relative Attack Surface Quotient (RSQ), weighting open management ports, CVSS-scored known vulns, software age, internet exposure, and data sensitivity. None of these scoring inputs require an external API beyond the discovery data gathered above (Shodan `vulns`, nuclei CVE matches, httpx tech-detect).
