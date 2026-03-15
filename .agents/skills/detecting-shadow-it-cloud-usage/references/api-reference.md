# API Reference — Detecting Shadow IT Cloud Usage

## Libraries Used
- **pandas**: DataFrame aggregation for traffic analysis — groupby, agg, nunique
- **tldextract**: Accurate registered domain extraction from URLs/hostnames
- **csv**: CSV log parsing with DictReader
- **re**: Regex parsing for Squid proxy and BIND DNS query log formats

## CLI Interface
```
python agent.py access.log --type proxy parse
python agent.py access.log --type proxy analyze
python agent.py dns-queries.log --type dns full
python agent.py traffic.csv --type csv --approved approved.txt full
```

## Core Functions

### `parse_proxy_log(filepath)` — Parse Squid/common proxy access logs
Regex pattern matches Squid format: `timestamp duration client_ip status bytes method url`.
Falls back to Apache Common Log Format parsing.

### `parse_dns_log(filepath)` — Parse BIND/named DNS query logs
Extracts query name and type from `query: DOMAIN IN TYPE` patterns.
Strips trailing dots from FQDNs.

### `parse_csv_log(filepath)` — Parse generic CSV traffic logs
Expects columns: timestamp, src_ip, dst_domain, bytes_out, bytes_in.

### `analyze_traffic(records)` — Aggregate and classify traffic
Uses pandas groupby on domain: total_bytes (sum), request_count (count),
unique_users (nunique). Falls back to collections.defaultdict if pandas unavailable.

### `classify_domain(domain)` — Categorize against SaaS database
Categories: storage, email, dev_tools, ai_ml, messaging, file_sharing, vpn_proxy.

### `full_audit(log_path, log_type, approved_list)` — Complete shadow IT audit

## Risk Scoring
| Factor | Points |
|--------|--------|
| Unapproved domain | +30 |
| Storage/file-sharing/VPN category | +25 |
| Email category | +15 |
| Data volume (per 10 MB) | +1 (max 20) |
| Unique users (per user) | +3 (max 15) |

## SaaS Category Database
| Category | Example Domains |
|----------|----------------|
| storage | dropbox.com, box.com, mega.nz, wetransfer.com |
| email | protonmail.com, tutanota.com, guerrillamail.com |
| dev_tools | github.com, gitlab.com, replit.com |
| ai_ml | chat.openai.com, claude.ai, huggingface.co |
| messaging | telegram.org, discord.com, signal.org |
| file_sharing | pastebin.com, file.io, gofile.io |
| vpn_proxy | nordvpn.com, expressvpn.com, protonvpn.com |

## Dependencies
- `pandas` >= 1.5.0
- `tldextract` >= 3.4.0 (optional, improves domain extraction accuracy)
