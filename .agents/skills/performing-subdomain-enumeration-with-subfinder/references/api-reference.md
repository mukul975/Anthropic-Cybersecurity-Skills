# API Reference: Subdomain Enumeration with Subfinder

## Subfinder CLI Options

| Flag | Description |
|------|-------------|
| `-d <domain>` | Target domain to enumerate |
| `-dL <file>` | File containing list of domains |
| `-o <file>` | Output file for results |
| `-oJ` | JSON lines output format |
| `-oD <dir>` | Output directory (one file per domain) |
| `-all` | Use all passive sources (slower, more thorough) |
| `-silent` | Show only subdomains in output |
| `-recursive` | Enumerate subdomains of discovered subdomains |
| `-s <src1,src2>` | Use only specified sources |
| `-es <src>` | Exclude specific sources |
| `-cs` | Show source for each subdomain |
| `-rate-limit <n>` | Max requests per second |
| `-t <n>` | Number of concurrent threads |

## httpx CLI Options

| Flag | Description |
|------|-------------|
| `-l <file>` | Input file with hosts |
| `-ports <p1,p2>` | Ports to probe |
| `-status-code` | Show HTTP status code |
| `-title` | Show page title |
| `-tech-detect` | Detect web technologies |
| `-json` | JSON output format |
| `-silent` | Suppress banner |

## dnsx CLI Options

| Flag | Description |
|------|-------------|
| `-l <file>` | Input file with hosts |
| `-a` | Resolve A records |
| `-cname` | Resolve CNAME records |
| `-resp` | Show response data |
| `-json` | JSON output |

## Passive Sources

| Source | API Key Required |
|--------|-----------------|
| crt.sh | No |
| VirusTotal | Yes |
| Shodan | Yes |
| SecurityTrails | Yes |
| Censys | Yes |
| Chaos (ProjectDiscovery) | Yes |
| AlienVault OTX | No |
| HackerTarget | No |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute subfinder, httpx, dnsx CLI |
| `json` | stdlib | Parse JSON lines output |
| `pathlib` | stdlib | File path management |

## References

- Subfinder GitHub: https://github.com/projectdiscovery/subfinder
- httpx GitHub: https://github.com/projectdiscovery/httpx
- dnsx GitHub: https://github.com/projectdiscovery/dnsx
- Subfinder Config: https://docs.projectdiscovery.io/tools/subfinder/install
