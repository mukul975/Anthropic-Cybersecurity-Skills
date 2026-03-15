# Workflows — Subdomain Enumeration with Subfinder

## Standard Enumeration Workflow
1. Configure API keys in provider-config.yaml for maximum source coverage
2. Run subfinder with `-all` flag against target domain(s)
3. Deduplicate results and remove out-of-scope entries
4. Validate live hosts with httpx including status codes and technologies
5. Resolve DNS records with dnsx to map IP infrastructure
6. Screenshot live hosts with gowitness for visual review
7. Feed live hosts into vulnerability scanner (nuclei) for automated checks

## Continuous Monitoring Workflow
1. Schedule subfinder runs via cron (daily or weekly)
2. Compare new results against baseline subdomain list
3. Alert on newly discovered subdomains via webhook or email
4. Automatically scan new subdomains for known vulnerabilities
5. Update asset inventory with new discoveries

## Bug Bounty Recon Pipeline
1. Collect target domains from bug bounty program scope
2. Run subfinder + amass + findomain for maximum coverage
3. Merge and deduplicate all results
4. Filter results to in-scope assets only
5. Probe for live HTTP services with httpx
6. Run nuclei templates for quick wins
7. Manually investigate interesting subdomains (dev, staging, api, admin)

## Integration Commands
```bash
# Full pipeline example
subfinder -d target.com -all -silent | \
  httpx -silent -status-code -title -tech-detect | \
  tee live_hosts.txt | \
  nuclei -t cves/ -t exposures/ -t misconfigurations/ -o findings.txt

# Delta monitoring
subfinder -d target.com -silent > today_subs.txt
comm -13 <(sort baseline_subs.txt) <(sort today_subs.txt) > new_subs.txt
```
