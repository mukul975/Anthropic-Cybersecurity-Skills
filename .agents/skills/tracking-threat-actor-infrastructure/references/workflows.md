# Infrastructure Tracking Workflows

## Workflow 1: IP-Centric Pivoting
```
[Known C2 IP] --> [Shodan/Censys] --> [Service Fingerprints]
      |                                      |
      v                                      v
[Passive DNS] --> [Associated Domains] --> [WHOIS Analysis] --> [Registrant Pivot]
      |                                                               |
      v                                                               v
[SSL Certs] --> [Subject Alt Names] --> [New Domains] --> [Additional IPs]
```

## Workflow 2: Domain-Centric Pivoting
```
[Known C2 Domain] --> [DNS History] --> [Historical IPs] --> [Co-hosted Domains]
        |                                                          |
        v                                                          v
  [CT Logs] --> [Subdomains] --> [Infrastructure Map] --> [Shared Hosting Analysis]
        |
        v
  [WHOIS] --> [Registrant/Email] --> [Other Registered Domains]
```

## Workflow 3: C2 Framework Hunting
```
[C2 Signature] --> [Shodan Search] --> [Candidate Servers] --> [Validation]
                                                                    |
                                                                    v
                                                          [JARM Fingerprint]
                                                                    |
                                                                    v
                                                          [Confirm C2 Type]
                                                                    |
                                                                    v
                                                          [Track Over Time]
```

## Workflow 4: Continuous Monitoring
```
[Watchlist IPs/Domains] --> [Scheduled Scans] --> [Change Detection] --> [Alerts]
                                                         |
                                                +--------+--------+
                                                |        |        |
                                                v        v        v
                                          [New Port] [DNS Change] [New Cert]
                                                |        |        |
                                                v        v        v
                                          [Investigate] [Update TI] [Share]
```
