# Workflows - BloodHound CE Reconnaissance

## Complete Reconnaissance Workflow

```
1. Deployment
   ├── Pull BloodHound CE Docker images
   ├── Start services with docker compose up -d
   ├── Access web UI and set admin password
   └── Verify API connectivity

2. Data Collection
   ├── Choose collector: SharpHound v2 (Windows) or BloodHound.py (Linux)
   ├── Run All collection method for comprehensive data
   ├── Run Session collection in loop for user mapping
   ├── Collect from all reachable domains
   └── Exfiltrate ZIP data to analysis workstation

3. Import and Setup
   ├── Upload ZIP files via BloodHound CE web interface
   ├── Wait for data processing to complete
   ├── Mark owned/compromised principals
   └── Set high-value targets

4. Analysis
   ├── Run built-in attack path queries
   ├── Execute custom Cypher queries
   ├── Identify ACL abuse opportunities
   ├── Map delegation configurations
   ├── Find Kerberoastable / AS-REP roastable accounts
   └── Discover GPO modification paths

5. Attack Planning
   ├── Prioritize paths by hop count and stealth
   ├── Identify tools needed per hop
   ├── Plan OPSEC for each technique
   └── Document execution plan

6. Reporting
   ├── Export graph visualizations
   ├── Generate path summaries
   ├── Document all findings with evidence
   └── Provide remediation recommendations
```

## Stealthy Collection Workflow

```
Low-Noise Collection:
  1. DCOnly mode: Only queries domain controllers via LDAP
     SharpHound.exe -c DCOnly

  2. Targeted collection: Specific container/OU
     SharpHound.exe -c All --searchbase "OU=Servers,DC=domain,DC=local"

  3. Session loop: Passive session enumeration over time
     SharpHound.exe -c Session --loop --loopduration 04:00:00 --loopinterval 00:05:00
```
