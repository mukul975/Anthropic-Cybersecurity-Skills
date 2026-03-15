# Workflows - Cloud Asset Inventory with Cartography

## Asset Discovery Workflow
```
1. Deploy Neo4j → Setup graph database
2. Configure Credentials → AWS/GCP/Azure access
3. Initial Sync → Run Cartography to populate graph
4. Query Analysis → Execute security-focused Cypher queries
5. Attack Path Review → Identify and document attack paths
6. Schedule Syncs → Automate regular inventory updates
7. Alert Integration → Notify on new risky relationships
```

## Security Assessment Workflow
```
1. Populate Graph → Run full Cartography sync
2. Public Exposure → Query for internet-facing resources
3. IAM Analysis → Identify overprivileged identities
4. Cross-Account → Map trust relationships
5. Network Paths → Analyze network reachability
6. Report → Generate findings for remediation
```
