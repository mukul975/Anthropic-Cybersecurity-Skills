---
name: performing-cloud-asset-inventory-with-cartography
description: Perform comprehensive cloud asset inventory and relationship mapping using Cartography to build a Neo4j security graph of infrastructure assets, IAM permissions, and attack paths across AWS, GCP, and Azure.
domain: cybersecurity
subdomain: cloud-security
tags: [cartography, neo4j, cloud-security, asset-inventory, attack-path, graph-database, cncf, lyft]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Cloud Asset Inventory with Cartography

## Overview

Cartography is a CNCF sandbox project (originally created at Lyft) that consolidates infrastructure assets and their relationships into a Neo4j graph database. It queries cloud APIs to discover resources, maps relationships between them, and enables security teams to identify attack paths, generate asset reports, and find areas for security improvement. The graph model reveals hidden connections such as IAM permission chains, network paths, and cross-account trust relationships.

## Prerequisites

- Python 3.8+
- Neo4j 4.x or 5.x database
- Cloud provider credentials (AWS, GCP, Azure)
- Docker (optional, for Neo4j deployment)
- Minimum 4GB RAM for Neo4j, more for large environments

## Installation

```bash
# Install Cartography
pip install cartography

# Verify installation
cartography --help
```

### Deploy Neo4j with Docker

```bash
docker run -d \
  --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/changethispassword \
  -e NEO4J_PLUGINS='["apoc"]' \
  -v neo4j_data:/data \
  neo4j:5-community
```

## Running Cartography

### Basic AWS Sync

```bash
# Sync AWS account data to Neo4j
cartography \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-password-env-var NEO4J_PASSWORD
```

### Sync specific AWS modules

```bash
cartography \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-password-env-var NEO4J_PASSWORD \
  --aws-sync-all-profiles
```

### GCP Sync

```bash
cartography \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-password-env-var NEO4J_PASSWORD \
  --gcp-requested-syncs compute iam storage
```

## Security-Focused Cypher Queries

### Find all S3 buckets with public access

```cypher
MATCH (b:S3Bucket)
WHERE b.anonymous_access = true
   OR b.anonymous_actions IS NOT NULL
RETURN b.name, b.anonymous_actions, b.region, b.arn
ORDER BY b.name
```

### Identify IAM users with admin policies

```cypher
MATCH (user:AWSUser)-[:POLICY]->(policy:AWSPolicy)
WHERE policy.name = 'AdministratorAccess'
   OR policy.arn CONTAINS 'AdministratorAccess'
RETURN user.name, user.arn, policy.name, user.password_last_used
```

### Find EC2 instances exposed to internet

```cypher
MATCH (instance:EC2Instance)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
      -[:MEMBER_OF_EC2_SECURITY_GROUP_RULE]->(rule:IpRule)
WHERE rule.fromport <= 22 AND rule.toport >= 22
  AND rule.protocol IN ['tcp', '-1']
  AND '0.0.0.0/0' IN rule.ipranges
RETURN instance.instanceid, instance.publicipaddress, sg.groupid, sg.name
```

### Discover cross-account trust relationships

```cypher
MATCH (role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(principal:AWSPrincipal)
WHERE principal.arn CONTAINS ':root'
  AND NOT principal.arn CONTAINS role.accountid
RETURN role.arn, role.name, principal.arn AS trusted_account
ORDER BY role.name
```

### Find attack path from public EC2 to sensitive S3

```cypher
MATCH path = (instance:EC2Instance)-[:STS_ASSUME_ROLE_ALLOWS|MEMBER_OF_EC2_SECURITY_GROUP|
  POLICY|INSTANCE_PROFILE*1..5]->(bucket:S3Bucket)
WHERE instance.publicipaddress IS NOT NULL
  AND bucket.name CONTAINS 'sensitive'
RETURN path
LIMIT 25
```

### Identify unused IAM roles

```cypher
MATCH (role:AWSRole)
WHERE role.last_used IS NULL
   OR role.last_used < datetime().epochMillis - (90 * 24 * 60 * 60 * 1000)
RETURN role.name, role.arn, role.last_used
ORDER BY role.last_used
```

### Find Lambda functions with overprivileged roles

```cypher
MATCH (func:AWSLambda)-[:STS_ASSUME_ROLE_ALLOWS]->(role:AWSRole)-[:POLICY]->(policy:AWSPolicy)
WHERE policy.name = 'AdministratorAccess'
RETURN func.name, func.arn, role.name, policy.name
```

### Network path analysis

```cypher
MATCH (vpc:AWSVpc)-[:RESOURCE]->(subnet:EC2Subnet)-[:MEMBER_OF_SUBNET]->(instance:EC2Instance)
WHERE instance.publicipaddress IS NOT NULL
RETURN vpc.id, subnet.subnetid, subnet.cidr_block, instance.instanceid,
       instance.publicipaddress, instance.state
```

## Scheduling Regular Syncs

### Cron-based sync

```bash
# Add to crontab - sync every 6 hours
0 */6 * * * /usr/local/bin/cartography \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-password-env-var NEO4J_PASSWORD \
  >> /var/log/cartography/sync.log 2>&1
```

### Docker Compose deployment

```yaml
version: '3.8'
services:
  neo4j:
    image: neo4j:5-community
    ports:
      - "7474:7474"
      - "7687:7687"
    environment:
      NEO4J_AUTH: neo4j/securepwd123
      NEO4J_PLUGINS: '["apoc"]'
      NEO4J_dbms_memory_heap_max__size: 4G
    volumes:
      - neo4j_data:/data

  cartography:
    image: ghcr.io/cartography-cncf/cartography:latest
    depends_on:
      - neo4j
    environment:
      NEO4J_PASSWORD: securepwd123
      AWS_DEFAULT_REGION: us-east-1
    command: >
      --neo4j-uri bolt://neo4j:7687
      --neo4j-user neo4j
      --neo4j-password-env-var NEO4J_PASSWORD

volumes:
  neo4j_data:
```

## Data Model Overview

### Key Node Types
- `AWSAccount`, `GCPProject`, `AzureSubscription`
- `EC2Instance`, `S3Bucket`, `RDSInstance`, `AWSLambda`
- `AWSUser`, `AWSRole`, `AWSGroup`, `AWSPolicy`
- `EC2SecurityGroup`, `EC2Subnet`, `AWSVpc`
- `GCPInstance`, `GCSBucket`, `GCPRole`

### Key Relationship Types
- `RESOURCE`: Account owns resource
- `POLICY`: Principal has policy attached
- `STS_ASSUME_ROLE_ALLOWS`: Principal can assume role
- `MEMBER_OF_EC2_SECURITY_GROUP`: Instance belongs to SG
- `TRUSTS_AWS_PRINCIPAL`: Cross-account trust

## References

- Cartography GitHub: https://github.com/cartography-cncf/cartography
- Cartography Documentation: https://cartography.dev
- CNCF Sandbox Project
- Neo4j Cypher Query Language Reference
