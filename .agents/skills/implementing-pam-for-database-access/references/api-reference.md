# API Reference: Implementing PAM for Database Access

## HashiCorp Vault Database Secrets Engine

```bash
# Enable database secrets engine
vault secrets enable database

# Configure PostgreSQL connection
vault write database/config/postgresql \
  plugin_name=postgresql-database-plugin \
  connection_url="postgresql://{{username}}:{{password}}@db.example.com:5432/mydb" \
  allowed_roles="readonly,readwrite" \
  username="vault_admin" password="admin_pass"

# Create dynamic credential role
vault write database/roles/readonly \
  db_name=postgresql \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl="1h" max_ttl="24h"

# Generate dynamic credentials
vault read database/creds/readonly
```

## hvac Python Client

```python
import hvac
client = hvac.Client(url='http://127.0.0.1:8200', token='s.xxx')
creds = client.secrets.database.generate_credentials('readonly')
# creds['data']['username'], creds['data']['password']
```

## CyberArk Privileged Cloud API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/Accounts?search=database` | GET | List database accounts |
| `/api/Accounts/{id}/Password/Retrieve` | POST | Check out password |
| `/api/Accounts/{id}/CheckIn` | POST | Check in password |
| `/api/LiveSessions` | GET | List active PSM sessions |
| `/api/Recordings` | GET | List session recordings |

## Privileged Database Roles

| Database | Privileged Roles | Risk |
|----------|-----------------|------|
| PostgreSQL | pg_read_all_data, rds_superuser | Critical |
| MySQL | SUPER, ALL PRIVILEGES, GRANT OPTION | Critical |
| Oracle | DBA, SYSDBA, SYSOPER | Critical |
| SQL Server | sysadmin, db_owner, securityadmin | Critical |

## Session Proxy Configuration

| Proxy | Protocol | Feature |
|-------|----------|---------|
| CyberArk PSM | RDP/SSH | Full session recording + keystroke logging |
| Teleport | PostgreSQL/MySQL wire | Query audit logging |
| StrongDM | All major DBs | Just-in-time access + approval workflow |

## NIST 800-53 PAM Controls

| Control | Description |
|---------|-------------|
| AC-2(4) | Automatic audit of account actions |
| AC-6(1) | Authorize access to security functions |
| AC-6(2) | Non-privileged access for non-security functions |
| AC-6(5) | Privileged accounts for privileged functions only |
| AU-9 | Protection of audit information |

### References

- Vault Database Secrets: https://developer.hashicorp.com/vault/docs/secrets/databases
- CyberArk REST API: https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Implementing%20Privileged%20Account%20Security%20Web%20Services%20SDK.htm
- NIST SP 800-53 AC-6: https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-6/
