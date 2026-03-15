# OpenVAS Authenticated Scan — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| python-gvm | `pip install python-gvm` | GVM protocol client (GMP) |

## python-gvm Connection

```python
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform

connection = UnixSocketConnection(path="/run/gvmd/gvmd.sock")
with Gmp(connection=connection, transform=EtreeTransform()) as gmp:
    gmp.authenticate("admin", "password")
```

## Key GMP Methods

| Method | Description |
|--------|-------------|
| `get_scan_configs()` | List scan configuration profiles |
| `get_credentials()` | List stored credentials |
| `create_credential(name=, type=, login=, password=)` | Create scan credential |
| `create_target(name=, hosts=, ssh_credential_id=)` | Create scan target with creds |
| `create_task(name=, config_id=, target_id=, scanner_id=)` | Create scan task |
| `start_task(task_id)` | Start a scan task |
| `get_task(task_id)` | Get task status and progress |
| `get_report(report_id, filter_string=)` | Fetch scan results |

## Scan Configuration IDs

| Name | ID | Description |
|------|----|-------------|
| Full and fast | `daba56c8-73ec-11df-a475-002264764cea` | Default comprehensive scan |
| Full and deep | `708f25c4-7489-11df-8094-002264764cea` | Thorough but slower scan |
| Discovery | `8715c877-47a0-438d-98a3-27c7a6ab2196` | Network discovery only |

## Credential Types

| Type | Protocol | Default Port |
|------|----------|-------------|
| USERNAME_PASSWORD (SSH) | SSH | 22 |
| USERNAME_PASSWORD (SMB) | SMB/WMI | 445 |
| USERNAME_PASSWORD (ESXi) | VMware | 443 |
| SNMP | SNMP | 161 |

## OpenVAS CLI (ospd-openvas)

```bash
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --xml "<get_version/>"
greenbone-feed-sync --type SCAP     # Sync vulnerability data
greenbone-feed-sync --type CERT     # Sync CERT advisories
greenbone-feed-sync --type GVMD_DATA  # Sync scan configs
```

## External References

- [python-gvm Documentation](https://python-gvm.readthedocs.io/)
- [Greenbone Community Edition](https://greenbone.github.io/docs/latest/)
- [GMP Protocol Reference](https://docs.greenbone.net/API/GMP/gmp-22.04.html)
