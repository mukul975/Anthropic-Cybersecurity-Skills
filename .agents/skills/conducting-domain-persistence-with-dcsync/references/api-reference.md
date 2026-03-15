# DCSync Persistence Detection — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| ldap3 | `pip install ldap3` | LDAP directory queries for AD permission enumeration |
| impacket | `pip install impacket` | Network protocol toolkit — secretsdump.py for DCSync |
| pyad | `pip install pyad` | Windows Active Directory interface |

## Key ldap3 Methods

| Method | Description |
|--------|-------------|
| `Server(ip, get_info=ALL)` | Create LDAP server connection object |
| `Connection(server, user, password, authentication=NTLM)` | Bind to AD with NTLM auth |
| `conn.search(search_base, search_filter, attributes)` | Query directory objects |
| `conn.entries` | Access search result entries |
| `conn.unbind()` | Close LDAP connection |

## Critical GUIDs for DCSync Detection

| GUID | Right |
|------|-------|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All |
| `89e95b76-444d-4c62-991a-0facbeda640c` | DS-Replication-Get-Changes-In-Filtered-Set |

## Windows Event IDs

| Event ID | Description |
|----------|-------------|
| 4662 | Directory service object accessed (replication GUIDs indicate DCSync) |
| 4624 | Logon event — correlate with replication activity from non-DC source |

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| OS Credential Dumping: DCSync | T1003.006 |

## External References

- [impacket secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
- [ldap3 Documentation](https://ldap3.readthedocs.io/)
- [Microsoft DCSync Detection](https://learn.microsoft.com/en-us/defender-for-identity/credential-access-alerts)
