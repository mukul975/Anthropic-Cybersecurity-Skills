# LDAP Security Hardening — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| ldap3 | `pip install ldap3` | LDAP protocol client for security auditing |

## Key ldap3 Methods

| Method | Description |
|--------|-------------|
| `Server(ip, port, use_ssl, tls, get_info=ALL)` | Create LDAP server with TLS config |
| `Connection(server, user, password, authentication=NTLM)` | Authenticated bind |
| `Connection(server, auto_bind=True)` | Anonymous bind test |
| `conn.search(base, filter, attributes)` | Search directory objects |

## LDAP Security Settings (GPO)

| Setting | Registry Path | Recommended Value |
|---------|--------------|-------------------|
| LDAP Signing | `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity` | 2 (Require) |
| Channel Binding | `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding` | 2 (Always) |
| Simple Bind | GPO: Network security: LDAP client signing requirements | Require signing |

## Security Checks

| Check | Risk | Severity |
|-------|------|----------|
| Anonymous bind allowed | User/group enumeration | CRITICAL |
| LDAPS not available | Cleartext credential transmission | HIGH |
| LDAP signing not enforced | NTLM relay via LDAP | HIGH |
| Channel binding disabled | Credential relay attacks | MEDIUM |

## External References

- [ldap3 Documentation](https://ldap3.readthedocs.io/)
- [Microsoft LDAP Signing](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server)
- [CIS AD Benchmark](https://www.cisecurity.org/benchmark/microsoft_windows_server)
