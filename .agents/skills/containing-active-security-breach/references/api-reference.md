# Active Security Breach Containment — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| requests | `pip install requests` | EDR API calls for host isolation |
| falconpy | `pip install crowdstrike-falconpy` | CrowdStrike Falcon SDK |
| ldap3 | `pip install ldap3` | AD account disable via LDAP |

## CrowdStrike Falcon Host Isolation

```python
from falconpy import Hosts
hosts = Hosts(client_id="ID", client_secret="SECRET")
hosts.perform_action(action_name="contain", ids=["device_id"])
```

## Containment Actions

| Action | Method | Scope |
|--------|--------|-------|
| Host Isolation | EDR API (CrowdStrike, Defender) | Single endpoint |
| Account Disable | `Disable-ADAccount` / LDAP | User identity |
| IP Block | Firewall rule / NGFW API | Network perimeter |
| Session Revoke | `Revoke-AzureADUserAllRefreshToken` | Cloud sessions |
| Token Invalidation | IdP API | OAuth/SAML tokens |

## NIST IR Phases

| Phase | Actions |
|-------|---------|
| Containment | Isolate, disable, block |
| Eradication | Remove malware, patch vulnerabilities |
| Recovery | Restore, validate, monitor |

## External References

- [CrowdStrike Falcon API](https://falcon.crowdstrike.com/documentation/page/a2a7fc0e/host-and-host-group-management-apis)
- [NIST SP 800-61 Rev 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS IR Playbook](https://www.sans.org/white-papers/33901/)
