# API Reference: Implementing Network Access Control

## Libraries

### pyrad (RADIUS Client)
- **Install**: `pip install pyrad`
- **Docs**: https://pypi.org/project/pyrad/
- `Client(server, secret, dict)` -- Create RADIUS client
- `CreateAuthPacket()` -- Build Access-Request
- `SendPacket(req)` -- Send and receive RADIUS reply
- Response codes: `AccessAccept`, `AccessReject`, `AccessChallenge`

### pysnmp (SNMP for Switch Queries)
- **Install**: `pip install pysnmp`
- **Docs**: https://pysnmp.readthedocs.io/
- `getCmd()` -- SNMP GET request
- `nextCmd()` -- SNMP GETNEXT/walk
- `CommunityData()` -- SNMPv2c community string
- `UsmUserData()` -- SNMPv3 authentication

## 802.1X SNMP OIDs

| OID | Description |
|-----|-------------|
| `1.3.6.1.2.1.8802.1.1.1.1.2.1.1.1` | dot1xAuthAuthControlledPortStatus |
| `1.3.6.1.2.1.8802.1.1.1.1.2.1.1.2` | dot1xAuthAuthControlledPortControl |
| `1.3.6.1.2.1.8802.1.1.1.1.2.4.1.1` | dot1xAuthSessionAuthenticMethod |

## RADIUS Attributes

| Attribute | Use |
|-----------|-----|
| `User-Name` | Client identity |
| `User-Password` | PAP password |
| `NAS-IP-Address` | Switch/AP IP |
| `NAS-Port-Type` | Port type (Ethernet, Wireless) |
| `Tunnel-Type` | VLAN assignment (13 = VLAN) |
| `Tunnel-Medium-Type` | Medium (6 = 802) |
| `Tunnel-Private-Group-Id` | VLAN ID for dynamic assignment |
| `Filter-Id` | ACL name to apply |

## EAP Methods
- **EAP-TLS**: Certificate-based (strongest, requires PKI)
- **PEAP**: Password with TLS tunnel
- **EAP-TTLS**: Tunneled TLS (flexible inner auth)
- **MAB**: MAC Authentication Bypass (fallback, no supplicant)

## PacketFence NAC API
- REST API at `https://packetfence:9999/api/v1/`
- `GET /nodes` -- List known devices
- `POST /nodes/{mac}/register` -- Register device
- `GET /violations` -- Active violations

## External References
- FreeRADIUS: https://freeradius.org/documentation/
- PacketFence NAC: https://www.packetfence.org/doc/
- Cisco ISE: https://developer.cisco.com/docs/identity-services-engine/
- 802.1X RFC 3748: https://datatracker.ietf.org/doc/html/rfc3748
