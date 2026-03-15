# Zscaler Private Access ZTNA — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| requests | `pip install requests` | ZPA REST API client |
| zscaler-sdk-python | `pip install zscaler-sdk-python` | Official Zscaler Python SDK |

## ZPA API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/signin` | Authenticate and get bearer token |
| GET | `/mgmtconfig/v1/admin/customers/{id}/application` | List app segments |
| GET | `/mgmtconfig/v1/admin/customers/{id}/connector` | List app connectors |
| GET | `/mgmtconfig/v1/admin/customers/{id}/serverGroup` | List server groups |
| GET | `/mgmtconfig/v1/admin/customers/{id}/policySet/rules` | List access policies |
| GET | `/mgmtconfig/v1/admin/customers/{id}/segmentGroup` | List segment groups |

## Key ZPA Concepts

| Component | Description |
|-----------|-------------|
| App Segment | Application definition with domain/IP and port ranges |
| App Connector | On-premise agent that brokers connections to apps |
| Server Group | Group of application servers behind connectors |
| Access Policy | Rules defining who can access which app segments |
| Segment Group | Logical grouping of app segments |

## External References

- [ZPA API Documentation](https://help.zscaler.com/zpa/api)
- [Zscaler SDK Python](https://github.com/zscaler/zscaler-sdk-python)
- [ZPA Admin Guide](https://help.zscaler.com/zpa)
