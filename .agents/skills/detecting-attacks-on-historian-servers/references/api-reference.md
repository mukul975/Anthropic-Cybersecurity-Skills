# Historian Server Attack Detection — API Reference

## Common Historian Platforms

| Platform | Vendor | Default Port |
|----------|--------|-------------|
| PI Data Archive | OSIsoft/AVEVA | 5457 |
| PI Web API | OSIsoft/AVEVA | 443/5459 |
| Wonderware Historian | AVEVA | 1433 (SQL) |
| FactoryTalk Historian | Rockwell | 1433 (SQL) |
| Ignition Gateway | Inductive Automation | 8088 |
| iFIX Historian | GE Digital | 5051 |

## OSIsoft PI Web API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/piwebapi/system` | System information and version |
| GET | `/piwebapi/points` | List PI data points |
| GET | `/piwebapi/streams/{webId}/value` | Get current point value |
| GET | `/piwebapi/streams/{webId}/recorded` | Get historical recorded values |
| GET | `/piwebapi/dataservers` | List configured data servers |

## Ignition Gateway Endpoints

| Endpoint | Description |
|----------|-------------|
| `/StatusPing` | Gateway health check |
| `/system/gwinfo` | Gateway system information |
| `/system/webdev` | Web development module |
| `/main/web/status` | Gateway status page |

## Attack Indicators

| Indicator | Description | Severity |
|-----------|-------------|----------|
| Anonymous API access | PI Web API accessible without auth | CRITICAL |
| Bulk data read | >10,000 points read in single session | CRITICAL |
| Brute force login | >5 failed logins from same IP | HIGH |
| Exposed gateway info | Ignition/PI info pages publicly accessible | HIGH |
| SQL injection on historian DB | Direct SQL queries to historian backend | CRITICAL |

## External References

- [OSIsoft PI Web API Reference](https://docs.aveva.com/bundle/pi-web-api-reference)
- [Ignition Gateway API](https://docs.inductiveautomation.com/docs/8.1/platform/gateway)
- [CISA ICS-CERT: Historian Security](https://www.cisa.gov/ics)
- [NIST SP 800-82 Rev 3](https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final)
