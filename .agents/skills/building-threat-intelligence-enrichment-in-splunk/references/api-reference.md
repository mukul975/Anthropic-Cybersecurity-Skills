# API Reference: Threat Intelligence Enrichment in Splunk

## Splunk KV Store REST API
```bash
# Create collection
curl -k -u admin:pass -X POST \
  "https://localhost:8089/servicesNS/nobody/SA-ThreatIntelligence/storage/collections/config" \
  -d name=ip_intel

# Insert record
curl -k -u admin:pass -X POST \
  "https://localhost:8089/servicesNS/nobody/SA-ThreatIntelligence/storage/collections/data/ip_intel" \
  -H "Content-Type: application/json" \
  -d '{"ip":"198.51.100.42","threat_key":"c2_server","weight":"3"}'

# Batch insert
curl -k -u admin:pass -X POST \
  "https://localhost:8089/servicesNS/nobody/SA-ThreatIntelligence/storage/collections/data/ip_intel/batch_save" \
  -H "Content-Type: application/json" \
  -d '[{"ip":"1.2.3.4","threat_key":"malware"},{"ip":"5.6.7.8","threat_key":"c2"}]'
```

## Splunk Enterprise Security TI Framework
| Collection | Lookup | Data Model |
|-----------|--------|------------|
| ip_intel | ip_intel_lookup | Network_Traffic |
| domain_intel | domain_intel_lookup | Network_Resolution |
| file_intel | file_intel_lookup | Endpoint |
| email_intel | email_intel_lookup | Email |
| http_intel | http_intel_lookup | Web |

## SPL Threat Matching
```spl
| tstats summariesonly=t count from datamodel=Network_Traffic
  by All_Traffic.dest_ip
| rename All_Traffic.dest_ip as ip
| lookup ip_intel_lookup ip OUTPUT threat_key description
| where isnotnull(threat_key)
```

## AlienVault OTX API
```bash
# Get pulse indicators
curl "https://otx.alienvault.com/api/v1/pulses/PULSE_ID/indicators"

# Search pulses
curl -H "X-OTX-API-KEY: $OTX_KEY" \
  "https://otx.alienvault.com/api/v1/search/pulses?q=ransomware&page=1"
```

## Splunk Python SDK
```python
import splunklib.client as client

service = client.connect(
    host="localhost", port=8089,
    username="admin", password="changeme"
)

# Access KV store collection
collection = service.kvstore["ip_intel"]
collection.data.insert(json.dumps({
    "ip": "198.51.100.42",
    "threat_key": "c2_server"
}))
```
