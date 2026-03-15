# API Reference: Ransomware Leak Site Intelligence

## ransomware.live API

### Recent Victims
```bash
curl https://api.ransomware.live/recentvictims
```

### Group Information
```bash
curl https://api.ransomware.live/groups
curl https://api.ransomware.live/group/lockbit3
```

### Response Format
```json
{
  "group_name": "lockbit3",
  "victim": "company-name",
  "website": "company.com",
  "discovered": "2024-03-15T00:00:00Z",
  "country": "US",
  "activity": "Manufacturing"
}
```

## ransomlook.io API

### Endpoints
```bash
curl https://www.ransomlook.io/api/groups       # List all groups
curl https://www.ransomlook.io/api/group/lockbit # Group details
curl https://www.ransomlook.io/api/recent        # Recent posts
```

## Ransomwatch (GitHub)

### Data Repository
```bash
git clone https://github.com/joshhighet/ransomwatch
# Data in JSON format: posts.json, groups.json
```

### JSON Schema
```json
{
  "group_name": "string",
  "post_title": "string",
  "discovered": "ISO-8601",
  "post_url": "onion URL",
  "country": "2-letter code",
  "activity": "sector"
}
```

## ID Ransomware

### Identification
```
Upload: encrypted file + ransom note
URL: https://id-ransomware.malwarehunterteam.com/
Returns: ransomware family, decryptor availability
```

## Active Ransomware Groups (2025)

| Group | Status | Primary Target |
|-------|--------|---------------|
| LockBit 3.0 | Active | Cross-sector |
| Cl0p | Active | MOVEit/file transfer exploitation |
| Play | Active | Manufacturing, IT |
| 8Base | Active | SMBs |
| Akira | Active | Healthcare, Education |
| Black Basta | Active | Enterprise |
| Medusa | Active | Education, Healthcare |
| RansomHub | Active | Cross-sector |
| Rhysida | Active | Government, Healthcare |
| BianLian | Active | Healthcare, Manufacturing |

## Intelligence Collection Framework

| Source | Type | Update Frequency |
|--------|------|------------------|
| ransomware.live | Victim listings | Real-time |
| ransomlook.io | Group monitoring | Daily |
| ransomwatch | Onion site scraping | Hourly |
| NoMoreRansom.org | Decryptor availability | As released |
| CISA alerts | Government advisories | As published |

## STIX Representation
```json
{
  "type": "threat-actor",
  "name": "LockBit",
  "threat_actor_types": ["crime-syndicate"],
  "roles": ["agent"],
  "goals": ["financial-gain"]
}
```
