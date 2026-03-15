# API Reference: Malpedia Malware Family Analysis

## Base URL
```
https://malpedia.caad.fkie.fraunhofer.de/api
```

## Authentication
```
Authorization: apitoken YOUR_API_KEY
```

## List Families
```
GET /list/families
```
Returns dict of `{family_name: {alt_names, description, attribution, urls}}`.

## Get Family Details
```
GET /get/family/{family_name}
```
| Field | Description |
|-------|-------------|
| `common_name` | Primary family name |
| `alt_names` | List of alternative names |
| `description` | Family description |
| `attribution` | List of attributed threat actors |
| `urls` | Reference URLs |

## Get YARA Rules
```
GET /get/yara/{family_name}
```
Returns dict of YARA rules keyed by rule source.

## List Actors
```
GET /list/actors
```
Returns dict of `{actor_name: {alt_names, description, families}}`.

## Get Actor Details
```
GET /get/actor/{actor_name}
```
| Field | Description |
|-------|-------------|
| `common_name` | Actor name |
| `description` | Actor profile |
| `families` | Associated malware families |
| `alt_names` | Alternative names (APT designations) |

## Get Sample
```
GET /get/sample/{sha256}
GET /get/sample/{sha256}/zip
```

## Relationship Types
| Relation | Description |
|----------|-------------|
| `also_known_as` | Family alias |
| `shared_actor` | Families used by same threat actor |
| `variant_of` | Derived malware variant |

## MITRE ATT&CK
- T1587.001 - Develop Capabilities: Malware
