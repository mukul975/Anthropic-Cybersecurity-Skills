# API Reference: Building Detection Rules with Sigma

## pySigma (sigma-cli)

```python
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.splunk import splunk_windows_pipeline

# Load and parse a Sigma rule
rule = SigmaRule.from_yaml(open("rule.yml").read())
print(rule.title, rule.id, rule.level, rule.status)

# Convert to Splunk SPL
pipeline = splunk_windows_pipeline()
backend = SplunkBackend(pipeline)
queries = backend.convert_rule(rule)
for q in queries:
    print(q)

# Saved search output format
saved = backend.convert_rule(rule, output_format="savedsearches")

# Batch convert a collection
collection = SigmaCollection.load_ruleset(["./rules/"])
output = backend.convert(collection)
```

## Key Sigma Rule Fields

| Field | Required | Description |
|-------|----------|-------------|
| `title` | Yes | Short rule name |
| `id` | Yes | UUID for the rule |
| `status` | Yes | test, experimental, stable |
| `level` | Yes | informational, low, medium, high, critical |
| `logsource` | Yes | category, product, service |
| `detection` | Yes | Selection + condition logic |
| `tags` | No | ATT&CK tags (attack.tXXXX) |

## Available Backends (pySigma)

| Package | Backend | Target |
|---------|---------|--------|
| `pySigma-backend-splunk` | `SplunkBackend` | Splunk SPL |
| `pySigma-backend-elasticsearch` | `LuceneBackend` | Elastic/OpenSearch |
| `pySigma-backend-microsoft365defender` | `Microsoft365DefenderBackend` | KQL |
| `pySigma-backend-qradar` | `QRadarBackend` | AQL |

## sigma-cli Commands

```bash
# Convert single rule
sigma convert -t splunk -p splunk_windows rule.yml

# Convert directory
sigma convert -t splunk -p splunk_windows ./rules/ -o output.txt

# List backends and pipelines
sigma list backends
sigma list pipelines

# Validate a rule
sigma check rule.yml
```

### References

- pySigma: https://github.com/SigmaHQ/pySigma
- sigma-cli: https://github.com/SigmaHQ/sigma-cli
- Sigma rules repo: https://github.com/SigmaHQ/sigma
- SigmaHQ docs: https://sigmahq.io/docs/guide/getting-started.html
