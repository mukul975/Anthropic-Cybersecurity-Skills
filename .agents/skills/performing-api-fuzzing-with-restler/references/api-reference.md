# RESTler API Fuzzing — API Reference

## Installation

```bash
git clone https://github.com/microsoft/restler-fuzzer.git
python3 ./build-restler.py --dest_dir /opt/restler
```

## RESTler CLI Commands

| Command | Description |
|---------|-------------|
| `Restler compile --api_spec <spec>` | Compile OpenAPI spec to fuzzing grammar |
| `Restler test --grammar_file <g>` | Smoke test — validate endpoint reachability |
| `Restler fuzz-lean --grammar_file <g>` | Quick fuzz — one pass with all checkers |
| `Restler fuzz --grammar_file <g>` | Full fuzz — extended fuzzing campaign |

## Key CLI Flags

| Flag | Description |
|------|-------------|
| `--grammar_file` | Path to compiled grammar.py |
| `--dictionary_file` | Custom fuzzing dictionary (dict.json) |
| `--settings` | Engine settings JSON file |
| `--target_ip` | Target API hostname or IP |
| `--target_port` | Target API port |
| `--time_budget` | Max hours to run (fuzz/fuzz-lean) |
| `--enable_checkers` | Space-separated checker names |
| `--no_ssl` | Disable TLS verification |

## Security Checkers

| Checker | Detects |
|---------|---------|
| UseAfterFree | Accessing deleted resources |
| NamespaceRule | Cross-tenant data access |
| ResourceHierarchy | Wrong parent resource ID access |
| LeakageRule | Sensitive data in error responses |
| InvalidDynamicObject | Malformed object ID handling |
| PayloadBody | Request body injection flaws |

## Output Directory Structure

| Path | Contents |
|------|----------|
| `ResponseBuckets/runSummary.json` | Aggregated run statistics |
| `bug_buckets/` | Individual bug report files |
| `Compile/grammar.py` | Generated fuzzing grammar |
| `Compile/dict.json` | Fuzzing dictionary |

## External References

- [RESTler GitHub](https://github.com/microsoft/restler-fuzzer)
- [RESTler Research Paper](https://patricegodefroid.github.io/public_psfiles/icse2019.pdf)
- [Schemathesis Alternative](https://github.com/schemathesis/schemathesis)
