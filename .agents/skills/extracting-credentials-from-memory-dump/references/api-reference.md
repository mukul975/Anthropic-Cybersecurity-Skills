# API Reference: Memory Dump Credential Extraction Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| volatility3 | >=2.0 | Memory forensics framework (invoked via subprocess) |
| pypykatz | >=0.6 | Python Mimikatz for LSASS credential extraction |

## CLI Usage

```bash
python scripts/agent.py \
  --dump /cases/case-001/memory.raw \
  --output-dir /cases/case-001/analysis/ \
  --output credential_report.json
```

## Functions

### `verify_dump(dump_path) -> dict`
Checks file existence, computes size and SHA-256 of first 1MB for integrity.

### `run_vol3(dump_path, plugin, extra_args) -> str`
Executes a volatility3 plugin via subprocess with 5-minute timeout. Returns stdout.

### `get_os_info(dump_path) -> dict`
Runs `windows.info` to identify OS version and build from the memory image.

### `find_lsass_pid(dump_path) -> int`
Runs `windows.pslist` and locates the LSASS process PID.

### `extract_hashdump(dump_path) -> list`
Runs `windows.hashdump` to extract SAM database NTLM hashes for local accounts.

### `extract_lsadump(dump_path) -> list`
Runs `windows.lsadump` to extract LSA secrets (service account passwords).

### `extract_cachedump(dump_path) -> list`
Runs `windows.cachedump` to extract DCC2 cached domain credential hashes.

### `run_pypykatz(dump_path, output_dir) -> dict`
Invokes pypykatz in JSON mode against LSASS minidump or full memory image.

### `parse_pypykatz_creds(pypykatz_data) -> list`
Parses pypykatz JSON output into structured credential list with NTLM, Kerberos, WDigest, DPAPI.

### `search_cloud_keys(dump_path) -> list`
Uses `windows.strings` to find AWS keys, JWT tokens, and auth strings in memory.

### `generate_report(dump_path, output_dir) -> dict`
Orchestrates all extraction steps and compiles the final report with summary and actions.

## Volatility3 Plugins Used

| Plugin | Purpose |
|--------|---------|
| `windows.info` | OS identification |
| `windows.pslist` | Process listing (find LSASS PID) |
| `windows.hashdump` | SAM hash extraction |
| `windows.lsadump` | LSA secret extraction |
| `windows.cachedump` | Cached domain credential extraction |
| `windows.strings` | String search for cloud keys and tokens |

## Output Schema

```json
{
  "source": "/cases/memory.raw",
  "sam_hashes": [{"user": "Administrator", "rid": 500, "ntlm_hash": "fc52..."}],
  "lsass_creds": [{"user": "CORP\\admin", "cred_types": [{"type": "NTLM", "hash": "..."}]}],
  "cloud_keys": [{"type": "AWS Access Key", "value": "AKIA..."}],
  "summary": {"sam_hashes": 4, "lsass_creds": 3, "cloud_keys": 1},
  "actions": ["Reset passwords for all local accounts..."]
}
```
