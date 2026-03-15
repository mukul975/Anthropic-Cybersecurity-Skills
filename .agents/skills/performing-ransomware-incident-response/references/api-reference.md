# Ransomware Incident Response - API Reference

## File System Scanning

### Ransomware Extensions
Common encrypted file extensions: `.encrypted`, `.locked`, `.crypt`, `.locky`, `.cerber`, `.zepto`, `.wncry`, `.wnry`, `.wcry`, `.onion`, `.micro`, `.r5a`

### Ransom Note Filenames
Common patterns: `readme.txt`, `how_to_decrypt.txt`, `decrypt_instructions.html`, `restore_files.txt`, `_readme.txt`, `how_to_recover.txt`

## IOC Collection

### hashlib (Python stdlib)
```python
sha = hashlib.sha256()
with open(path, "rb") as f:
    for chunk in iter(lambda: f.read(8192), b""):
        sha.update(chunk)
sha.hexdigest()
```

### ID Ransomware Identification
Upload ransom note or encrypted file sample to id-ransomware.malwarehunterteam.com for variant identification.

## Shadow Copy Detection (Windows)

```bash
vssadmin list shadows
```

Ransomware commonly deletes shadow copies via:
```bash
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
```

## Containment Checklist

1. Network isolation - Disable NICs or move to quarantine VLAN
2. Evidence preservation - Disk image before remediation
3. Credential reset - krbtgt (twice), DA accounts, service accounts
4. Scope assessment - Enumerate affected hosts and shares
5. Variant identification - Submit IOCs to threat intel platforms
6. Recovery - Restore from clean backups after root cause confirmed

## Output Schema

```json
{
  "report": "ransomware_incident_response",
  "encrypted_files_found": 342,
  "ransom_notes_found": 5,
  "shadow_copy_status": {"intact": false, "shadow_copies": 0},
  "containment_actions": [{"priority": 1, "action": "Isolate affected hosts"}],
  "file_hashes": [{"path": "/data/file.encrypted", "sha256": "abc123..."}]
}
```

## CLI Usage

```bash
python agent.py --target /mnt/affected_share --max-files 5000 --output report.json
```
