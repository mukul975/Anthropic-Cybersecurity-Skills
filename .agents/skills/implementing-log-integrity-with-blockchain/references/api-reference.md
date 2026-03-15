# API Reference: Log Integrity with Blockchain Hash Chaining

## hashlib - SHA-256 Hashing
```python
import hashlib
hash_hex = hashlib.sha256("data".encode("utf-8")).hexdigest()
# Returns 64-char hex string
```

## Chain Entry Structure
```json
{
  "index": 0,
  "timestamp": "2024-01-15T10:30:00.000Z",
  "content_hash": "SHA256(log_entry_text)",
  "prev_hash": "0000...0000 (genesis) or previous chain_hash",
  "chain_hash": "SHA256(prev_hash + timestamp + content_hash)",
  "content_preview": "first 200 chars of log entry"
}
```

## Chain Construction Algorithm
```
genesis_hash = "0" * 64
for each log_entry:
    content_hash = SHA256(log_entry)
    chain_hash = SHA256(prev_hash + timestamp + content_hash)
    store(index, timestamp, content_hash, prev_hash, chain_hash)
    prev_hash = chain_hash
```

## Verification Algorithm
```
prev_hash = genesis_hash
for each entry in chain:
    expected = SHA256(prev_hash + entry.timestamp + entry.content_hash)
    if expected != entry.chain_hash:
        TAMPER DETECTED at index
    prev_hash = entry.chain_hash
```

## Checkpoint Structure
```json
{
  "timestamp": "2024-01-15T12:00:00Z",
  "chain_length": 1000,
  "head_hash": "chain_hash of last entry",
  "head_index": 999,
  "checkpoint_hash": "SHA256(chain_length + head_hash)"
}
```

## Tamper Detection Properties
- Modifying any entry invalidates all subsequent chain_hashes
- First break index identifies the tampered entry
- Checkpoint comparison detects retroactive modifications
