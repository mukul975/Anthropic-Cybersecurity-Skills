# API Reference: Implementing Immutable Backup with Restic

## Core Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `init_repository(repo_url, password, s3_config)` | Repository URL, password, optional S3 credentials | Init result dict |
| `create_backup(repo_url, password, source_paths, tags, exclude)` | Repo, password, paths list, optional tags/excludes | Snapshot summary |
| `verify_backup_integrity(repo_url, password, read_data)` | Repo, password, whether to verify data blobs | Verification result |
| `list_snapshots(repo_url, password)` | Repo, password | Snapshot list with metadata |
| `apply_retention_policy(repo_url, password, keep_*)` | Repo, password, retention counts | Pruning result |
| `test_restore(repo_url, password, snapshot_id)` | Repo, password, snapshot to restore | Restore test result |
| `get_repository_stats(repo_url, password)` | Repo, password | Size, dedup ratio, file count |

## S3 Object Lock Configuration

| Function | Parameters | Returns |
|----------|-----------|---------|
| `configure_s3_object_lock(bucket, retention_days, mode)` | Bucket name, days, COMPLIANCE or GOVERNANCE | Config result |

## Restic Commands Wrapped

| Command | Description |
|---------|-------------|
| `restic init` | Initialize encrypted repository |
| `restic backup --json` | Create snapshot with JSON progress |
| `restic check --read-data` | Full integrity verification |
| `restic snapshots --json` | List snapshots |
| `restic forget --prune` | Apply retention and reclaim space |
| `restic restore` | Extract files from snapshot |
| `restic stats --json` | Repository size statistics |

## CLI Usage

```bash
# Initialize repository
python agent.py --repo s3:s3.amazonaws.com/my-backups --action init

# Backup with tags
python agent.py --repo s3:s3.amazonaws.com/my-backups --action backup \
  --source /var/lib/postgresql /etc --tags database config

# Full pipeline: backup + verify + retention + restore test
python agent.py --repo s3:s3.amazonaws.com/my-backups --action full-pipeline \
  --source /srv/data --keep-daily 7 --keep-weekly 4
```

## Retention Policy Defaults

| Parameter | Default | Description |
|-----------|---------|-------------|
| `keep-daily` | 7 | Keep 7 daily snapshots |
| `keep-weekly` | 4 | Keep 4 weekly snapshots |
| `keep-monthly` | 12 | Keep 12 monthly snapshots |
| `keep-yearly` | 2 | Keep 2 yearly snapshots |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute restic CLI commands |
| `hashlib` | stdlib | SHA-256 verification of restored files |
| `tempfile` | stdlib | Temporary restore target directories |
| `json` | stdlib | Parse restic JSON output |

## References

- Restic Documentation: https://restic.readthedocs.io/
- AWS S3 Object Lock: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
- resticpy Python Wrapper: https://mtlynch.github.io/resticpy/
- Veeam 3-2-1-1-0 Strategy: https://www.veeam.com/blog/321-backup-rule.html
