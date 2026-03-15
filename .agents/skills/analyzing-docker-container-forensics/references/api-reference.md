# API Reference: Docker Container Forensics Tools

## docker inspect - Container Details

### Syntax
```bash
docker inspect <container_id>
docker inspect --format '{{.HostConfig.Privileged}}' <container_id>
docker inspect --format '{{json .Mounts}}' <container_id> | jq
docker inspect --format '{{.GraphDriver.Data.MergedDir}}' <container_id>
```

### Key JSON Paths
| Path | Description |
|------|-------------|
| `.HostConfig.Privileged` | Privileged mode status |
| `.HostConfig.CapAdd` | Added capabilities |
| `.HostConfig.PidMode` | PID namespace mode |
| `.HostConfig.NetworkMode` | Network namespace mode |
| `.Mounts` | Volume mount configuration |
| `.Config.User` | Container user |
| `.Config.Env` | Environment variables |
| `.Config.Image` | Source image name |
| `.State.StartedAt` | Container start time |

## docker diff - Filesystem Changes

### Syntax
```bash
docker diff <container_id>
```

### Output Codes
| Code | Meaning |
|------|---------|
| `A` | File or directory was added |
| `C` | File or directory was changed |
| `D` | File or directory was deleted |

## docker export - Container Filesystem Export

### Syntax
```bash
docker export <container_id> > container_fs.tar
docker export <container_id> | gzip > container_fs.tar.gz
```

## docker commit / docker save - Image Preservation

### Syntax
```bash
docker commit <container_id> forensic-evidence:case001
docker save forensic-evidence:case001 > evidence_image.tar
```

## docker logs - Container Log Retrieval

### Syntax
```bash
docker logs --timestamps <container_id>
docker logs --since 2024-01-15 <container_id>
docker logs --tail 1000 <container_id>
docker logs -f <container_id>   # Follow (live)
```

## dive - Image Layer Analysis

### Syntax
```bash
dive <image_name>                      # Interactive mode
dive <image_name> --ci                 # CI mode (non-interactive)
dive <image_name> --ci --json out.json # JSON output
```

### Output Includes
- Layer-by-layer filesystem changes
- Image efficiency score
- Wasted space analysis

## container-diff - Image Comparison

### Syntax
```bash
container-diff diff daemon://nginx:latest daemon://suspect:latest \
  --type=file --type=apt --type=history --json
```

### Diff Types
| Type | Description |
|------|-------------|
| `file` | File system differences |
| `apt` | APT package differences |
| `pip` | Python package differences |
| `history` | Docker build history differences |

## Trivy - Vulnerability Scanning

### Syntax
```bash
trivy image <image_name>
trivy image --format json <image_name>
trivy image --scanners vuln,secret <image_name>
trivy fs /path/to/exported/container/
```

### Severity Levels
`CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `UNKNOWN`

## docker-explorer - Offline Forensics

### Syntax
```bash
de.py -r /var/lib/docker list
de.py -r /var/lib/docker mount <container_id> /mnt/forensic
de.py -r /var/lib/docker history <container_id>
```
