# API Reference: Docker Daemon Configuration Hardening

## daemon.json Location
- Linux: `/etc/docker/daemon.json`
- Windows: `C:\ProgramData\docker\config\daemon.json`

## Recommended daemon.json
```json
{
  "icc": false,
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "userns-remap": "default",
  "log-driver": "json-file",
  "log-opts": {"max-size": "10m", "max-file": "3"},
  "tls": true,
  "tlsverify": true,
  "tlscacert": "/etc/docker/ca.pem",
  "tlscert": "/etc/docker/server-cert.pem",
  "tlskey": "/etc/docker/server-key.pem"
}
```

## CIS Docker Benchmark — Daemon Settings

| CIS # | Setting | Recommendation |
|-------|---------|---------------|
| 2.1 | `icc` | Set to `false` |
| 2.2 | `live-restore` | Set to `true` |
| 2.3 | `userland-proxy` | Set to `false` |
| 2.4 | `no-new-privileges` | Set to `true` |
| 2.6 | TLS | Enable with certificates |
| 2.8 | `userns-remap` | Set to `default` |
| 2.12 | Logging | Configure centralized logging |

## File Permission Checks

| File | Permissions |
|------|------------|
| `/etc/docker/daemon.json` | 644 |
| `/var/run/docker.sock` | 660 |
| `/etc/docker/certs.d/` | 444 |
| Docker service files | 644 |

## Docker Socket Security

### Check permissions
```bash
ls -la /var/run/docker.sock
# srw-rw---- 1 root docker 0 ... /var/run/docker.sock
```

### Restrict group access
```bash
chmod 660 /var/run/docker.sock
chown root:docker /var/run/docker.sock
```

## Content Trust (Image Signing)

### Enable globally
```bash
export DOCKER_CONTENT_TRUST=1
```

### In daemon.json
```json
{"content-trust": {"mode": "enforced"}}
```

## Docker Info Command
```bash
docker info --format '{{json .}}'
```

### Key Fields
| Field | Description |
|-------|-------------|
| `SecurityOptions` | seccomp, apparmor, userns |
| `LiveRestoreEnabled` | Live restore status |
| `RegistryConfig.InsecureRegistryCIDRs` | Insecure registries |
| `ServerVersion` | Docker version |
