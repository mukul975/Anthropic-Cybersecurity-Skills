# Docker Daemon Hardening Checklist

## Pre-Hardening

- [ ] Document current daemon.json configuration
- [ ] Run Docker Bench Security baseline
- [ ] Identify running containers that may be affected
- [ ] Schedule maintenance window
- [ ] Backup existing /etc/docker/daemon.json

## CIS Docker Benchmark v1.6 - Daemon Checks

### Critical
- [ ] 2.2 - Disable inter-container communication (`"icc": false`)
- [ ] 2.9 - Enable user namespace remapping (`"userns-remap": "default"`)
- [ ] 2.14 - Restrict new privileges (`"no-new-privileges": true`)
- [ ] 2.7 - Configure TLS authentication (if remote access needed)

### High
- [ ] 2.6 - Use overlay2 storage driver
- [ ] 2.16 - Disable userland proxy
- [ ] 2.13 - Configure centralized logging
- [ ] 2.8 - Set default ulimits
- [ ] 2.17 - Apply custom seccomp profile

### Medium
- [ ] 2.15 - Enable live restore
- [ ] 2.1 - Consider rootless mode
- [ ] Docker socket permissions set to 660

## Post-Hardening Verification

- [ ] Docker daemon restarts successfully
- [ ] All containers start correctly
- [ ] Docker Bench shows improved score
- [ ] TLS connection works (if configured)
- [ ] Monitoring endpoints accessible
- [ ] Log rotation working

## Recommended daemon.json

```json
{
  "icc": false,
  "userns-remap": "default",
  "no-new-privileges": true,
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "5" },
  "storage-driver": "overlay2",
  "live-restore": true,
  "userland-proxy": false,
  "experimental": false
}
```

## Rollback Plan

1. Stop Docker daemon: `sudo systemctl stop docker`
2. Restore backup: `sudo cp /etc/docker/daemon.json.bak /etc/docker/daemon.json`
3. Start Docker daemon: `sudo systemctl start docker`
4. Verify containers: `docker ps`
