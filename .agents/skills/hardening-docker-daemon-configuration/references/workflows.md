# Workflow - Hardening Docker Daemon Configuration

## Phase 1: Baseline Assessment

```bash
# Check current Docker daemon configuration
docker info
docker system info --format '{{json .SecurityOptions}}'

# Check existing daemon.json
cat /etc/docker/daemon.json 2>/dev/null || echo "No daemon.json found"

# Run Docker Bench Security for baseline
docker run --rm --net host --pid host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /etc:/etc:ro \
  docker/docker-bench-security 2>&1 | tee docker-bench-baseline.txt
```

## Phase 2: Apply Hardened Configuration

### Step 1 - Backup Current Config
```bash
sudo cp /etc/docker/daemon.json /etc/docker/daemon.json.bak 2>/dev/null
```

### Step 2 - Deploy Hardened daemon.json
```bash
sudo tee /etc/docker/daemon.json <<'EOF'
{
  "icc": false,
  "userns-remap": "default",
  "no-new-privileges": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "5"
  },
  "storage-driver": "overlay2",
  "live-restore": true,
  "userland-proxy": false,
  "default-ulimits": {
    "nofile": { "Name": "nofile", "Hard": 65536, "Soft": 32768 },
    "nproc": { "Name": "nproc", "Hard": 4096, "Soft": 2048 }
  },
  "experimental": false,
  "metrics-addr": "127.0.0.1:9323"
}
EOF
```

### Step 3 - Restart Docker Daemon
```bash
sudo systemctl restart docker
sudo systemctl status docker
```

### Step 4 - Verify Settings
```bash
docker info | grep -E "(Remap|ICC|Live Restore|Security)"
```

## Phase 3: TLS Configuration

```bash
# Generate certificates (see SKILL.md for full commands)
# Deploy to /etc/docker/tls/

# Add TLS to daemon.json
sudo jq '. + {
  "tls": true,
  "tlsverify": true,
  "tlscacert": "/etc/docker/tls/ca.pem",
  "tlscert": "/etc/docker/tls/server-cert.pem",
  "tlskey": "/etc/docker/tls/server-key.pem",
  "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2376"]
}' /etc/docker/daemon.json | sudo tee /etc/docker/daemon.json.new
sudo mv /etc/docker/daemon.json.new /etc/docker/daemon.json

sudo systemctl restart docker
```

## Phase 4: Post-Hardening Validation

```bash
# Run Docker Bench again
docker run --rm --net host --pid host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /etc:/etc:ro \
  docker/docker-bench-security 2>&1 | tee docker-bench-hardened.txt

# Compare results
diff docker-bench-baseline.txt docker-bench-hardened.txt
```

## Phase 5: Ongoing Monitoring

```bash
# Setup auditd rules for Docker
sudo auditctl -w /var/run/docker.sock -k docker
sudo auditctl -w /etc/docker -p wa -k docker-config
sudo auditctl -w /usr/bin/docker -k docker-binary
sudo auditctl -w /var/lib/docker -k docker-data

# Monitor Docker metrics
curl -s http://127.0.0.1:9323/metrics | head -20
```
