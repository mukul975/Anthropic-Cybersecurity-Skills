---
name: hardening-docker-daemon-configuration
description: Harden the Docker daemon by configuring daemon.json with user namespace remapping, TLS authentication, rootless mode, and CIS benchmark controls.
domain: cybersecurity
subdomain: container-security
tags: [docker, daemon-hardening, container-security, cis-benchmark, rootless, userns-remap]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Hardening Docker Daemon Configuration

## Overview

The Docker daemon (`dockerd`) runs with root privileges and controls all container operations. Hardening its configuration through `/etc/docker/daemon.json`, TLS certificates, user namespace remapping, and network restrictions is essential to prevent privilege escalation, lateral movement, and container breakout attacks.

## Prerequisites

- Docker Engine 24.0+ installed
- Root or sudo access to the Docker host
- OpenSSL for TLS certificate generation
- Understanding of Linux namespaces and cgroups

## Core Hardened daemon.json

```json
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
    "nofile": {
      "Name": "nofile",
      "Hard": 65536,
      "Soft": 32768
    },
    "nproc": {
      "Name": "nproc",
      "Hard": 4096,
      "Soft": 2048
    }
  },
  "seccomp-profile": "/etc/docker/seccomp/default.json",
  "default-address-pools": [
    {
      "base": "172.17.0.0/16",
      "size": 24
    }
  ],
  "iptables": true,
  "ip-forward": true,
  "ip-masq": true,
  "experimental": false,
  "metrics-addr": "127.0.0.1:9323",
  "max-concurrent-downloads": 3,
  "max-concurrent-uploads": 5,
  "default-runtime": "runc",
  "runtimes": {
    "runsc": {
      "path": "/usr/local/bin/runsc",
      "runtimeArgs": ["--platform=ptrace"]
    }
  }
}
```

## Setting-by-Setting Explanation

### Disable Inter-Container Communication (ICC)

```json
{
  "icc": false
}
```

Prevents containers on the default bridge network from communicating. Each container must use explicit `--link` or user-defined networks with published ports.

### Enable User Namespace Remapping

```json
{
  "userns-remap": "default"
}
```

Maps container root (UID 0) to a high unprivileged UID on the host. This prevents a container breakout from gaining root on the host.

```bash
# Verify userns-remap is active
cat /etc/subuid
# Output: dockremap:100000:65536

cat /etc/subgid
# Output: dockremap:100000:65536

# Verify container UID mapping
docker run --rm alpine id
# uid=0(root) gid=0(root) -- but host UID is 100000+
```

### Disable New Privilege Escalation

```json
{
  "no-new-privileges": true
}
```

Prevents container processes from gaining additional privileges via setuid/setgid binaries or capability escalation.

### Enable Live Restore

```json
{
  "live-restore": true
}
```

Keeps containers running during daemon downtime, enabling daemon upgrades without container restart.

### Disable Userland Proxy

```json
{
  "userland-proxy": false
}
```

Uses iptables rules instead of docker-proxy for port forwarding, reducing attack surface and improving performance.

## TLS Configuration for Remote Docker API

### Generate CA and Server Certificates

```bash
# Create CA
openssl genrsa -aes256 -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem \
  -subj "/CN=Docker CA"

# Create server key and CSR
openssl genrsa -out server-key.pem 4096
openssl req -subj "/CN=docker-host" -sha256 -new -key server-key.pem -out server.csr

# Create extfile with SANs
echo "subjectAltName = DNS:docker-host,IP:10.0.0.5,IP:127.0.0.1" > extfile.cnf
echo "extendedKeyUsage = serverAuth" >> extfile.cnf

# Sign server certificate
openssl x509 -req -days 365 -sha256 -in server.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -extfile extfile.cnf

# Create client key and certificate
openssl genrsa -out key.pem 4096
openssl req -subj "/CN=client" -new -key key.pem -out client.csr
echo "extendedKeyUsage = clientAuth" > extfile-client.cnf
openssl x509 -req -days 365 -sha256 -in client.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out cert.pem -extfile extfile-client.cnf

# Set permissions
chmod 0400 ca-key.pem key.pem server-key.pem
chmod 0444 ca.pem server-cert.pem cert.pem

# Move to Docker TLS directory
sudo mkdir -p /etc/docker/tls
sudo cp ca.pem server-cert.pem server-key.pem /etc/docker/tls/
```

### Configure daemon.json for TLS

```json
{
  "tls": true,
  "tlsverify": true,
  "tlscacert": "/etc/docker/tls/ca.pem",
  "tlscert": "/etc/docker/tls/server-cert.pem",
  "tlskey": "/etc/docker/tls/server-key.pem",
  "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2376"]
}
```

### Client Connection

```bash
docker --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=cert.pem \
  --tlskey=key.pem \
  -H=tcp://docker-host:2376 version
```

## Docker Socket Protection

```bash
# Restrict socket ownership
sudo chown root:docker /var/run/docker.sock
sudo chmod 660 /var/run/docker.sock

# Audit Docker socket access
sudo auditctl -w /var/run/docker.sock -k docker-socket

# Never mount Docker socket into containers
# BAD: docker run -v /var/run/docker.sock:/var/run/docker.sock ...
```

## Rootless Docker

```bash
# Install rootless Docker
curl -fsSL https://get.docker.com/rootless | sh

# Configure environment
export PATH=$HOME/bin:$PATH
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock

# Start rootless daemon
systemctl --user start docker
systemctl --user enable docker

# Verify rootless mode
docker info | grep -i rootless
# Rootless: true
```

## Content Trust (Image Signing)

```bash
# Enable Docker Content Trust
export DOCKER_CONTENT_TRUST=1

# Pull only signed images
docker pull library/alpine:3.18
# Will fail if image is not signed

# Sign and push image
docker trust sign myregistry/myapp:1.0
```

## Seccomp Profile

```bash
# View default seccomp profile
docker info --format '{{.SecurityOptions}}'

# Use custom seccomp profile
docker run --security-opt seccomp=/etc/docker/seccomp/custom.json alpine

# Verify seccomp is enabled
docker inspect --format='{{.HostConfig.SecurityOpt}}' container_name
```

## AppArmor Profile

```bash
# Check AppArmor status
sudo aa-status

# Use custom AppArmor profile
docker run --security-opt apparmor=docker-custom alpine

# Load custom profile
sudo apparmor_parser -r /etc/apparmor.d/docker-custom
```

## Verification Commands

```bash
# Check daemon configuration
docker info

# Verify userns-remap
docker info --format '{{.SecurityOptions}}'

# Check ICC setting
docker network inspect bridge --format '{{.Options}}'

# Audit with Docker Bench
docker run --rm --net host --pid host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /etc:/etc:ro \
  docker/docker-bench-security
```

## Best Practices

1. **Never expose Docker daemon without TLS** - Always use `--tlsverify` for remote access
2. **Enable user namespace remapping** - Map container root to unprivileged host UID
3. **Disable ICC** - Prevent default bridge network container-to-container communication
4. **Use rootless mode** - Run Docker daemon as non-root where possible
5. **Enable content trust** - Only pull signed images
6. **Configure log rotation** - Prevent log files from filling disk
7. **Use seccomp profiles** - Restrict syscalls available to containers
8. **Audit Docker socket** - Monitor access to /var/run/docker.sock
9. **Run Docker Bench regularly** - Automate CIS benchmark checks
10. **Keep Docker updated** - Apply security patches promptly
