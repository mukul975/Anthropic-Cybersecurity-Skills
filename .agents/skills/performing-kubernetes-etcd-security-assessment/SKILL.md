---
name: performing-kubernetes-etcd-security-assessment
description: Assess the security posture of Kubernetes etcd clusters by evaluating encryption at rest, TLS configuration, access controls, backup encryption, and network isolation.
domain: cybersecurity
subdomain: container-security
tags: [kubernetes, etcd, encryption, tls, security-assessment, backup, secrets, control-plane]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Kubernetes etcd Security Assessment

## Overview

etcd is the distributed key-value store that serves as Kubernetes' backing store for all cluster data, including Secrets, RBAC policies, ConfigMaps, and workload configurations. Without proper hardening, etcd exposes all cluster secrets in plaintext, making it the highest-value target for attackers who gain control plane access. A comprehensive security assessment covers encryption at rest, TLS for transport, access control, backup security, and network isolation.

## Prerequisites

- Access to Kubernetes control plane nodes
- SSH access to etcd cluster nodes (or etcdctl configured)
- CIS Kubernetes Benchmark reference document
- Understanding of TLS certificate management and EncryptionConfiguration

## Assessment Areas

### 1. Encryption at Rest

Verify that Kubernetes encrypts Secret data stored in etcd:

```bash
# Check if EncryptionConfiguration is configured on API server
ps aux | grep kube-apiserver | grep encryption-provider-config

# View the encryption configuration
cat /etc/kubernetes/enc/encryption-config.yaml
```

Expected secure configuration:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      - configmaps
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-32-byte-key>
      - identity: {}  # Fallback for reading unencrypted data
```

Verify secrets are actually encrypted in etcd:

```bash
# Read a secret directly from etcd
ETCDCTL_API=3 etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/default/my-secret | hexdump -C | head -20

# If encrypted, output starts with "k8s:enc:aescbc:v1:key1"
# If NOT encrypted, you'll see plaintext key-value pairs
```

### 2. TLS Transport Security

```bash
# Verify etcd uses TLS for client connections
ETCDCTL_API=3 etcdctl endpoint health \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key

# Check peer TLS configuration
ps aux | grep etcd | tr ' ' '\n' | grep -E "peer-cert|peer-key|peer-trusted-ca"

# Verify certificate expiration
openssl x509 -in /etc/kubernetes/pki/etcd/server.crt -noout -enddate
openssl x509 -in /etc/kubernetes/pki/etcd/peer.crt -noout -enddate
```

Expected flags:

| Flag | Required Value | Purpose |
|------|---------------|---------|
| `--cert-file` | Path to server cert | Client-to-server TLS |
| `--key-file` | Path to server key | Client-to-server TLS |
| `--trusted-ca-file` | Path to CA cert | Client certificate validation |
| `--peer-cert-file` | Path to peer cert | Peer-to-peer TLS |
| `--peer-key-file` | Path to peer key | Peer-to-peer TLS |
| `--peer-trusted-ca-file` | Path to peer CA | Peer certificate validation |
| `--client-cert-auth` | true | Require client certificates |
| `--peer-client-cert-auth` | true | Require peer certificates |

### 3. Access Control

```bash
# Verify etcd is not exposed on all interfaces
ps aux | grep etcd | tr ' ' '\n' | grep listen-client-urls
# Should be: https://127.0.0.1:2379 (not 0.0.0.0)

# Check who can access etcd certificates
ls -la /etc/kubernetes/pki/etcd/
# Should be readable only by root/etcd user

# Verify API server is the only etcd client
ss -tlnp | grep 2379
# Only kube-apiserver should have connections
```

### 4. Backup Security

```bash
# Create an encrypted etcd backup
ETCDCTL_API=3 etcdctl snapshot save /backup/etcd-snapshot.db \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key

# Encrypt the backup file
gpg --symmetric --cipher-algo AES256 /backup/etcd-snapshot.db

# Verify backup integrity
ETCDCTL_API=3 etcdctl snapshot status /backup/etcd-snapshot.db --write-out=table
```

### 5. Network Isolation

```bash
# Verify etcd ports are firewalled
iptables -L -n | grep -E "2379|2380"

# Check if etcd is accessible from worker nodes (should NOT be)
# Run from a worker node:
curl -k https://<control-plane-ip>:2379/health
# Should be rejected/timeout
```

## CIS Benchmark Checks

| CIS Control | Check | Expected Result |
|-------------|-------|----------------|
| 2.1 | etcd cert-file set | TLS certificate configured |
| 2.2 | etcd client-cert-auth | Client certificate authentication enabled |
| 2.3 | etcd auto-tls disabled | auto-tls=false |
| 2.4 | etcd peer cert-file set | Peer TLS configured |
| 2.5 | etcd peer client-cert-auth | Peer authentication enabled |
| 2.6 | etcd peer auto-tls disabled | peer-auto-tls=false |
| 2.7 | etcd unique CA | Separate CA for etcd (not shared with cluster) |

## Key Rotation Procedure

```bash
# 1. Generate new encryption key
NEW_KEY=$(head -c 32 /dev/urandom | base64)

# 2. Update EncryptionConfiguration with new key first
cat > /etc/kubernetes/enc/encryption-config.yaml <<EOF
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key2
              secret: ${NEW_KEY}
            - name: key1
              secret: <old-key>
      - identity: {}
EOF

# 3. Restart API server to pick up new config
# 4. Re-encrypt all secrets with new key
kubectl get secrets --all-namespaces -o json | \
  kubectl replace -f -

# 5. Remove old key from EncryptionConfiguration
# 6. Restart API server again
```

## References

- [Kubernetes etcd Encryption Documentation](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
- [CIS Kubernetes Benchmark - etcd Controls](https://www.cisecurity.org/benchmark/kubernetes)
- [Securing etcd - K8s Security Guide](https://k8s-security.geek-kb.com/docs/best_practices/cluster_setup_and_hardening/control_plane_security/etcd_security_mitigation/)
- [Infosec: Encryption and etcd](https://www.infosecinstitute.com/resources/cryptography/encryption-and-etcd-the-key-to-securing-kubernetes/)
