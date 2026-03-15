---
name: implementing-syslog-centralization-with-rsyslog
description: >-
  Configure rsyslog for centralized log collection with TLS encryption, custom templates,
  and log rotation. Generates server and client configuration files with GnuTLS stream
  drivers, x509 certificate authentication, per-host log segregation, and reliable
  queue settings for high-availability syslog infrastructure.
domain: cybersecurity
subdomain: security-operations
tags: [implementing, syslog, centralization, with]
version: "1.0"
author: mahipal
license: Apache-2.0
---

## Instructions

1. Install dependencies: `pip install jinja2 paramiko`
2. Generate TLS certificates for rsyslog server and clients using OpenSSL.
3. Run the agent to generate rsyslog server and client configurations:
   - Server: TLS listener on port 6514, per-host directory output, JSON-format templates
   - Client: TLS forwarding with disk-assisted queues for reliability
4. Deploy configurations to servers via SSH (paramiko).
5. Validate TLS connectivity and log delivery.

```bash
python scripts/agent.py --server-ip 10.0.0.1 --clients 10.0.0.10,10.0.0.11 --ca-cert ca.pem --output syslog_report.json
```

## Examples

### Server Configuration (TLS)
```
module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1"
       StreamDriver.Authmode="x509/name")
input(type="imtcp" port="6514")
template(name="PerHostLog" type="string" string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log")
*.* ?PerHostLog
```

### Client Configuration (Reliable Forwarding)
```
action(type="omfwd" target="10.0.0.1" port="6514" protocol="tcp"
       StreamDriver="gtls" StreamDriverMode="1"
       StreamDriverAuthMode="x509/name"
       queue.type="LinkedList" queue.filename="fwdRule1"
       queue.maxdiskspace="1g" queue.saveonshutdown="on"
       action.resumeRetryCount="-1")
```
