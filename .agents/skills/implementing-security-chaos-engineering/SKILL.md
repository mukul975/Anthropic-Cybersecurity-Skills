---
name: implementing-security-chaos-engineering
description: >
  Implements security chaos engineering experiments that deliberately disable or degrade
  security controls to verify detection and response capabilities. Tests WAF bypass,
  firewall rule removal, log pipeline disruption, and EDR disablement scenarios using
  boto3 and subprocess. Use when validating SOC detection coverage and resilience.
domain: cybersecurity
subdomain: security-operations
tags: [implementing, security, chaos, engineering]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Security Chaos Engineering

## Instructions

Design and execute security chaos experiments that intentionally break security
controls to verify that detection, alerting, and response systems work correctly.

```python
# Example: Verify detection when a security group is opened
import boto3
ec2 = boto3.client("ec2")

# Chaos experiment: temporarily add 0.0.0.0/0 rule
ec2.authorize_security_group_ingress(
    GroupId="sg-12345",
    IpProtocol="tcp", FromPort=22, ToPort=22,
    CidrIp="0.0.0.0/0",
)
# Verify: does GuardDuty/Config alert fire within SLA?
# Rollback: remove the rule after verification
```

Key experiments:
1. Open a security group and verify Config Rule alerts
2. Disable CloudTrail and verify detection time
3. Create IAM admin user and verify alert triggers
4. Simulate log pipeline failure and check monitoring gaps
5. Deploy test malware hash and verify EDR response

## Examples

```python
# Rollback function for safe experiment execution
def run_experiment(setup_fn, verify_fn, rollback_fn, timeout=300):
    try:
        setup_fn()
        result = verify_fn(timeout)
    finally:
        rollback_fn()
    return result
```
