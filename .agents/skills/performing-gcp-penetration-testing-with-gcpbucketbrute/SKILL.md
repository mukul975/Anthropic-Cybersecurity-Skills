---
name: performing-gcp-penetration-testing-with-gcpbucketbrute
description: Perform GCP security testing using GCPBucketBrute for storage bucket enumeration, gcloud IAM privilege escalation path analysis, and service account permission auditing
domain: cybersecurity
subdomain: cloud-security
tags: [gcp, cloud-pentesting, bucket-enumeration, iam-audit, privilege-escalation, gcpbucketbrute]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing GCP Penetration Testing with GCPBucketBrute

## Overview

This skill covers Google Cloud Platform security testing using GCPBucketBrute for storage bucket enumeration and access permission testing, combined with gcloud CLI IAM enumeration to identify privilege escalation paths. The approach tests for publicly accessible buckets, overly permissive IAM bindings, and service account key exposure.

## Prerequisites

- Python 3.8+ with google-cloud-storage library
- GCPBucketBrute installed from RhinoSecurityLabs GitHub
- gcloud CLI authenticated with test credentials
- Authorized penetration testing scope for target GCP project
- google-api-python-client and google-auth libraries

## Steps

1. **Enumerate Storage Buckets** — Use GCPBucketBrute with keyword permutations to discover accessible GCP storage buckets
2. **Test Bucket Permissions** — Call TestIamPermissions API on each discovered bucket to determine read/write/admin access levels
3. **Audit IAM Bindings** — Enumerate project-level IAM policies to identify overly permissive role bindings
4. **Check Service Account Keys** — Identify service accounts with user-managed keys and test for privilege escalation via impersonation
5. **Test Privilege Escalation Paths** — Check for iam.serviceAccounts.actAs, setIamPolicy, and other privilege escalation vectors
6. **Generate Findings Report** — Produce a structured security assessment with risk severity ratings

## Expected Output

- JSON report of discovered buckets with permission levels
- IAM privilege escalation path analysis
- Service account security assessment
- Risk-scored findings with remediation recommendations
