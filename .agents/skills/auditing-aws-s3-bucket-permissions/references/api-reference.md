# API Reference: Auditing AWS S3 Bucket Permissions

## boto3 S3 Client

### List Buckets

```python
import boto3
s3 = boto3.client("s3")
response = s3.list_buckets()
for bucket in response["Buckets"]:
    print(bucket["Name"], bucket["CreationDate"])
```

### Get Bucket ACL

```python
acl = s3.get_bucket_acl(Bucket="my-bucket")
for grant in acl["Grants"]:
    print(grant["Grantee"], grant["Permission"])
```

### Get/Put Public Access Block

```python
# Check settings
resp = s3.get_public_access_block(Bucket="my-bucket")
config = resp["PublicAccessBlockConfiguration"]

# Enable all blocks
s3.put_public_access_block(
    Bucket="my-bucket",
    PublicAccessBlockConfiguration={
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    },
)
```

### Get Bucket Policy

```python
import json
policy_str = s3.get_bucket_policy(Bucket="my-bucket")["Policy"]
policy = json.loads(policy_str)
for stmt in policy["Statement"]:
    print(stmt["Effect"], stmt["Principal"], stmt["Action"])
```

### Check Encryption

```python
enc = s3.get_bucket_encryption(Bucket="my-bucket")
rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
print(rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"])
```

### Check Versioning

```python
resp = s3.get_bucket_versioning(Bucket="my-bucket")
print(resp.get("Status", "Disabled"))
```

## Key S3 API Methods for Security Auditing

| Method | Returns |
|--------|---------|
| `list_buckets()` | All buckets in account |
| `get_bucket_acl()` | ACL grants (AllUsers, AuthenticatedUsers) |
| `get_public_access_block()` | Block public access configuration |
| `get_bucket_policy()` | Bucket policy JSON (wildcard principals) |
| `get_bucket_encryption()` | Default encryption algorithm |
| `get_bucket_versioning()` | Versioning status |
| `get_bucket_logging()` | Access logging configuration |
| `get_bucket_location()` | Bucket region |

## Public Grant URIs to Flag

| URI | Risk |
|-----|------|
| `http://acs.amazonaws.com/groups/global/AllUsers` | Public read/write |
| `http://acs.amazonaws.com/groups/global/AuthenticatedUsers` | Any AWS account |

### References

- boto3 S3 docs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html
- AWS S3 security: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security.html
