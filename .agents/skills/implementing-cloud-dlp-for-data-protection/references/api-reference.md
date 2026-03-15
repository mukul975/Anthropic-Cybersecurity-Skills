# API Reference: Implementing Cloud DLP for Data Protection

## Libraries

### google-cloud-dlp (Google Cloud DLP)
- **Install**: `pip install google-cloud-dlp`
- **Docs**: https://cloud.google.com/dlp/docs/reference/libraries
- `DlpServiceClient()` -- Create DLP client
- `inspect_content(parent, inspect_config, item)` -- Scan content for sensitive data
- `deidentify_content(parent, deidentify_config, item)` -- Mask/redact sensitive data
- `create_inspect_template()` -- Reusable inspection configuration
- `create_dlp_job()` -- Scan Cloud Storage, BigQuery, Datastore

### boto3 -- Amazon Macie
- **Install**: `pip install boto3`
- **Docs**: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/macie2.html
- `enable_macie()` -- Enable Macie service
- `create_classification_job()` -- Scan S3 buckets for sensitive data
- `list_findings()` / `get_findings()` -- Retrieve discovery results
- `create_custom_data_identifier()` -- Define custom PII patterns

## GCP DLP Info Types

| Category | Info Types |
|----------|-----------|
| PII | PERSON_NAME, EMAIL_ADDRESS, PHONE_NUMBER, DATE_OF_BIRTH |
| Financial | CREDIT_CARD_NUMBER, IBAN_CODE, SWIFT_CODE |
| US-specific | US_SOCIAL_SECURITY_NUMBER, US_DRIVERS_LICENSE_NUMBER |
| Health | US_HEALTHCARE_NPI, MEDICAL_RECORD_NUMBER |

## De-identification Methods
- `CharacterMaskConfig` -- Replace characters with mask symbol
- `CryptoReplaceFfxFpeConfig` -- Format-preserving encryption
- `RedactConfig` -- Remove sensitive content entirely
- `ReplaceWithInfoTypeConfig` -- Replace with info type name

## Macie Finding Types
- `SensitiveData:S3Object/Personal` -- PII found
- `SensitiveData:S3Object/Financial` -- Financial data found
- `SensitiveData:S3Object/Credentials` -- Credentials detected
- `Policy:IAMUser/S3BucketPublic` -- Public bucket with sensitive data

## External References
- GCP DLP API: https://cloud.google.com/dlp/docs
- GCP Info Types: https://cloud.google.com/sensitive-data-protection/docs/infotypes-reference
- Macie User Guide: https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html
- Azure Purview DLP: https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp
