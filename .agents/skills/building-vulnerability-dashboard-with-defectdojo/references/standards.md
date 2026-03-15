# Standards and References - DefectDojo Vulnerability Dashboard

## Primary References

### DefectDojo Project
- **GitHub**: https://github.com/DefectDojo/django-DefectDojo
- **Documentation**: https://defectdojo.github.io/django-DefectDojo/
- **API v2 Docs**: https://defectdojo.github.io/django-DefectDojo/integrations/api-v2-docs/
- **OWASP Project Page**: https://owasp.org/www-project-defectdojo/
- **License**: BSD-3-Clause

### Supported Scanner Integrations
- **Full List**: https://defectdojo.com/integrations
- **200+ parsers** including Nessus, Qualys, Burp Suite, ZAP, Trivy, Semgrep, SonarQube, Snyk, Checkov, and more

### OWASP Application Security Verification Standard (ASVS)
- **URL**: https://owasp.org/www-project-application-security-verification-standard/
- **Relevance**: DefectDojo categorizes findings using OWASP taxonomy

### NIST SP 800-53 Rev 5 - RA-5
- **Title**: Vulnerability Monitoring and Scanning
- **Relevance**: DefectDojo supports centralized vulnerability tracking as required by RA-5

### PCI DSS v4.0 - Requirement 6
- **Relevance**: DefectDojo tracks application security findings for PCI compliance

## Deployment Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4 cores |
| RAM | 4 GB | 8 GB |
| Disk | 20 GB | 50 GB+ |
| PostgreSQL | 12+ | 15+ |
| Docker | 20.10+ | Latest stable |
| Docker Compose | 2.0+ | Latest stable |
