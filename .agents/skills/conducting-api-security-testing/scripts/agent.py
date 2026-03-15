#!/usr/bin/env python3
# For authorized penetration testing and lab environments only
"""API Security Testing Agent - Tests REST/GraphQL APIs for OWASP API Top 10 vulnerabilities."""

import json
import logging
import argparse
from urllib.parse import urljoin

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def test_bola(base_url, endpoint_template, id_field, valid_id, other_id, auth_token):
    """Test for Broken Object Level Authorization (BOLA/IDOR)."""
    headers = {"Authorization": f"Bearer {auth_token}"}
    own_resp = requests.get(
        urljoin(base_url, endpoint_template.replace(f"{{{id_field}}}", str(valid_id))),
        headers=headers, timeout=10,
    )
    other_resp = requests.get(
        urljoin(base_url, endpoint_template.replace(f"{{{id_field}}}", str(other_id))),
        headers=headers, timeout=10,
    )
    vulnerable = other_resp.status_code == 200 and len(other_resp.content) > 50
    result = {
        "test": "BOLA (API1:2023)",
        "endpoint": endpoint_template,
        "own_status": own_resp.status_code,
        "other_status": other_resp.status_code,
        "vulnerable": vulnerable,
    }
    if vulnerable:
        logger.warning("BOLA vulnerability found: %s", endpoint_template)
    return result


def test_bfla(base_url, admin_endpoints, low_priv_token):
    """Test for Broken Function Level Authorization (BFLA)."""
    headers = {"Authorization": f"Bearer {low_priv_token}"}
    results = []
    for endpoint in admin_endpoints:
        for method in ["GET", "POST", "DELETE"]:
            try:
                resp = requests.request(
                    method, urljoin(base_url, endpoint),
                    headers=headers, timeout=10,
                )
                vulnerable = resp.status_code in (200, 201, 204)
                results.append({
                    "test": "BFLA (API5:2023)",
                    "endpoint": endpoint,
                    "method": method,
                    "status": resp.status_code,
                    "vulnerable": vulnerable,
                })
                if vulnerable:
                    logger.warning("BFLA: %s %s accessible with low-priv token", method, endpoint)
            except requests.RequestException:
                continue
    return results


def test_mass_assignment(base_url, endpoint, auth_token, extra_fields):
    """Test for mass assignment vulnerability."""
    headers = {"Authorization": f"Bearer {auth_token}", "Content-Type": "application/json"}
    resp = requests.put(
        urljoin(base_url, endpoint),
        headers=headers, json=extra_fields, timeout=10,
    )
    verify = requests.get(urljoin(base_url, endpoint), headers=headers, timeout=10)
    verify_data = verify.json() if verify.status_code == 200 else {}

    vulnerable = False
    for key, value in extra_fields.items():
        if key in verify_data and verify_data[key] == value:
            vulnerable = True
            break

    return {
        "test": "Mass Assignment (API6:2023)",
        "endpoint": endpoint,
        "injected_fields": list(extra_fields.keys()),
        "vulnerable": vulnerable,
        "update_status": resp.status_code,
    }


def test_rate_limiting(base_url, endpoint, num_requests=100):
    """Test rate limiting on sensitive endpoints."""
    statuses = []
    for i in range(num_requests):
        try:
            resp = requests.post(
                urljoin(base_url, endpoint),
                json={"username": f"test{i}", "password": "wrong"},
                timeout=5,
            )
            statuses.append(resp.status_code)
            if resp.status_code == 429:
                logger.info("Rate limiting triggered after %d requests", i + 1)
                return {
                    "test": "Rate Limiting (API4:2023)",
                    "endpoint": endpoint,
                    "requests_sent": i + 1,
                    "rate_limited": True,
                    "vulnerable": False,
                }
        except requests.RequestException:
            break

    return {
        "test": "Rate Limiting (API4:2023)",
        "endpoint": endpoint,
        "requests_sent": len(statuses),
        "rate_limited": False,
        "vulnerable": True,
    }


def test_jwt_none_algorithm(base_url, endpoint, jwt_token):
    """Test for JWT 'none' algorithm bypass."""
    import base64
    parts = jwt_token.split(".")
    if len(parts) != 3:
        return {"test": "JWT None Algorithm", "vulnerable": False, "error": "Invalid JWT"}

    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    header["alg"] = "none"
    new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    forged_token = f"{new_header}.{parts[1]}."

    resp = requests.get(
        urljoin(base_url, endpoint),
        headers={"Authorization": f"Bearer {forged_token}"},
        timeout=10,
    )
    vulnerable = resp.status_code == 200
    return {
        "test": "JWT None Algorithm",
        "endpoint": endpoint,
        "forged_status": resp.status_code,
        "vulnerable": vulnerable,
    }


def test_graphql_introspection(base_url, graphql_endpoint="/graphql"):
    """Test if GraphQL introspection is enabled."""
    query = {"query": "{__schema{types{name,fields{name,args{name,type{name}}}}}}"}
    resp = requests.post(
        urljoin(base_url, graphql_endpoint),
        json=query, timeout=10,
    )
    has_schema = "types" in resp.text if resp.status_code == 200 else False
    return {
        "test": "GraphQL Introspection Disclosure",
        "endpoint": graphql_endpoint,
        "status": resp.status_code,
        "introspection_enabled": has_schema,
        "vulnerable": has_schema,
    }


def test_excessive_data_exposure(base_url, endpoint, auth_token, expected_fields):
    """Test for excessive data exposure in API responses."""
    headers = {"Authorization": f"Bearer {auth_token}"}
    resp = requests.get(urljoin(base_url, endpoint), headers=headers, timeout=10)
    if resp.status_code != 200:
        return {"test": "Excessive Data Exposure", "endpoint": endpoint, "vulnerable": False}
    data = resp.json()
    extra_fields = [k for k in data.keys() if k not in expected_fields] if isinstance(data, dict) else []
    return {
        "test": "Excessive Data Exposure (API3:2023)",
        "endpoint": endpoint,
        "expected_fields": expected_fields,
        "extra_fields": extra_fields,
        "vulnerable": len(extra_fields) > 0,
    }


def generate_report(findings):
    """Generate API security testing report."""
    critical = [f for f in findings if f.get("vulnerable")]
    report = {
        "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        "total_tests": len(findings),
        "vulnerabilities_found": len(critical),
        "findings": findings,
    }
    logger.info("Report: %d tests, %d vulnerabilities", len(findings), len(critical))
    return report


def main():
    parser = argparse.ArgumentParser(description="API Security Testing Agent")
    parser.add_argument("--base-url", required=True, help="API base URL")
    parser.add_argument("--token", help="Auth bearer token")
    parser.add_argument("--low-priv-token", help="Low-privilege bearer token for BFLA testing")
    parser.add_argument("--login-endpoint", default="/api/auth/login", help="Login endpoint for rate limit test")
    parser.add_argument("--graphql", action="store_true", help="Test GraphQL introspection")
    parser.add_argument("--output", default="api_security_report.json")
    args = parser.parse_args()

    findings = []

    findings.append(test_rate_limiting(args.base_url, args.login_endpoint, 50))

    if args.graphql:
        findings.append(test_graphql_introspection(args.base_url))

    if args.low_priv_token:
        admin_eps = ["/api/admin/users", "/api/admin/settings", "/api/admin/dashboard"]
        findings.extend(test_bfla(args.base_url, admin_eps, args.low_priv_token))

    if args.token:
        findings.append(test_jwt_none_algorithm(args.base_url, "/api/profile", args.token))

    report = generate_report(findings)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
