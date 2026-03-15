#!/usr/bin/env python3
"""Agent for testing WebSocket API security.

Tests WebSocket endpoints for missing authentication, Cross-Site
WebSocket Hijacking (CSWSH), injection attacks, message flooding,
and authorization bypass vulnerabilities.
"""

import json
import sys
import asyncio
import time
from pathlib import Path
from datetime import datetime

try:
    import websockets
except ImportError:
    websockets = None

try:
    import requests
except ImportError:
    requests = None


INJECTION_PAYLOADS = [
    '{"action":"admin","data":"test"}',
    '{"action":"subscribe","channel":"../admin"}',
    '<script>alert(1)</script>',
    "' OR 1=1 --",
    '{"__proto__":{"isAdmin":true}}',
    '{"action":"eval","code":"process.exit()"}',
    "A" * 100000,
]


class WebSocketSecurityAgent:
    """Tests WebSocket API implementations for vulnerabilities."""

    def __init__(self, ws_url, http_url=None, output_dir="./websocket_test"):
        self.ws_url = ws_url
        self.http_url = http_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    async def _connect(self, headers=None, origin=None, timeout=5):
        if not websockets:
            return None
        extra = {}
        if headers:
            extra["additional_headers"] = headers
        if origin:
            extra["origin"] = origin
        try:
            return await asyncio.wait_for(
                websockets.connect(self.ws_url, **extra), timeout=timeout
            )
        except Exception:
            return None

    async def test_no_auth(self):
        """Test if WebSocket connects without authentication."""
        ws = await self._connect()
        if ws:
            await ws.send('{"action":"ping"}')
            try:
                resp = await asyncio.wait_for(ws.recv(), timeout=3)
                self.findings.append({"severity": "high", "type": "No Auth on WebSocket",
                                      "detail": "WebSocket accepts connection without credentials"})
                await ws.close()
                return {"connected": True, "response": resp[:200]}
            except Exception:
                await ws.close()
                return {"connected": True, "response": None}
        return {"connected": False}

    async def test_cswsh(self, evil_origin="https://evil.com"):
        """Test Cross-Site WebSocket Hijacking via Origin header."""
        ws = await self._connect(origin=evil_origin)
        if ws:
            self.findings.append({"severity": "critical", "type": "CSWSH",
                                  "detail": f"WebSocket accepts connection from origin: {evil_origin}"})
            await ws.close()
            return {"vulnerable": True, "origin": evil_origin}
        return {"vulnerable": False}

    async def test_injection(self, auth_headers=None):
        """Send injection payloads through WebSocket messages."""
        ws = await self._connect(headers=auth_headers)
        if not ws:
            return []
        results = []
        for payload in INJECTION_PAYLOADS:
            try:
                await ws.send(payload)
                resp = await asyncio.wait_for(ws.recv(), timeout=3)
                if "error" not in resp.lower() and len(resp) > 10:
                    results.append({"payload": payload[:80], "response": resp[:200],
                                    "potential_issue": True})
                    self.findings.append({"severity": "medium", "type": "Injection Accepted",
                                          "detail": f"Payload accepted: {payload[:50]}"})
            except Exception:
                continue
        await ws.close()
        return results

    async def test_authorization_bypass(self, auth_headers=None):
        """Test accessing admin/privileged channels without authorization."""
        ws = await self._connect(headers=auth_headers)
        if not ws:
            return []
        channels = ["admin", "internal", "debug", "system", "logs", "metrics"]
        results = []
        for ch in channels:
            try:
                await ws.send(json.dumps({"action": "subscribe", "channel": ch}))
                resp = await asyncio.wait_for(ws.recv(), timeout=3)
                if "error" not in resp.lower() and "denied" not in resp.lower():
                    results.append({"channel": ch, "response": resp[:200]})
                    self.findings.append({"severity": "high", "type": "Channel Auth Bypass",
                                          "detail": f"Subscribed to restricted channel: {ch}"})
            except Exception:
                continue
        await ws.close()
        return results

    async def test_message_flood(self, count=1000, auth_headers=None):
        """Test DoS resilience with message flooding."""
        ws = await self._connect(headers=auth_headers)
        if not ws:
            return {"error": "connection failed"}
        start = time.time()
        sent = 0
        for i in range(count):
            try:
                await ws.send(f'{{"action":"ping","id":{i}}}')
                sent += 1
            except Exception:
                break
        elapsed = time.time() - start
        await ws.close()
        if sent == count:
            self.findings.append({"severity": "medium", "type": "No Rate Limiting",
                                  "detail": f"Accepted {count} messages in {elapsed:.2f}s"})
        return {"sent": sent, "elapsed": round(elapsed, 2), "rate_limited": sent < count}

    def check_upgrade_headers(self):
        """Check HTTP upgrade response headers for security issues."""
        if not requests:
            return {"error": "requests not available"}
        http_url = self.http_url or self.ws_url.replace("ws://", "http://").replace("wss://", "https://")
        try:
            resp = requests.get(http_url, headers={
                "Upgrade": "websocket", "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
            }, timeout=10)
            issues = []
            if "Sec-WebSocket-Accept" in resp.headers and resp.status_code == 101:
                if "strict-transport-security" not in {k.lower() for k in resp.headers}:
                    issues.append("Missing HSTS header")
                if "x-frame-options" not in {k.lower() for k in resp.headers}:
                    issues.append("Missing X-Frame-Options")
            for issue in issues:
                self.findings.append({"severity": "low", "type": "Missing Security Header",
                                      "detail": issue})
            return {"status": resp.status_code, "issues": issues}
        except requests.RequestException:
            return {"error": "connection failed"}

    async def run_all_tests(self, auth_headers=None):
        no_auth = await self.test_no_auth()
        cswsh = await self.test_cswsh()
        injection = await self.test_injection(auth_headers)
        authz = await self.test_authorization_bypass(auth_headers)
        flood = await self.test_message_flood(auth_headers=auth_headers)
        upgrade = self.check_upgrade_headers()
        return {
            "no_auth": no_auth, "cswsh": cswsh, "injection": injection,
            "authz_bypass": authz, "flood": flood, "upgrade_headers": upgrade,
        }

    def generate_report(self, auth_headers=None):
        results = asyncio.get_event_loop().run_until_complete(self.run_all_tests(auth_headers))
        report = {
            "report_date": datetime.utcnow().isoformat(),
            "target": self.ws_url,
            **results,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "websocket_security_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <ws_url> [--token <bearer_token>]")
        sys.exit(1)
    ws_url = sys.argv[1]
    headers = None
    if "--token" in sys.argv:
        token = sys.argv[sys.argv.index("--token") + 1]
        headers = {"Authorization": f"Bearer {token}"}
    agent = WebSocketSecurityAgent(ws_url)
    agent.generate_report(headers)


if __name__ == "__main__":
    main()
