---
name: auditing-mcp-servers-for-tool-poisoning
description: Audit MCP servers for tool poisoning, tool shadowing, rug pulls, SSRF, and unauthenticated exposure using Invariant Labs' mcp-scan for static/runtime scanning plus manual SSRF/auth checks and description pinning. Use when adding a new MCP server to an agent stack, reviewing an internal MCP server, detecting rug pulls, or investigating an agent's unexpected tool-driven behavior. Do not use for hardening your own agent's tool-invocation boundary with allowlisting, least-privilege identity, and human-in-the-loop approval - use securing-agentic-ai-tool-invocation.
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- mcp
- tool-poisoning
- agent-security
- mcp-scan
- ssrf
- supply-chain
- rug-pull
version: '1.0'
author: mahipal
license: Apache-2.0
nist_ai_rmf:
- MANAGE-2.2
atlas_techniques:
- AML.T0010
---
# Auditing MCP Servers for Tool Poisoning

> **Authorized-use-only notice:** Auditing MCP servers can connect to and probe live tool endpoints. Only scan servers you own or are authorized to assess. Treat scanned tool descriptions as untrusted input — do not load an unaudited MCP server into a privileged agent. Probing third-party MCP endpoints for SSRF or auth weaknesses without permission may be illegal.

## Overview

The Model Context Protocol (MCP) lets AI agents discover and call external tools advertised by MCP servers. Each tool exposes a name and a natural-language **description** that the agent's LLM reads *before* deciding to call it. In early 2025, Invariant Labs disclosed that this description field is an attack surface: a malicious server can embed hidden instructions in a tool's description (a **tool poisoning attack**, OWASP **MCP03:2025**), and a capable model will silently follow them — exfiltrating files, leaking secrets, or redirecting tool calls — while returning a normal-looking response to the user. Because tool descriptions are loaded into the agent's context, tool poisoning is effectively indirect prompt injection delivered through the supply chain (MITRE ATLAS **AML.T0010 ML Supply Chain Compromise**).

Beyond poisoning, MCP servers introduce classic infrastructure risks: **tool shadowing** (a malicious server overrides a trusted tool's behavior), **rug pulls** (a tool's description changes after the user approved it), **toxic flows** (a combination of tools that enables data exfiltration), **SSRF** in tools that fetch URLs server-side, and **unauthenticated exposure** of MCP servers bound to network interfaces. This skill audits MCP servers end-to-end using Invariant Labs' **mcp-scan** for static and runtime analysis, plus manual checks for SSRF and authentication, and tool pinning to catch rug pulls.

## When to Use

- Before adding a new MCP server to an agent stack (Claude Desktop, Cursor, VS Code, Windsurf, custom agents).
- During a security review of an internally developed MCP server.
- When validating that approved tools have not silently changed (rug-pull detection).
- As a CI/CD gate that scans MCP configs and SKILL/tool definitions on every change.
- During incident response when an agent took unexpected actions consistent with a poisoned tool.

## Prerequisites

- Python 3.10+ and `uv` (for `uvx`), or pip.
- The MCP config file(s) you want to scan (e.g. `~/.cursor/mcp.json`, `~/.vscode/mcp.json`, Claude Desktop config).
- Install the tooling:

```bash
# uv provides uvx (recommended runner for mcp-scan)
curl -LsSf https://astral.sh/uv/install.sh | sh    # or: pipx install uv

# mcp-scan (Invariant Labs) — no global install needed with uvx
uvx mcp-scan@latest --help

# For the runtime proxy mode (separate extra)
uvx --with "mcp-scan[proxy]" mcp-scan@latest proxy --help

# Manual probing helpers
pip install requests mcp
```

## Objectives

- Statically scan all installed MCP servers for tool poisoning, shadowing, rug pulls, and toxic flows.
- Inspect raw tool/prompt/resource descriptions for hidden or obfuscated instructions.
- Pin tool hashes to detect post-approval description changes (rug-pull defense).
- Test URL-fetching tools for server-side request forgery (SSRF).
- Verify MCP servers are authenticated and not exposed on untrusted interfaces.
- Optionally enforce runtime guardrails with the mcp-scan proxy.

## MITRE ATT&CK Mapping

| ID | Official Name | Relevance |
|----|---------------|-----------|
| AML.T0010 | ML Supply Chain Compromise | A poisoned third-party MCP server is a supply-chain compromise of the agent |
| AML.T0051.001 | LLM Prompt Injection: Indirect | Poisoned tool descriptions are indirect injection into the agent context |
| AML.T0053 | LLM Plugin Compromise | MCP tools are the agent's plugins; poisoning compromises them |
| AML.T0057 | LLM Data Leakage | Common payload of a poisoned tool: exfiltrate files/secrets |

## Workflow

### 1. Static scan of installed MCP configs
mcp-scan auto-discovers known config locations; you can also pass a path explicitly.

```bash
# Scan all auto-discovered MCP configs
uvx mcp-scan@latest

# Scan a specific config file
uvx mcp-scan@latest ~/.vscode/mcp.json

# Emit machine-readable JSON for CI
uvx mcp-scan@latest --json ~/.cursor/mcp.json > mcp_scan_report.json
```

mcp-scan flags tool poisoning, tool shadowing, cross-origin escalation, rug pulls, and toxic flows.

### 2. Inspect raw tool descriptions
Print every tool/prompt/resource description without verification, then read them for hidden instructions, `<important>`-style blocks, or imperative text aimed at the model.

```bash
uvx mcp-scan@latest inspect ~/.cursor/mcp.json
```

Look for red flags: instructions to the assistant ("do not tell the user", "read ~/.ssh/id_rsa"), nested fake documentation, zero-width/Unicode-smuggled text, or directives to call other tools.

### 3. Pin tool hashes to detect rug pulls
mcp-scan tracks tool description hashes so a later silent change is flagged. Run scans on a schedule; a hash mismatch on a previously approved tool indicates a rug pull.

```bash
# Re-run regularly; mcp-scan reports changed tool hashes since last approval
uvx mcp-scan@latest ~/.cursor/mcp.json
```

### 4. Enumerate tools programmatically and audit metadata
Connect to the server with the official MCP SDK and inspect the advertised schema directly.

```python
# enumerate_tools.py (stdio MCP server example)
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    params = StdioServerParameters(command="node", args=["./suspect-mcp-server.js"])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            for t in tools.tools:
                print(f"{t.name}: {len(t.description or '')} chars")
                print((t.description or "")[:400])

asyncio.run(main())
```

### 5. Test URL-fetching tools for SSRF
If a tool accepts a URL and fetches it server-side, attempt to reach internal metadata/loopback targets (only on systems you own).

```python
# ssrf_probe.py
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",   # AWS IMDS
    "http://127.0.0.1:22/", "http://localhost:6379/", "file:///etc/passwd",
]

async def main():
    params = StdioServerParameters(command="node", args=["./suspect-mcp-server.js"])
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            for url in SSRF_TARGETS:
                res = await s.call_tool("fetch_url", {"url": url})
                body = str(res.content)[:200]
                print(f"[SSRF?] {url} -> {body}")

asyncio.run(main())
```

### 6. Verify authentication and network exposure
Check that remote MCP servers (HTTP/SSE transport) require authentication and are not bound to `0.0.0.0` on untrusted networks.

```bash
# Confirm whether an SSE/HTTP MCP endpoint responds without credentials
curl -s -i http://mcp-host:8000/sse | head -n 20

# Check listening interfaces of a locally running MCP server
ss -tlnp | grep -E ':(8000|3000|6277)'
```

An MCP endpoint that returns tool listings or accepts `tools/call` without auth is unauthenticated exposure — remediate with a token/OAuth and bind to localhost or an authenticated gateway.

### 7. Enforce runtime guardrails (optional)
For continuous protection, route agent MCP traffic through the mcp-scan proxy, which checks tool calls, data-flow constraints, PII, and indirect injection in real time.

```bash
uvx --with "mcp-scan[proxy]" mcp-scan@latest proxy
```

### 8. Report findings
Document each finding with server, tool, evidence (the poisoned description / SSRF response / unauth listing), severity, and ATLAS mapping. Recommend removing or sandboxing poisoned servers, adding auth, pinning approved tools, and enabling the proxy.

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| mcp-scan | Static + runtime MCP security scanner | https://github.com/invariantlabs-ai/mcp-scan |
| MCP Python SDK | Programmatic tool enumeration / calls | https://github.com/modelcontextprotocol/python-sdk |
| OWASP MCP Top 10 | MCP risk reference (MCP03 Tool Poisoning) | https://owasp.org/www-project-mcp-top-10/ |
| Invariant Labs blog | Tool poisoning disclosure | https://invariantlabs.ai/blog/introducing-mcp-scan |
| MITRE ATLAS | AI threat technique taxonomy | https://atlas.mitre.org/ |

## MCP Threat Reference

| Threat | Description | Detection |
|--------|-------------|-----------|
| Tool poisoning | Hidden instructions in tool description | mcp-scan scan / inspect |
| Tool shadowing | Malicious server overrides trusted tool | mcp-scan cross-origin checks |
| Rug pull | Description changes after approval | mcp-scan tool pinning (hash) |
| Toxic flow | Tool combo enabling exfiltration | mcp-scan toxic-flow analysis |
| SSRF | URL-fetch tool reaches internal targets | ssrf_probe against owned server |
| Unauth exposure | MCP endpoint with no auth | curl/ss interface and auth check |

## Validation Criteria

- [ ] All installed MCP configs statically scanned with mcp-scan
- [ ] Raw tool/prompt/resource descriptions inspected for hidden instructions
- [ ] Tool hashes pinned and rug-pull detection enabled
- [ ] Tools enumerated programmatically via the MCP SDK
- [ ] URL-fetching tools tested for SSRF against owned targets
- [ ] Authentication and network exposure of remote servers verified
- [ ] Runtime proxy guardrails evaluated or deployed where appropriate
- [ ] Findings mapped to MITRE ATLAS AML.T0010 and OWASP MCP03:2025
- [ ] Severity assigned and remediation documented for each finding
- [ ] Re-scan scheduled to catch future rug pulls
