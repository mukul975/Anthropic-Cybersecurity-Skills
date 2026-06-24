# Message Boundary Checklist

Use this checklist to validate every inter-agent handoff in a multi-agent system.

- [ ] Does the message include a producer identity and trust tier?
- [ ] Is the message explicitly typed as `instruction`, `data`, `tool_result`, `memory`, or `evidence`?
- [ ] Is the content schema-validated before it enters the downstream context?
- [ ] Are upstream agent outputs treated as untrusted by default?
- [ ] Is raw text transformed into structured data when possible?
- [ ] Are tool results quoted, typed, or sanitized before reuse?
- [ ] Are low-trust agents prevented from writing shared memory without verification?
- [ ] Does the handoff include provenance metadata (source, timestamp, trust level)?
- [ ] Does the downstream agent apply stricter checks for external/agent-generated content than for system prompts?
- [ ] Is delegation or task escalation explicitly authorized?
