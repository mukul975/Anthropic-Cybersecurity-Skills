# Product Requirements Document: SentinelBlue

## 1. Product Overview

### 1.1 Product Name

SentinelBlue

### 1.2 Product Type

Local-first AI security monitoring, investigation, and automation application.

### 1.3 Product Thesis

Security teams need help turning noisy telemetry into defensible decisions, but many organizations cannot send endpoint logs, identity data, malware evidence, or incident notes to remote AI services. SentinelBlue solves this by running the AI reasoning loop locally, using a curated cybersecurity skill library, deterministic detectors, and controlled automation to assist analysts without surrendering telemetry privacy.

### 1.4 Core Promise

SentinelBlue continuously monitors security signals, explains what matters, maps evidence to known adversary behavior, recommends next actions, and safely automates approved response work while keeping data local by default.

### 1.5 Target Form Factors

- Desktop app: macOS, Windows, and Linux via Tauri.
- Headless service: Linux-first server deployment with web UI and API.
- Hybrid deployment: local desktop UI connects to a continuously running local or LAN server.

## 2. Problem Statement

Small and mid-sized teams often have enough telemetry to detect meaningful incidents but not enough analyst capacity to investigate every alert. Open-source tools such as Wazuh, Zeek, Suricata, osquery, Sigma, and this repository's cybersecurity skills provide strong building blocks, but they are fragmented:

- Alerts live in separate dashboards and log files.
- Playbooks are disconnected from evidence.
- Analysts must manually decide which workflow applies.
- AI tools are often cloud-hosted and unsuitable for sensitive telemetry.
- Autonomous response is risky without explicit approval and audit trails.
- Desktop tools do not always run continuously, while server tools often lack local analyst UX.

SentinelBlue unifies these into one local product.

## 3. Goals

### 3.1 Business Goals

- Deliver a privacy-preserving AI SOC assistant that can run locally or on a private server.
- Make this cybersecurity skills repository operational by turning skills into searchable playbooks, detector recipes, and automation adapters.
- Reduce mean time to triage for common alerts.
- Help small teams build repeatable incident response habits without needing a full SIEM/SOAR program.
- Provide a path from desktop lab use to continuous production monitoring.

### 3.2 User Goals

- See the most important alerts first.
- Understand why an alert matters.
- Know which cybersecurity skill/playbook applies.
- Run safe enrichment and investigation automatically.
- Review recommended containment before execution.
- Produce evidence-backed incident summaries.
- Keep sensitive logs, IOCs, credentials, and samples local.

### 3.3 Technical Goals

- Use Rust for the core runtime, ingestion, policy, and service layer.
- Use Tauri for the local desktop shell.
- Use `llama-server` as the first local inference runtime.
- Support a Gemma 4 31B GGUF model preset and smaller fallback presets.
- Run read-only detectors deterministically.
- Enforce action policy in backend code.
- Support continuous server operation with health checks, metrics, and restart behavior.

## 4. Non-Goals

- Replace Wazuh, Zeek, Suricata, osquery, or an enterprise SIEM.
- Execute offensive exploitation workflows outside an explicit lab mode.
- Let the model directly execute shell commands.
- Guarantee fully autonomous containment without human approval.
- Bundle large model weights in the source repository.
- Support every skill in this repository as an executable tool in v1.
- Train or fine-tune a model in v1.
- Provide managed cloud hosting in v1.

## 5. Personas

### 5.1 Solo Security Operator

Works at a startup or small company. Needs practical monitoring on a limited budget. Wants Wazuh, local logs, and AI summaries without building a full SOC.

Primary needs:

- Simple onboarding.
- Clear alert prioritization.
- Local privacy.
- Suggested next steps.
- Lightweight reports.

### 5.2 SOC Analyst

Handles alert triage and investigation. Needs faster correlation across endpoint, identity, DNS, API, and CTI signals.

Primary needs:

- Evidence timeline.
- Attack technique mapping.
- Runbook guidance.
- Query suggestions.
- Case handoff.

### 5.3 Security Engineer

Owns detection content, integrations, and automation guardrails. Needs configurable detectors and controlled response actions.

Primary needs:

- Skill-to-detector mapping.
- Rule provenance.
- Policy management.
- Logs and audit trail.
- Test datasets.

### 5.4 Incident Commander

Coordinates response during high-severity events. Needs reliable case state, decisions, containment approvals, and executive summaries.

Primary needs:

- Incident timeline.
- Impact assessment.
- Action log.
- Confidence levels.
- Report generation.

### 5.5 Managed Service Provider Analyst

Monitors multiple small customers or environments. Needs tenant separation and continuous service deployment.

Primary needs:

- Tenant-aware data separation.
- Server mode.
- Role-based access.
- Integrations per tenant.
- Audit-ready actions.

### 5.6 Homelab / Research User

Uses the app to learn, simulate, and validate detections with local models.

Primary needs:

- Lab mode.
- Skill exploration.
- Sample data.
- Detector testing.
- Optional red-team skill visibility with warnings.

## 6. Product Principles

- Local first: telemetry and case notes stay on the machine or private server by default.
- Deterministic before generative: detectors produce evidence; the model explains and reasons over it.
- Skills are context, not unchecked code: playbooks guide the model and analysts, scripts become reviewed adapters.
- Human-approved response: containment and destructive actions require explicit approval.
- Audit everything: selected skills, prompts, outputs, detectors, and actions must be traceable.
- Operational density: the UI should feel like a security workbench, not a marketing dashboard.
- Continuous by design: desktop and server modes must support long-running monitoring.

## 7. Scope

### 7.1 MVP Scope

MVP must include:

- Local skill indexer for all `index.json` entries and `SKILL.md` frontmatter.
- Full-text search over skill names, descriptions, tags, subdomains, and ATT&CK mappings.
- Advisory skill view with workflow extraction.
- `llama-server` process manager.
- Local model configuration and health check.
- Local SQLite database for events, alerts, cases, evidence, skills, and actions.
- JSON log import for Wazuh alerts, Sysmon events, Zeek logs, Suricata EVE logs, and API gateway logs.
- Wazuh read-only API connector.
- Four initial detectors:
  - Process injection from Sysmon Event IDs 8 and 10.
  - Suspicious PowerShell execution.
  - Authentication anomalies: password spray, brute force, impossible travel.
  - DNS tunneling/beaconing candidates.
- Case generation with evidence timeline and ATT&CK mapping.
- AI-generated analyst summary using local model.
- Approval workflow for proposed actions.
- Light, dark, and system themes.
- Desktop mode with tray status.
- Server mode with REST API and web UI.

### 7.2 V1 Scope

V1 should add:

- Action policy editor.
- osquery scheduled query pack ingestion.
- STIX/TAXII indicator ingestion.
- IOC enrichment adapters.
- Sigma rule import and compilation path.
- Report templates from skill `assets/template.md`.
- Role-based access for server mode.
- Prometheus-compatible metrics.
- Service installation scripts for Linux `systemd`, macOS LaunchAgent, and Windows service.
- Offline model bundle import.
- Signed Tauri desktop updates.

### 7.3 Later Scope

Later releases may add:

- Multi-tenant MSSP mode.
- OpenCTI and MISP connectors.
- CAPE/Cuckoo malware sandbox integration.
- Timesketch timeline export.
- Automated ATT&CK coverage reporting.
- Tauri mobile companion app for approvals.
- Local multimodal analysis for screenshots, PDFs, or phishing images.
- Fine-tuned security summarization models.

## 8. Functional Requirements

### 8.1 Skill Indexing

Requirements:

- Parse root `index.json`.
- Parse every `skills/*/SKILL.md` frontmatter.
- Store skill name, path, description, domain, subdomain, tags, version, author, license, ATT&CK IDs, NIST CSF IDs, ATLAS IDs, D3FEND IDs, and AI RMF IDs.
- Compute skill file checksum.
- Extract body sections: When to Use, Prerequisites, Workflow/Steps, Verification/Expected Output, Tools & Systems, Common Pitfalls.
- Link references, scripts, and templates if present.
- Index skill metadata in SQLite FTS.
- Support a future vector index, but do not require embeddings for MVP.

Acceptance criteria:

- All 754 skills are indexed.
- Searching "process injection sysmon" returns `hunting-for-process-injection-techniques` and related T1055 skills.
- Searching "Wazuh endpoint detection" returns `implementing-endpoint-detection-with-wazuh`.
- Skill checksums change when source skill files change.

### 8.2 Skill Router

Requirements:

- Select relevant skills for alerts, cases, hunts, and analyst questions.
- Combine keyword match, tags, source type, ATT&CK IDs, event fields, and detector IDs.
- Return top skills with reason codes.
- Load full skill body only for selected skills.
- Keep dangerous/offensive skills disabled unless lab mode is active.

Acceptance criteria:

- Every routed skill has at least one explanation: tag match, ATT&CK match, source match, detector match, or explicit analyst selection.
- Offensive skills are not suggested for production containment unless framed as defensive detection/validation.

### 8.3 Telemetry Ingestion

Requirements:

- Support file import and directory tailing for JSONL logs.
- Support Wazuh API read-only connector.
- Support manual paste/import for small samples.
- Normalize raw events into common schema.
- Preserve raw payloads.
- Deduplicate repeated events.
- Track source connector health.

Initial sources:

- Wazuh alerts.
- Sysmon JSON.
- Zeek JSON/TSV logs.
- Suricata EVE JSON.
- API gateway access JSON.
- Identity/authentication CSV or JSON.

Acceptance criteria:

- Imported events appear in event search within 5 seconds for files under 100 MB.
- Raw payload is accessible from the evidence panel.
- Connector health shows last read time, event count, and error state.

### 8.4 Detection Engine

Requirements:

- Run deterministic detectors over normalized events.
- Store detector version and input query.
- Generate alerts with severity, confidence, evidence IDs, and ATT&CK mapping.
- Support scheduled and on-demand detector runs.
- Support unit tests with sample logs.

Initial detectors:

- `detector.process_injection.sysmon`
- `detector.powershell.suspicious_execution`
- `detector.auth.password_spray`
- `detector.auth.impossible_travel`
- `detector.dns.tunneling_candidate`
- `detector.dns.beaconing_candidate`
- `detector.api.enumeration`
- `detector.ioc.match`

Acceptance criteria:

- Detector outputs are reproducible for the same input.
- Each alert links to evidence and selected skills.
- Detector confidence is numeric and explainable.

### 8.5 Local AI Runtime

Requirements:

- Manage `llama-server` process in desktop mode.
- Connect to an externally managed model server in server mode.
- Support model presets:
  - `gemma-4-31b-it-gguf-q4-workstation`
  - `gemma-4-e4b-it-gguf-laptop`
  - `custom-openai-compatible-local`
- Check `/health` before inference.
- Support streaming responses.
- Apply structured prompt templates.
- Prefer JSON-constrained outputs when supported.
- Log prompt metadata and hash sensitive prompt bodies for audit where full prompt retention is disabled.

Acceptance criteria:

- Model health check reports loading, ready, degraded, or unavailable.
- AI summary generation is disabled if model health is unavailable.
- The app can operate in deterministic-only mode without a model.

### 8.6 AI Analysis

Requirements:

- Generate case summaries from evidence.
- Explain detector findings.
- Map likely ATT&CK techniques.
- Recommend investigation steps.
- Suggest but not execute response actions.
- Cite evidence IDs in every claim.
- State uncertainty and missing telemetry.

Acceptance criteria:

- AI output includes "Evidence Used", "Assessment", "Confidence", "Recommended Next Steps", and "Missing Data".
- Claims without evidence are flagged as model inference.
- Case summary can be regenerated after more evidence is added.

### 8.7 Case Management

Requirements:

- Create cases manually or automatically from alerts.
- Merge alerts into cases by entity, time window, technique, source, or analyst action.
- Store timeline, evidence, notes, skills used, AI summaries, decisions, and actions.
- Support statuses: new, triage, investigating, contained, monitoring, resolved, false positive.
- Support severity: info, low, medium, high, critical.
- Support confidence: unknown, low, medium, high.

Acceptance criteria:

- A case can be created from one alert in two clicks.
- A case timeline shows raw events, detector alerts, model summaries, analyst notes, and actions in order.
- Closing a case requires disposition and notes.

### 8.8 Automation

Requirements:

- Classify actions as:
  - Read-only.
  - Analysis-only.
  - Low-risk write.
  - Containment.
  - Destructive.
  - Lab-only.
- Read-only and analysis-only actions may run automatically.
- Low-risk writes require configurable policy.
- Containment and destructive actions require approval.
- Every action must declare target, tool, input, expected effect, rollback guidance, approval state, and audit record.

Initial actions:

- Enrich IOC.
- Create case.
- Generate report.
- Query Wazuh agent inventory.
- Query Wazuh alert summary.
- Run detector.
- Submit file hash to local lookup.
- Draft block recommendation.

Future approval-gated actions:

- Isolate host.
- Disable user.
- Block domain/IP/hash.
- Quarantine file.
- Open ticket.
- Trigger Wazuh active response.

Acceptance criteria:

- The model cannot bypass action policy.
- Every containment action requires human approval in production mode.
- An action log can reconstruct who approved what and why.

### 8.9 Desktop UX

Requirements:

- Tauri app with dashboard, alert queue, case workspace, hunt workspace, skills library, connectors, model/runtime settings, and policy admin.
- Light, dark, and system theme.
- Meta-blue inspired accent palette.
- Tray icon with health/status menu.
- Optional autostart.
- Local notifications for critical alerts and approval requests.

Acceptance criteria:

- App remains usable at 1280x800 desktop viewport.
- Dashboard has no marketing hero or decorative card layout.
- Dense tables are scannable.
- All destructive buttons are clearly differentiated and approval-gated.

### 8.10 Server Mode

Requirements:

- Run backend without Tauri.
- Serve web UI and API continuously.
- Support system service installation.
- Support container deployment.
- Expose health endpoints.
- Expose metrics endpoint.
- Support authentication and role-based access.
- Support remote desktop clients connecting to server mode.

Acceptance criteria:

- Server restarts after process failure under `systemd`.
- `/health` returns app, database, connectors, workers, and model health.
- Server mode can run with external `llama-server`.
- Web UI is available without desktop shell.

## 9. Data Requirements

### 9.1 Core Entities

- `Skill`
- `TelemetrySource`
- `RawEvent`
- `NormalizedEvent`
- `DetectorRun`
- `Alert`
- `Case`
- `Evidence`
- `Action`
- `ActionApproval`
- `ModelRuntime`
- `ModelRun`
- `Connector`
- `Asset`
- `Identity`
- `IOC`
- `Policy`
- `AuditEvent`

### 9.2 Retention

Defaults:

- Raw imported logs: 30 days.
- Normalized events: 90 days.
- Alerts: 180 days.
- Cases and evidence: retained until deleted by admin.
- Model prompts/outputs: configurable; default keep outputs and prompt metadata, redact secrets.
- Audit events: 1 year minimum in server mode.

### 9.3 Privacy

Requirements:

- No external AI calls by default.
- No telemetry upload by default.
- Local model server bound to `127.0.0.1` in desktop mode.
- Secrets stored in OS keychain or encrypted server secret store.
- Sensitive fields redacted in UI by default: tokens, passwords, private keys, cookies, authorization headers.

## 10. Security Requirements

- Least-privilege connectors.
- Separate read and write credentials where possible.
- Backend-enforced action policy.
- Immutable audit log option.
- TLS required for server mode remote access.
- API keys or OIDC for server mode.
- Signed desktop updates.
- Model file checksum verification.
- Skill checksum verification.
- Prompt injection hardening for telemetry text.
- Offensive skill gating.
- Local-only default.

## 11. UX Requirements

- Operational, dense, calm.
- No decorative hero screens.
- Sidebar navigation with health status.
- Alerts prioritized by severity, confidence, affected asset criticality, and ATT&CK stage.
- Case view optimized for repeated triage.
- Every AI summary shows evidence and uncertainty.
- Every action shows expected effect before approval.
- Theme defaults to system.

## 12. Success Metrics

### 12.1 Product Metrics

- Time to first local alert ingested: under 10 minutes from first launch.
- Time to first AI case summary: under 15 minutes from first launch with compatible model.
- Alert-to-case creation time: under 30 seconds.
- Analyst triage time reduction: target 30% on supported scenarios.
- Evidence citation coverage: 95% of AI claims in case summaries cite evidence.
- False-positive feedback captured for 80% of closed false-positive cases.

### 12.2 Technical Metrics

- Skill indexing time: under 30 seconds on typical laptop.
- Search response: under 250 ms for keyword search.
- Detector run on 100k normalized events: under 30 seconds for MVP detectors.
- Desktop idle CPU: under 5% without active model generation.
- Desktop idle memory excluding model: under 500 MB target.
- Server uptime target: 99% in lab/SMB deployment after service setup.

### 12.3 Safety Metrics

- Zero unapproved containment actions.
- 100% of action executions have audit records.
- 100% of model-generated actions pass policy classification before display or execution.
- All secret-like strings in prompts are redacted or marked according to settings.

## 13. Release Plan

### 13.1 Alpha

Audience: internal builders and homelab users.

Features:

- Skill indexer.
- Log import.
- SQLite store.
- llama.cpp runtime health.
- First detectors.
- Minimal Tauri UI.
- No write automation.

Exit criteria:

- Can triage sample Wazuh/Sysmon/Zeek/Suricata logs.
- Can produce evidence-backed summaries.
- No data leaves machine by default.

### 13.2 Beta

Audience: small security teams.

Features:

- Wazuh API connector.
- Policy engine.
- Case workspace.
- Report export.
- Server mode.
- Autostart/tray.
- Signed builds.

Exit criteria:

- Can run for 7 days continuously.
- Can recover from model runtime crash.
- Can audit all actions.

### 13.3 V1

Audience: small teams, consultants, MSSP pilots.

Features:

- Role-based server mode.
- Metrics.
- Offline model import.
- Sigma import preview.
- osquery support.
- STIX/TAXII ingestion.
- Stable docs and deployment scripts.

Exit criteria:

- Production hardening checklist complete.
- Supported deployments documented.
- Test suite covers ingestion, detectors, policy, and case generation.

## 14. Risks And Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| 31B model too large for user hardware | Poor onboarding | Provide smaller presets, benchmark before enabling, support external model server |
| Model hallucination | Bad incident decisions | Evidence citations, deterministic detectors, uncertainty labels, analyst approval |
| Unsafe automation | Operational disruption | Backend policy engine, approvals, action tiers, rollback notes |
| Prompt injection in logs | Model manipulation | Treat logs as untrusted data, isolate evidence blocks, never grant tool execution from text |
| Packaging llama.cpp cross-platform | Delayed releases | Start with sidecar binaries, pin versions, add per-platform CI |
| Model license/package size | Distribution friction | Download-on-first-run, checksum, license acceptance |
| Continuous server security | Exposure risk | Bind localhost by default, TLS/API auth for remote mode, RBAC |
| Skill quality variance | Inconsistent guidance | Skill scoring, source checksum, curated supported-skill list |

## 15. Open Questions

- Which exact model presets should be officially supported in V1 beyond Gemma 4 31B?
- Should desktop mode include a local web server for UI parity with server mode?
- Should vector search be in SQLite/SQLite extensions, Qdrant, Tantivy plus embeddings, or deferred?
- Which server auth should ship first: local users, OIDC, reverse-proxy auth, or all three?
- Should the product bundle Wazuh all-in-one for labs or only connect to existing Wazuh?
- Should Sigma rules execute in-process or compile to backend-specific queries first?
- What minimum hardware tier should be stated for a "recommended" Gemma 4 31B experience?
