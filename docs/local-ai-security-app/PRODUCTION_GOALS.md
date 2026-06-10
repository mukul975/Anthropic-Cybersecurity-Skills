# SentinelBlue Production Goals

This document breaks the SentinelBlue roadmap into sequential goals. Each goal has a Definition of Done and Acceptance section so progress can be tracked objectively from blueprint to production-stable release.

## Milestone Map

- Goals 1-8: MVP Core
- Goals 9-12: Analyst-usable Alpha
- Goals 13-16: Team/server Beta
- Goals 17-21: Production-stable V1

## Goal 1: Create Product Workspace

Build the actual SentinelBlue product workspace under a new product repo or a top-level `product/sentinelblue/` directory.

### Definition of Done

- Rust workspace exists.
- Web application exists.
- Tauri desktop shell exists.
- Server binary target exists.
- Basic local development commands are documented.

### Acceptance

- `cargo test` runs successfully.
- Frontend build runs successfully.
- Repository contains clear workspace structure for backend crates, web UI, packaging, sample data, and docs.

## Goal 2: Database Foundation

Create the local persistence layer for events, skills, cases, actions, model runs, policies, and audit records.

### Definition of Done

- SQLite schema is created.
- Versioned migrations exist.
- Core tables exist for `skills`, `telemetry_sources`, `raw_events`, `normalized_events`, `alerts`, `cases`, `evidence`, `detector_runs`, `actions`, `audit_events`, `model_runs`, and `policies`.
- Database initialization is idempotent.

### Acceptance

- App can create and reopen a local database.
- Migration tests pass from empty database to latest schema.
- Basic insert, query, and delete tests pass for core entities.

## Goal 3: Skill Indexer

Index this cybersecurity skills repository into SentinelBlue.

### Definition of Done

- App reads root `index.json`.
- App parses every `skills/*/SKILL.md` frontmatter.
- App stores skill metadata, tags, subdomain, path, checksum, and framework mappings.
- Full-text search is implemented.

### Acceptance

- All 754 skills from the current index are loaded.
- Searching `network traffic`, `Wazuh`, `PowerShell`, and `DNS tunneling` returns relevant skills.
- Skill checksum changes are detected and reindexed.

## Goal 4: Basic API Layer

Expose the initial local REST API used by the desktop and web UI.

### Definition of Done

- Backend exposes `/api/health`, `/api/skills`, `/api/events`, `/api/alerts`, and `/api/cases`.
- API responses use stable JSON shapes.
- API error responses are structured.

### Acceptance

- UI can call the backend.
- `/api/health` reports database and skill index status.
- API tests cover successful and error responses for each initial endpoint.

## Goal 5: File Log Import

Support manual import of local telemetry files.

### Definition of Done

- Import supports JSON, JSONL, CSV, Zeek logs, Suricata EVE JSON, Sysmon JSON, Wazuh alert JSON, and API gateway logs.
- Raw payloads are preserved.
- Import jobs report progress and errors.

### Acceptance

- User can import a file from the UI.
- Imported raw events are searchable.
- A 100 MB test import completes within the target time budget or reports a clear performance exception.

## Goal 6: Event Normalization

Convert raw telemetry into one internal schema.

### Definition of Done

- Normalized schema includes time, source product, host, user, source IP, destination IP, process, command line, URL, DNS query, severity, and raw reference.
- Unmapped fields are preserved.
- Normalizers exist for each MVP source type.

### Acceptance

- Different log sources can be queried using common fields.
- Normalization tests cover Wazuh, Sysmon, Zeek, Suricata, API gateway, and identity/authentication samples.
- Raw evidence remains reachable from normalized events.

## Goal 7: Detection Engine

Build deterministic detectors before using AI for analysis.

### Definition of Done

- Detector trait or interface exists.
- Detector runs are versioned and stored.
- Initial detectors exist for suspicious PowerShell, Sysmon process injection, password spray, impossible travel, DNS tunneling candidate, DNS beaconing candidate, API enumeration, and IOC match.

### Acceptance

- Detector output is reproducible for the same input.
- Each alert links to evidence IDs.
- Each alert includes severity, confidence, explanation, and ATT&CK mapping when applicable.

## Goal 8: Alerts And Cases

Build the core investigation workflow.

### Definition of Done

- Detector findings create alerts.
- Alerts can be promoted to cases.
- Cases support status, severity, confidence, notes, evidence timeline, and closure reason.
- Case timelines include raw events, detector alerts, model summaries, analyst notes, and actions.

### Acceptance

- Analyst can create a case from one alert.
- Case timeline displays evidence in chronological order.
- Closing a case requires disposition and notes.

## Goal 9: Local Model Integration

Add `llama-server` or another OpenAI-compatible local model endpoint.

### Definition of Done

- Model runtime configuration exists.
- Health checks report loading, ready, degraded, or unavailable.
- Deterministic-only mode works without a model.
- Case summary prompt templates exist.
- Prompt input redacts secret-like values.

### Acceptance

- App can generate a case summary from local evidence.
- Every model claim cites evidence IDs or is explicitly marked as inference.
- AI summary generation is disabled when model health is unavailable.

## Goal 10: Desktop UI

Build the Tauri desktop analyst experience.

### Definition of Done

- Screens exist for dashboard, alert queue, case workspace, event search, skill library, connectors, model settings, policy settings, and audit log.
- UI supports light, dark, and system themes.
- Desktop shell exposes only narrow backend commands.

### Acceptance

- Analyst can import logs, run detectors, open a case, and generate a summary from the UI.
- UI remains usable at 1280x800.
- Destructive or containment actions are visually distinct and approval-gated.

## Goal 11: Wazuh Connector

Add read-only Wazuh API support.

### Definition of Done

- Connector authenticates to Wazuh with least-privilege credentials.
- Connector reads agents, alerts, and rule summaries.
- Connector health shows last poll time, event count, and error state.

### Acceptance

- Wazuh alerts become normalized events.
- Wazuh data can create SentinelBlue alerts and cases.
- Wazuh connector tests pass against a mock API.

## Goal 12: Policy And Approval Engine

Prevent unsafe automation and enforce human approval.

### Definition of Done

- Action tiers exist: read-only, analysis-only, low-risk write, containment, destructive, and lab-only.
- Backend policy enforcement runs before action display, queueing, and execution.
- Every action writes an audit record.

### Acceptance

- Model cannot execute actions directly.
- Containment actions require approval in production mode.
- Destructive actions require elevated approval.
- Policy bypass tests pass.

## Goal 13: Server Mode

Build the headless deployment path.

### Definition of Done

- `sentinel-server` runs without Tauri.
- Server serves web UI and API.
- Server supports config file, systemd, Docker Compose, and external `llama-server`.

### Acceptance

- Server starts, stops, and restarts under `systemd`.
- Docker Compose deployment starts successfully.
- `/api/health` works in server mode.

## Goal 14: Authentication And RBAC

Secure production server mode.

### Definition of Done

- API requires authentication in server mode.
- Roles exist for viewer, analyst, responder, admin, and auditor.
- Admin can manage users or configure OIDC.
- Authorization is enforced in backend code.

### Acceptance

- Unauthorized API calls fail.
- Users cannot perform actions outside their role.
- RBAC tests cover sensitive routes and actions.

## Goal 15: Observability

Make SentinelBlue operable in long-running deployments.

### Definition of Done

- `/api/health` reports app, database, skill index, connectors, workers, model runtime, disk space, last event ingestion, and last detector run.
- Prometheus-compatible metrics exist.
- Structured JSON logs exist.
- Audit logs are queryable.
- Backup and restore path is documented.

### Acceptance

- Operator can diagnose degraded database, connector, worker, and model states.
- Metrics show event ingestion, alerts, cases, detector duration, model latency, connector errors, and pending actions.
- Backup and restore procedure is tested.

## Goal 16: Network Security Expansion

Strengthen networking coverage beyond MVP security-log triage.

### Definition of Done

- Additional support exists for NetFlow/IPFIX, firewall logs, proxy logs, VPN logs, DHCP/DNS correlation, Suricata alert workflows, Zeek connection baselines, network asset inventory, and lateral movement detection candidates.
- Network detections are mapped to evidence and skills.

### Acceptance

- SentinelBlue can investigate network security incidents using more than endpoint logs.
- Network alerts include source, destination, protocol, time window, evidence, severity, and confidence.
- Sample data covers DNS, web proxy, firewall, VPN, and flow scenarios.

## Goal 17: Security Hardening

Harden the app for production use.

### Definition of Done

- TLS is required for remote server access.
- Secrets use OS keychain or encrypted server secret store.
- Skill and model checksums are verified.
- Prompt injection defenses are implemented.
- Offensive and lab-only skills are gated from production mode.

### Acceptance

- Prompt injection tests pass.
- Secret redaction tests pass.
- Unauthorized API action tests pass.
- Policy bypass tests pass.
- Malicious skill content tests pass.
- Sidecar argument injection tests pass.

## Goal 18: Packaging

Create installable artifacts.

### Definition of Done

- macOS, Windows, and Linux desktop builds exist.
- Docker image exists.
- Linux server package or tarball exists.
- systemd unit exists.
- Example config and hardening guide exist.
- Signing and update strategy is documented.

### Acceptance

- Fresh install works on each supported platform.
- Docker deployment starts with documented commands.
- Server package installs and starts under documented service manager.

## Goal 19: Test Suite

Stabilize the product with automated tests.

### Definition of Done

- Tests cover skill parser, normalizers, detectors, API, Wazuh mock, model mock, policy engine, UI smoke flows, and end-to-end import-to-case flow.
- CI runs tests on every commit.
- Sample telemetry validates all MVP detectors.

### Acceptance

- CI passes on a clean checkout.
- Failed tests block release.
- Test fixtures include benign and suspicious examples for each detector.

## Goal 20: Beta Soak

Run SentinelBlue continuously before calling it production-ready.

### Definition of Done

- App runs for 7 days continuously in beta deployment.
- Connector errors are recoverable.
- Model runtime crashes are recoverable.
- Large log imports do not corrupt data.
- Audit trail records all case and action activity.

### Acceptance

- No data loss during the soak period.
- No unapproved action executes.
- Service recovers from restart and model crash.
- Known issues are triaged before production release.

## Goal 21: Production Release

Ship the first production-stable V1 release.

### Definition of Done

- Production hardening checklist is complete.
- Deployment docs are complete.
- Backup and restore are tested.
- Security tests pass.
- Performance targets pass.
- Known limitations are documented.
- Versioned release artifacts are created.

### Acceptance

- A new operator can install, configure, ingest logs, run detections, create cases, generate summaries, and review audit logs from documentation alone.
- Release artifacts are signed or checksum-published.
- Production release notes list features, supported deployments, limitations, and upgrade path.
