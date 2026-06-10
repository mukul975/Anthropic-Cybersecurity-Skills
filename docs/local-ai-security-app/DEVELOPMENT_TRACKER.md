# SentinelBlue Development Tracker

Last updated: 2026-06-10

This tracker records current implementation status against [PRODUCTION_GOALS.md](PRODUCTION_GOALS.md). The production goals document is the source of truth for goal scope; this tracker is the working execution board.

## Current Status

SentinelBlue now has an initialized product workspace plus durable backend foundations. The workspace exists under `product/sentinelblue/` with a Rust workspace, server binary crate, web app, Tauri desktop shell, packaging directories, sample data, model notes, local development docs, SQLite persistence, durable skill indexing, FTS-backed skill search, DB-backed HTTP read endpoints, JSON/JSONL raw event import, MVP event normalization, deterministic detector engine, detector-created alerts/evidence, and read-only web API consumption.

## Goal Status Board

| Goal | Title | Status | Notes |
|---:|---|---|---|
| 1 | Create Product Workspace | Complete | Product workspace created under `product/sentinelblue/`. |
| 2 | Database Foundation | Complete | `sentinel-db` crate, versioned migration, core tables, idempotent init, DB health, and tests are complete. |
| 3 | Skill Indexer | Complete | Parser, DB persistence, FTS search, checksum reindexing, and repository indexing tests are complete. |
| 4 | Basic API Layer | Complete | HTTP stack, `GET /api/health`, DB-backed read endpoints, API contracts, errors, and route tests are complete. |
| 5 | File Log Import | Complete | `sentinel-ingest` imports JSON/JSONL into raw events, hashes payloads, skips duplicates, reports errors, and is wired into `sentinel-server`. |
| 6 | Event Normalization | Complete | Wazuh, Sysmon, Zeek DNS/connection, Suricata EVE, API gateway, and identity/authentication JSON records normalize into common event fields. |
| 7 | Detection Engine | Complete | Detector trait, versioned detector runs, initial deterministic detectors, alert creation, ATT&CK mappings, and evidence links are complete. |
| 8 | Alerts And Cases | Next | Detector findings create alerts; case promotion, status workflow, notes, evidence timeline, and closure remain. |
| 9 | Local Model Integration | Later | More useful after evidence/case shape exists. |
| 10 | Desktop UI | Partial | Tauri shell exists and web UI consumes read-only health, skills, events, alerts, and cases APIs. Import/case workflows remain. |
| 11 | Wazuh Connector | Later | Depends on DB, ingestion, normalization, and connector health model. |
| 12 | Policy And Approval Engine | Later | Depends on actions, audit, users/roles direction, and backend execution boundaries. |
| 13 | Server Mode | Partial scaffold complete | Server binary, simple HTTP serving, health, and read endpoints exist; config, auth, metrics, static web serving, and deployment still remain. |
| 14 | Authentication And RBAC | Later | Should follow basic server API and persistence. |
| 15 | Observability | Later | Health scaffold exists; full metrics/logging/audit health depends on core services. |
| 16 | Network Security Expansion | Later | Should follow MVP ingestion, normalization, and detector engine. |
| 17 | Security Hardening | Later | Must be continuous, but final acceptance depends on implemented surfaces. |
| 18 | Packaging | Partial scaffold complete | Packaging directories exist; installable artifacts are not implemented. |
| 19 | Test Suite | In progress | Rust unit tests now cover core, API contracts, DB migrations, DB inserts, FTS search, repository skill indexing, server routing, DB-backed read endpoints, JSON/JSONL import, dedupe, MVP event normalization, detector runs, detector findings, alerts, and evidence links. |
| 20 | Beta Soak | Not started | Requires deployable beta. |
| 21 | Production Release | Not started | Requires all prior production gates. |

## Completed Goal Evidence

### Goal 1: Create Product Workspace

Artifacts:

- Rust workspace: `product/sentinelblue/Cargo.toml`
- Core crates: `product/sentinelblue/crates/sentinel-core`, `product/sentinelblue/crates/sentinel-api`, `product/sentinelblue/crates/sentinel-server`
- Server binary: `product/sentinelblue/crates/sentinel-server/src/main.rs`
- Web application: `product/sentinelblue/web`
- Tauri desktop shell: `product/sentinelblue/apps/desktop`
- Packaging directories: `product/sentinelblue/packaging`
- Sample data: `product/sentinelblue/sample-data`
- Workspace docs: `product/sentinelblue/docs`

Verified commands:

```bash
cd product/sentinelblue
cargo test
cargo run -p sentinel-server -- --print-health

cd product/sentinelblue/web
npm install
npm run build
```

### Goal 2: Database Foundation

Artifacts:

- Database crate: `product/sentinelblue/crates/sentinel-db`
- Versioned migration: `product/sentinelblue/crates/sentinel-db/migrations/001_initial_schema.sql`
- Core tables: `skills`, `telemetry_sources`, `raw_events`, `normalized_events`, `alerts`, `cases`, `evidence`, `detector_runs`, `actions`, `audit_events`, `model_runs`, and `policies`
- Server DB health wiring: `product/sentinelblue/crates/sentinel-server/src/lib.rs`
- Persistence choice: `rusqlite` plus explicit embedded migrations

Verified commands:

```bash
cd product/sentinelblue
cargo test
cargo run -p sentinel-server -- --print-health --database /tmp/sentinelblue.db
```

Verification result:

- Migrations create all core tables.
- Database initialization is idempotent.
- App can create and reopen a local SQLite database.
- Basic insert/query tests pass for all core tables.
- Server health reports `database` as healthy with `schema_version=4`, `applied_migrations=4`, and `core_tables=12`.

### Goal 3: Skill Indexer

Artifacts:

- Parser/indexer crate: `product/sentinelblue/crates/sentinel-skill-indexer`
- DB skill repository APIs: `product/sentinelblue/crates/sentinel-db/src/lib.rs`
- FTS migration: `product/sentinelblue/crates/sentinel-db/migrations/002_skill_fts.sql`

Completed work:

- Parses root `index.json` shape.
- Parses `skills/*/SKILL.md` YAML frontmatter.
- Extracts path, name, description, domain, subdomain, tags, license, version, author, checksums, and framework mappings.
- Persists parsed skills into the `skills` table.
- Maintains FTS-backed skill search through `skills_fts`.
- Detects unchanged skills by checksum.
- Reindexes changed skills without duplicate rows.
- Indexes the current repository skill set in an end-to-end test.

Verified command:

```bash
cd product/sentinelblue
cargo test
```

Verification result:

- Fixture parser tests pass.
- Durable indexing idempotency and checksum reindex tests pass.
- Repository skill set indexing test passes.
- Search tests pass for `network traffic`, `Wazuh`, `PowerShell`, and `DNS tunneling`.

### Goal 4: Basic API Layer

Artifacts:

- API contracts: `product/sentinelblue/crates/sentinel-api`
- HTTP route implementation: `product/sentinelblue/crates/sentinel-server`

Completed work:

- Defines response contracts for skills, events, alerts, and cases.
- Defines structured API error responses.
- Implements `GET /api/health`.
- Implements DB-backed `GET /api/skills`.
- Implements DB-backed `GET /api/events`.
- Implements DB-backed `GET /api/alerts`.
- Implements DB-backed `GET /api/cases`.
- Adds route-level tests for health, not found, method-not-allowed, skill search, event list, alert list, and case list behavior.

Verified command:

```bash
cd product/sentinelblue
cargo test
```

Verification result:

- `GET /api/health` returns JSON 200.
- Unknown GET routes return structured 404.
- Unsupported methods return structured 405.
- DB-backed skill, event, alert, and case routes return list responses from a temporary initialized database.

### Goal 5: File Log Import

Artifacts:

- Ingest crate: `product/sentinelblue/crates/sentinel-ingest`
- Raw event hash migration: `product/sentinelblue/crates/sentinel-db/migrations/003_raw_event_hash_index.sql`
- Server import command: `product/sentinelblue/crates/sentinel-server/src/main.rs`
- Web API client: `product/sentinelblue/web/src/api.ts`

Completed work:

- Adds `sentinel-ingest` crate depending on `sentinel-db`.
- Imports JSON files into `raw_events`.
- Imports JSONL files into `raw_events`.
- Creates or reuses `telemetry_sources`.
- Stores raw payloads and payload hashes.
- Skips repeated imports by raw payload hash.
- Returns import reports with scanned, imported, skipped, failed, normalized, and errors.
- Wires import execution into `sentinel-server --import-file`.
- Adds tests with Wazuh JSON and generic JSONL fixtures.

Verified commands:

```bash
cd product/sentinelblue
cargo test
cargo run -p sentinel-server -- --import-file sample-data/wazuh-alert.sample.json --database /tmp/sentinelblue.db --source-name sample-wazuh --source-product wazuh
```

Verification result:

- JSON Wazuh sample imports one raw event.
- JSONL fixture imports valid lines, reports invalid lines, and skips duplicates on repeat import.
- Raw payload hashes are stored and used for duplicate detection.
- Import report includes imported, skipped, failed, normalized, and error details.

### Goal 6: Event Normalization First Mapper

Artifacts:

- Normalization crate: `product/sentinelblue/crates/sentinel-ingest`
- Normalized event persistence: `product/sentinelblue/crates/sentinel-db/src/lib.rs`
- Normalized event schema: `product/sentinelblue/crates/sentinel-db/migrations/001_initial_schema.sql`

Completed work:

- Defines a source-neutral normalized event draft.
- Implements Wazuh alert JSON normalization.
- Implements Sysmon JSON normalization.
- Implements Zeek DNS and connection normalization.
- Implements Suricata EVE normalization.
- Implements API gateway access log normalization.
- Implements identity/authentication JSON normalization.
- Stores normalized rows in `normalized_events` during import.
- Tests Wazuh fields for event time, host, asset ID, user, source IP, command line, rule ID, rule name, and severity.
- Tests Sysmon fields for event time, host, asset ID, user, process name/path, parent process, command line, rule ID, and SHA-256 hash.
- Tests Zeek DNS and connection fields for source/destination IPs, ports, protocol, DNS query, service, and connection state.
- Tests Suricata EVE alert fields for event time, source/destination IPs, ports, protocol, signature ID/name, severity, and action.
- Tests API gateway fields for host, request ID, user, source IP, method, URL, status code, severity, and action.
- Tests identity/authentication fields for event time, user, user ID, source IP, device, event type, message, action, and severity.

Verified commands:

```bash
cd product/sentinelblue
cargo test
```

Verification result:

- Wazuh, Sysmon, Zeek, Suricata, API gateway, and identity/authentication fixtures normalize into common fields.
- Importing each MVP source writes a raw event and one normalized event.
- Normalized rows retain `raw_event_id`, keeping raw evidence reachable from normalized events.

### Goal 7: Detection Engine

Artifacts:

- Detector crate: `product/sentinelblue/crates/sentinel-detect`
- Detector run persistence APIs: `product/sentinelblue/crates/sentinel-db/src/lib.rs`
- Alert description migration: `product/sentinelblue/crates/sentinel-db/migrations/004_alert_description.sql`
- Server detector command: `product/sentinelblue/crates/sentinel-server/src/main.rs`

Completed work:

- Defines a source-neutral `Detector` trait.
- Defines detector findings with title, severity, confidence, explanation, ATT&CK mappings, and evidence references.
- Stores versioned detector runs in `detector_runs`.
- Stores detector-created alerts in `alerts`.
- Links alert evidence through `evidence` rows and alert `evidence_json`.
- Exposes alert explanation, ATT&CK JSON, and evidence JSON through the API contract.
- Adds `sentinel-server --run-detectors`.
- Implements initial deterministic detectors for suspicious PowerShell, Sysmon process injection, password spray, impossible travel, DNS tunneling candidate, DNS beaconing candidate, API enumeration, and IOC match.

Verified commands:

```bash
cd product/sentinelblue
cargo test
cargo run -p sentinel-server -- --import-file sample-data/wazuh-alert.sample.json --database /tmp/sentinelblue.db --source-name sample-wazuh --source-product wazuh
cargo run -p sentinel-server -- --run-detectors --database /tmp/sentinelblue.db
```

Verification result:

- The default detector runner executes all eight initial detectors.
- Detector runs are persisted with detector ID, version, input query, status, and finding count.
- Suspicious PowerShell detection creates a high-severity alert from the Wazuh sample.
- Detector alerts include severity, confidence, explanation, ATT&CK mapping JSON, and evidence JSON.
- Alert evidence links back to raw and normalized event IDs.

## Partial Parallel Goal Evidence

### Goal 10: Read-Only UI/API Consumption

Completed narrow work:

- Adds `web/src/api.ts`.
- Fetches `/api/health`.
- Fetches `/api/skills?q=network`.
- Fetches `/api/events`, `/api/alerts`, and `/api/cases`.
- Shows API-backed counts and empty/offline states.

Remaining UI work:

- Upload/import UI.
- Case workspace workflows.
- Policy/action UI.

## Recommended Next Work

### Primary Next Goal: Goal 8, Alerts And Cases

Goal 8 should be the main next implementation target because detector findings now create alerts with evidence links. The next stable layer is the analyst workflow that promotes alerts into cases, tracks investigation state, and shows evidence chronologically.

Recommended scope for the next development pass:

- Add typed case creation APIs in `sentinel-db`.
- Promote one alert into one case.
- Link existing alert evidence into the case timeline.
- Add case status, severity, confidence, disposition, and closure helpers.
- Add server command or API path for alert-to-case promotion.
- Add tests for case creation, evidence timeline ordering, and close-with-disposition behavior.

Definition of Done for the next pass:

- Analyst can create a case from one alert.
- Case timeline displays evidence in chronological order.
- Closing a case requires disposition and notes.
- Case records preserve alert, raw event, and normalized event references.

### Parallel Goal A: Continue Goal 10 UI Import Readiness

Parallel-safe work:

- Add an import status surface that reads API data only.
- Keep file upload controls disabled until HTTP import/upload endpoints exist.
- Add event/alert/case list rendering from existing read endpoints.

### Parallel Goal B: Expand Goal 19 Fixture Coverage

Parallel-safe work:

- Move representative normalization fixtures into `sample-data/`.
- Add import smoke tests that use reusable fixture files.
- Keep unit fixtures small and hand-authored for mapper edge cases.

## Suggested Parallel Plan

Use three short-lived implementation lanes:

| Lane | Owner Type | Goal | Can Start Now | Stop Point |
|---|---|---:|---|---|
| Case Workflow | Backend | 8 | Yes | Alert promotion, case status helpers, and evidence timeline. |
| UI Case Readiness | Frontend | 10 | Yes | API-backed alert/case detail display, no destructive actions. |
| Detector Fixtures | Backend | 7/19 | Yes | Reusable detector fixture files beyond unit fixtures. |

The safest order is:

1. Add alert-to-case promotion and evidence timeline helpers.
2. Expose enough case detail for the UI to display case evidence.
3. Keep frontend actions constrained to read-only or explicit safe case workflow commands.
4. Move to local model summaries after case evidence and citations are stable.

## Near-Term Risks

- Case workflow will churn if evidence timeline ordering and references are not stable.
- UI upload flows should wait for explicit HTTP upload/import design.
- Detector deduplication is not implemented yet, so repeated detector runs can create repeated alerts.

## Next Decision Needed

Choose the first case workflow target for Goal 8:

- Promote a single alert to a case from the CLI.
- Add HTTP case promotion endpoint.
- Add UI-only case detail view first.

Recommended for this app stage: promote a single alert to a case from the backend first, then expose the workflow through HTTP/UI after the case timeline contract is stable.
