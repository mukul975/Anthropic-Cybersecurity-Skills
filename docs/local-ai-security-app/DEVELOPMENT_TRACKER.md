# SentinelBlue Development Tracker

Last updated: 2026-06-10

This tracker records current implementation status against [PRODUCTION_GOALS.md](PRODUCTION_GOALS.md). The production goals document is the source of truth for goal scope; this tracker is the working execution board.

## Current Status

SentinelBlue now has an initialized product workspace plus durable backend foundations. The workspace exists under `product/sentinelblue/` with a Rust workspace, server binary crate, web app, Tauri desktop shell, packaging directories, sample data, model notes, local development docs, SQLite persistence, durable skill indexing, FTS-backed skill search, DB-backed HTTP read endpoints, JSON/JSONL raw event import, MVP event normalization, deterministic detector engine, detector-created alerts/evidence, alert-to-case promotion, case timeline, case closure workflow, local model health/configuration, redacted evidence-cited case summaries, persisted model runs, and read-only web API consumption.

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
| 8 | Alerts And Cases | Complete | Detector findings create alerts, alerts promote to cases, case timeline includes evidence/alerts/notes/actions/model summaries, and closure requires disposition plus notes. |
| 9 | Local Model Integration | Complete | Deterministic-only and OpenAI-compatible local model modes exist; model health, prompt redaction, evidence-cited summaries, unavailable-model guardrails, and model run persistence are complete. |
| 10 | Desktop UI | Next | Tauri shell exists and web UI consumes read-only health, skills, events, alerts, and cases APIs. Import/case workflows remain. |
| 11 | Wazuh Connector | Later | Depends on DB, ingestion, normalization, and connector health model. |
| 12 | Policy And Approval Engine | Later | Depends on actions, audit, users/roles direction, and backend execution boundaries. |
| 13 | Server Mode | Partial scaffold complete | Server binary, simple HTTP serving, health, and read endpoints exist; config, auth, metrics, static web serving, and deployment still remain. |
| 14 | Authentication And RBAC | Later | Should follow basic server API and persistence. |
| 15 | Observability | Later | Health scaffold exists; full metrics/logging/audit health depends on core services. |
| 16 | Network Security Expansion | Later | Should follow MVP ingestion, normalization, and detector engine. |
| 17 | Security Hardening | Later | Must be continuous, but final acceptance depends on implemented surfaces. |
| 18 | Packaging | Partial scaffold complete | Packaging directories exist; installable artifacts are not implemented. |
| 19 | Test Suite | In progress | Rust unit tests now cover core, API contracts, DB migrations, DB inserts, FTS search, repository skill indexing, server routing, DB-backed read endpoints, JSON/JSONL import, dedupe, MVP event normalization, detector runs, detector findings, alerts, evidence links, case promotion, case timelines, case closure requirements, model health, prompt redaction, deterministic summaries, and model run persistence. |
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

### Goal 8: Alerts And Cases

Artifacts:

- Case workflow persistence APIs: `product/sentinelblue/crates/sentinel-db/src/lib.rs`
- Case timeline API contract: `product/sentinelblue/crates/sentinel-api/src/lib.rs`
- Case workflow server commands: `product/sentinelblue/crates/sentinel-server/src/main.rs`
- Case timeline route: `GET /api/cases/{id}/timeline`

Completed work:

- Detector findings create alerts through Goal 7 detector persistence.
- Alerts can be promoted to cases with `sentinel-server --promote-alert`.
- Cases store status, severity, confidence, disposition, and closure timestamp.
- Existing alert evidence is linked into the promoted case.
- Case timeline returns detector alert evidence, raw/normalized event evidence, analyst notes, model summaries, and actions in chronological order.
- Analyst notes are stored as timeline evidence entries.
- Case closure requires non-empty disposition and notes.
- Case closure stores disposition, closes the case, and adds a closure note to the timeline.

Verified commands:

```bash
cd product/sentinelblue
cargo test
cargo run -p sentinel-server -- --import-file sample-data/wazuh-alert.sample.json --database /tmp/sentinelblue.db --source-name sample-wazuh --source-product wazuh
cargo run -p sentinel-server -- --run-detectors --database /tmp/sentinelblue.db
cargo run -p sentinel-server -- --promote-alert 1 --database /tmp/sentinelblue.db
cargo run -p sentinel-server -- --close-case 1 --database /tmp/sentinelblue.db --disposition benign --notes "Confirmed approved administration"
```

Verification result:

- A generated detector alert promotes into one triage case.
- Case timeline includes normalized event evidence and detector alert evidence.
- Case timeline ordering is covered by unit tests with explicit timestamps.
- Closing without disposition or notes is rejected.
- Closing with disposition and notes marks the case closed and adds a closure note.

### Goal 9: Local Model Integration

Artifacts:

- Model integration crate: `product/sentinelblue/crates/sentinel-model`
- Model run persistence APIs: `product/sentinelblue/crates/sentinel-db/src/lib.rs`
- Server model health and summary wiring: `product/sentinelblue/crates/sentinel-server/src/lib.rs`
- Case summary command: `product/sentinelblue/crates/sentinel-server/src/main.rs`

Completed work:

- Adds runtime configuration for deterministic-only mode and OpenAI-compatible local HTTP endpoints.
- Reports model health as loading, ready, degraded, unavailable, or deterministic-only disabled.
- Keeps deterministic-only summary generation working without a model.
- Adds case summary prompt templates built from case timeline evidence.
- Redacts secret-like values before prompt construction.
- Disables AI summary generation when model health is unavailable.
- Falls back to deterministic evidence-cited summaries when AI is unavailable or disabled.
- Requires every generated summary claim to cite evidence IDs or be marked as inference.
- Persists summary runs into `model_runs`.
- Includes model summaries in the case timeline.

Verified commands:

```bash
cd product/sentinelblue
cargo test
cargo run -p sentinel-server -- --import-file sample-data/wazuh-alert.sample.json --database /tmp/sentinelblue.db --source-name sample-wazuh --source-product wazuh
cargo run -p sentinel-server -- --run-detectors --database /tmp/sentinelblue.db
cargo run -p sentinel-server -- --promote-alert 1 --database /tmp/sentinelblue.db
cargo run -p sentinel-server -- --summarize-case 1 --database /tmp/sentinelblue.db
```

Verification result:

- Deterministic-only mode reports model health as disabled and does not attempt AI generation.
- Unavailable model endpoints disable AI summary generation.
- Prompt input redacts secret-like tokens before model use.
- Deterministic summaries cite case timeline evidence IDs.
- Model summaries are stored as model runs and appear in case timeline output.

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

### Primary Next Goal: Goal 10, Desktop UI

Goal 10 should be the main next implementation target because the backend now has enough stable read/write workflow surface for an analyst-facing workspace. The next stable layer is a desktop UI that makes the current health, event, alert, case, timeline, and model-summary workflows usable without relying on CLI commands.

Recommended scope for the next development pass:

- Add an analyst dashboard with backend health, ingestion, detector, alert, and case status.
- Add alert queue and case detail screens backed by existing APIs.
- Add case timeline rendering for evidence, notes, actions, and model summaries.
- Add disabled or staged controls for import, promote, summarize, and close workflows until HTTP mutation routes are implemented.
- Add model settings visibility for deterministic-only and OpenAI-compatible endpoint state.

Definition of Done for the next pass:

- Desktop/web UI has navigable dashboard, alerts, cases, events, skills, and settings surfaces.
- Case detail view shows timeline evidence and model summary entries.
- Empty, loading, offline, and API error states are handled without page crashes.
- Destructive or unavailable actions are visibly disabled until backend endpoints exist.
- The UI builds successfully and remains compatible with the Tauri shell.

Acceptance for the next pass:

- An analyst can open the app, see backend health, inspect imported events, review detector alerts, open a case, and read its evidence timeline.
- The UI clearly distinguishes available workflows from planned workflows.
- No screen requires seeded demo-only data to render correctly.

### Parallel Goal A: Goal 19 Test Suite Expansion

Parallel-safe work:

- Move representative normalization and detector fixtures into `sample-data/`.
- Add reusable CLI smoke tests for import, detection, case promotion, and case summary.
- Add UI build and API contract checks to the regular verification path.

### Parallel Goal B: Goal 11 Wazuh Connector Design Spike

Parallel-safe work:

- Define Wazuh connector configuration and local-only credential storage boundaries.
- Add connector health states without fetching remote data yet.
- Identify the exact Wazuh API endpoints needed for alert polling and cursor persistence.

## Suggested Parallel Plan

Use three short-lived implementation lanes:

| Lane | Owner Type | Goal | Can Start Now | Stop Point |
|---|---|---:|---|---|
| Analyst Workspace | Frontend | 10 | Yes | Dashboard, alert list, case detail, timeline/model summary display. |
| Verification Harness | Backend | 19 | Yes | Reusable smoke coverage for the current CLI workflow. |
| Wazuh Connector Prep | Backend | 11 | Yes | Config schema, health model, endpoint contract, no production polling yet. |

The safest order is:

1. Build UI read surfaces from existing stable API routes.
2. Add case detail and timeline rendering before adding mutation controls.
3. Add mutation API design for promote, summarize, close, and import workflows.
4. Add Wazuh connector config and health after UI can show connector status cleanly.

## Near-Term Risks

- UI upload flows should wait for explicit HTTP upload/import design.
- Case mutation flows need idempotent API behavior before exposing active buttons.
- Detector deduplication is not implemented yet, so repeated detector runs can create repeated alerts.

## Next Decision Needed

Choose the first Desktop UI target for Goal 10:

- Dashboard and navigation shell first.
- Alert queue and case detail first.
- Settings and model/connector health first.

Recommended for this app stage: alert queue and case detail first, because they expose the highest-value backend workflow now available.
