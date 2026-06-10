# SentinelBlue Development Tracker

Last updated: 2026-06-09

This tracker records current implementation status against [PRODUCTION_GOALS.md](PRODUCTION_GOALS.md). The production goals document is the source of truth for goal scope; this tracker is the working execution board.

## Current Status

SentinelBlue now has an initialized product workspace plus durable backend foundations. The workspace exists under `product/sentinelblue/` with a Rust workspace, server binary crate, web app, Tauri desktop shell, packaging directories, sample data, model notes, local development docs, SQLite persistence, durable skill indexing, FTS-backed skill search, DB-backed HTTP read endpoints, JSON/JSONL raw event import, Wazuh alert normalization, and read-only web API consumption.

## Goal Status Board

| Goal | Title | Status | Notes |
|---:|---|---|---|
| 1 | Create Product Workspace | Complete | Product workspace created under `product/sentinelblue/`. |
| 2 | Database Foundation | Complete | `sentinel-db` crate, versioned migration, core tables, idempotent init, DB health, and tests are complete. |
| 3 | Skill Indexer | Complete | Parser, DB persistence, FTS search, checksum reindexing, and repository indexing tests are complete. |
| 4 | Basic API Layer | Complete | HTTP stack, `GET /api/health`, DB-backed read endpoints, API contracts, errors, and route tests are complete. |
| 5 | File Log Import | Complete | `sentinel-ingest` imports JSON/JSONL into raw events, hashes payloads, skips duplicates, reports errors, and is wired into `sentinel-server`. |
| 6 | Event Normalization | Partial / Next | Source-neutral normalized event draft exists and Wazuh alert normalization is implemented. Broader MVP source mapping remains. |
| 7 | Detection Engine | Blocked by Goals 2 and 6 | Requires normalized event schema and detector run persistence. |
| 8 | Alerts And Cases | Blocked by Goals 2 and 7 | Requires alerts, evidence, detector output, and case tables. |
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
| 19 | Test Suite | In progress | Rust unit tests now cover core, API contracts, DB migrations, DB inserts, FTS search, repository skill indexing, server routing, DB-backed read endpoints, JSON/JSONL import, dedupe, and Wazuh normalization. |
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
- Server health reports `database` as healthy with `schema_version=3`, `applied_migrations=3`, and `core_tables=12`.

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

## Partial Parallel Goal Evidence

### Goal 6: Event Normalization First Mapper

Completed narrow work:

- Defines a source-neutral normalized event draft.
- Implements Wazuh alert JSON normalization.
- Stores normalized Wazuh rows in `normalized_events` during import.
- Tests Wazuh fields for event time, host, asset ID, user, source IP, command line, rule ID, rule name, and severity.

Remaining Goal 6 work:

- Sysmon JSON normalization.
- Zeek DNS/connection normalization.
- Suricata EVE normalization.
- API gateway log normalization.
- Identity/authentication CSV or JSON normalization.
- Normalization tests for each MVP source.

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

### Primary Next Goal: Goal 6, Event Normalization

Goal 6 should be the main next implementation target because detectors and cases need consistent normalized event rows across the MVP telemetry sources.

Recommended scope for the next development pass:

- Keep Wazuh normalization as the first mapper.
- Add Sysmon process event normalization.
- Add Zeek DNS/connection normalization.
- Add Suricata EVE alert normalization.
- Add API gateway access log normalization.
- Add identity/authentication JSON normalization.
- Add fixture tests for each mapper.

Definition of Done for the next pass:

- Different log sources can be queried using common fields.
- Normalization tests cover Wazuh, Sysmon, Zeek, Suricata, API gateway, and identity/authentication samples.
- Raw evidence remains reachable from normalized events.

### Parallel Goal A: Continue Goal 10 UI Import Readiness

Parallel-safe work:

- Add an import status surface that reads API data only.
- Keep file upload controls disabled until HTTP import/upload endpoints exist.
- Add event/alert/case list rendering from existing read endpoints.

### Parallel Goal B: Start Goal 7 Detector Contracts

Parallel-safe work:

- Define detector trait and finding output structs.
- Do not implement production detectors until normalized event coverage is broader.

## Suggested Parallel Plan

Use three short-lived implementation lanes:

| Lane | Owner Type | Goal | Can Start Now | Stop Point |
|---|---|---:|---|---|
| Normalization | Backend | 6 | Yes | MVP source mappers and tests. |
| UI Import Readiness | Frontend | 10 | Yes | API-backed status/list views, no upload mutation yet. |
| Detector Contracts | Backend | 7 | Yes | Trait and finding schema only. |

The safest order is:

1. Finish Goal 6 normalization breadth across MVP sources.
2. Add detector contracts in parallel, but wait on real detector logic until normalized fixtures exist.
3. Keep frontend work read-only until import/upload HTTP endpoints are designed.
4. Move to detector implementation after normalized Wazuh/Sysmon/DNS/API events exist.

## Near-Term Risks

- Detector logic will churn if normalized field names are not stable.
- UI upload flows should wait for explicit HTTP upload/import design.
- CSV/TSV import should be added after JSON/JSONL import behavior remains stable.

## Next Decision Needed

Choose the normalization fixture set for Goal 6:

- Minimal hand-authored fixtures per source.
- Realistic samples under `sample-data/`.
- Both hand-authored unit fixtures and sample-data integration fixtures.

Recommended for this app stage: both hand-authored unit fixtures and reusable `sample-data/` integration fixtures.
