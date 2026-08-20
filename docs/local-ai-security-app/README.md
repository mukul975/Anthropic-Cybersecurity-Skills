# Local AI Security Monitoring App Build Packet

This folder defines a build-ready product direction for a local-first autonomous AI security monitoring app built with Rust, Tauri, llama.cpp, and the cybersecurity skills in this repository.

## Product Name

Working name: **SentinelBlue**

## One-Line Definition

SentinelBlue is a local-first AI SOC assistant that continuously ingests endpoint, identity, network, API, cloud, and threat-intelligence telemetry; maps evidence to curated cybersecurity skills; runs deterministic detections; summarizes incidents with a local model; and performs approved security automation.

## Documents

- [PRD.md](PRD.md): exhaustive product requirements, scope, personas, features, KPIs, non-goals, risk model, acceptance criteria.
- [USE_CASES.md](USE_CASES.md): use cases, user journeys, event flows, user stories, automation policy, and acceptance tests.
- [CASE_STUDIES.md](CASE_STUDIES.md): realistic operating scenarios for small business, solo analyst, MSSP, lab, and server deployment.
- [TECHNICAL_DESIGN.md](TECHNICAL_DESIGN.md): Rust/Tauri architecture, llama.cpp runtime, local model packaging, data model, APIs, detectors, deployment, server mode, security controls.
- [PRODUCTION_GOALS.md](PRODUCTION_GOALS.md): sequential build goals with definition of done and acceptance criteria for reaching a production-stable app.
- [DEVELOPMENT_TRACKER.md](DEVELOPMENT_TRACKER.md): current implementation status, completed-goal evidence, and next parallel work lanes.
- [UX_DESIGN_SYSTEM.md](UX_DESIGN_SYSTEM.md): app IA, screens, interaction model, Meta-blue inspired light/dark/system themes, design tokens, accessibility, empty/loading/error states.
- [RESEARCH_NOTES.md](RESEARCH_NOTES.md): source-backed feasibility notes and references.

## Core Product Decisions

- Use this repository as the skills/playbook knowledge layer.
- Build a new Rust workspace as the product backend.
- Use Tauri for the local desktop shell.
- Run `llama-server` as a managed sidecar for desktop mode and as a managed service/container for server mode.
- Use a local GGUF model such as `unsloth/gemma-4-31B-it-GGUF:UD-Q4_K_XL` for the workstation target, with smaller fallback models for constrained machines.
- Use deterministic detectors for security-critical scoring and let the model explain, correlate, plan, and draft.
- Allow autonomous read-only analysis by default.
- Require human approval for containment and destructive actions.
- Support both interactive desktop use and continuous headless server operation.

## Build Phases

1. Skill indexer and local search.
2. llama.cpp runtime manager and health checks.
3. Wazuh and JSON log ingestion.
4. Deterministic detectors for endpoint, identity, DNS, API, and IOC workflows.
5. Case store, evidence graph, and model-generated analyst summaries.
6. Tauri desktop UI with light/dark/system themes.
7. Action policy engine and approval workflow.
8. Continuous server mode with API, web UI, metrics, and service manager.
9. Signed packaging, updates, model bootstrap, and admin hardening.
