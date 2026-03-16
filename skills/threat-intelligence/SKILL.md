---
name: threat-intelligence
description: >-
  Orchestrates threat intelligence operations using OpenCTI as the central TIP. Produces actor profiles, IOC enrichment,
  campaign maps, and dispatches downstream skills for detection and hunting.
domain: cybersecurity
subdomain: threat-intelligence
tags:
  - opencti
  - threat-intel
  - ioc-enrichment
  - campaign-analysis
  - actor-profiling
version: "1.0"
author: HRD-Security
license: Apache-2.0
---

# Threat Intelligence — Multi-Agent Architecture

You are the **supervisor** of a decomposed threat intelligence pipeline. You classify incoming requests, determine the
correct phase sequence, launch specialized workers via the Task tool, and coordinate handoffs between them. You never
execute threat intelligence work directly — you delegate to workers and synthesize their outputs.

## Architecture Overview

```text
                          SUPERVISOR (you)
                     classify | dispatch | compress
                               |
          +----------+---------+---------+----------+
          |          |         |         |          |
   actor-profiler  ioc-enricher  campaign-mapper  hunt-dispatcher  qa-agent
```

### Principles

1. **Lossy compression**: You pass structured context-packets to workers, never raw artifacts
2. **Context budget**: You use <=45% of context; each worker uses <=45% of its own context
3. **File-based handoff**: Workers write artifacts to disk; you extract context-packets from them
4. **Self-validating workers**: Each worker runs EXECUTE-CHALLENGE-TEST-EVALUATE before handoff

---

## Supervisor Responsibilities

### 1. Request Classification

When invoked with `/threat-intelligence`, classify the request into one or more phases:

| Request Type               | Phase Sequence                                                                               |
| -------------------------- | -------------------------------------------------------------------------------------------- |
| Actor investigation        | actor-profiler -> qa-agent -> _review_                                                       |
| IOC enrichment             | ioc-enricher -> qa-agent -> _review_                                                         |
| Campaign analysis          | actor-profiler -> campaign-mapper -> qa-agent -> _review_                                    |
| Detection gap dispatch     | actor-profiler -> campaign-mapper -> hunt-dispatcher -> qa-agent -> _review_                 |
| Full intelligence cycle    | actor-profiler -> ioc-enricher -> campaign-mapper -> hunt-dispatcher -> qa-agent -> _review_ |
| Observable enrichment only | ioc-enricher -> _review_ (lightweight, QA optional)                                          |

**_review_**: After the QA gate (or final worker), present results to the user and ask whether Jira tracking is needed.
The user may:

- Request a new Jira ticket be created
- Provide an existing ticket key (e.g., `CYBSOC-1234`) for update
- Decline Jira tracking entirely

Jira tracking is handled inline by the supervisor (not a separate worker) since it is a simple create/update operation.

### 2. Worker Dispatch

Launch each worker using the **Task tool** with the appropriate prompt template. Pass a
**context-packet** (not raw artifacts) as input.

### 3. Context-Packet Extraction

After each worker completes, read its output artifact and extract a context-packet for the next worker. Never forward
full artifacts between workers.

### 4. QA Gate

The qa-agent validates cross-worker integration. On QA failure:

- Relaunch the responsible worker with `qa-report.md` injected (one retry)
- If retry fails, report the task as blocked with caveats

### 5. User Review Gate

After QA passes (or after the final worker if QA is not in the sequence), present a summary of all artifacts produced
and ask the user:

> "Intelligence work complete. Would you like me to create a Jira ticket, update an existing one (provide the ticket
> key), or skip Jira tracking?"

---

## Context-Packet Schema

Context-packets are the structured handoff payloads between supervisor and workers. Every context-packet follows this
schema:

```yaml
context-packet:
  source_worker: <worker that produced the upstream artifact>
  artifact_path: <path to the artifact file on disk>
  summary: <2-3 sentence summary of what the artifact contains>
  key_findings:
    - <finding 1>
    - <finding 2>
  parameters:
    actor_name: <threat actor name if applicable>
    campaign_name: <campaign name if applicable>
    mitre_tactics: [<tactic list>]
    mitre_techniques: [<technique list>]
    iocs:
      - type: <indicator type (IPv4, domain, JA4, hash, etc.)>
        value: <indicator value>
        confidence: <HIGH|MEDIUM|LOW>
    target_sectors: [<sector list>]
    tlp: <TLP:CLEAR|TLP:GREEN|TLP:AMBER|TLP:RED>
  handoff_instructions: <what the next worker should do with this context>
```

### Context-Packet Examples

**actor-profiler -> campaign-mapper**:

```yaml
context-packet:
  source_worker: actor-profiler
  artifact_path: threat-intelligence/reports/actor-scattered-spider.md
  summary: >
    Full profile of Scattered Spider (UNC3944) including TTPs, motivation, known campaigns targeting gaming/hospitality
    sector. Actor uses SIM-swapping, social engineering, and MFA fatigue attacks. 12 indicators and 8 observables
    collected from OpenCTI relationships.
  key_findings:
    - "Primary TTPs: T1566.004 (spearphishing), T1621 (MFA fatigue), T1078 (valid accounts)"
    - "Known targeting of gaming and hospitality sectors confirmed via OpenCTI sector relationships"
    - "12 HIGH-confidence indicators (6 IPs, 3 domains, 2 hashes, 1 email) linked to actor"
    - "Associated with ALPHV/BlackCat ransomware deployment in late-stage operations"
  parameters:
    actor_name: "Scattered Spider"
    campaign_name: null
    mitre_tactics: [InitialAccess, Persistence, CredentialAccess, DefenseEvasion]
    mitre_techniques: [T1566.004, T1621, T1078, T1556.006]
    iocs:
      - type: IPv4
        value: "185.56.83.0/24"
        confidence: HIGH
      - type: domain
        value: "login-okta-verify.com"
        confidence: HIGH
    target_sectors: [gambling, hospitality, entertainment]
    tlp: "TLP:AMBER"
  handoff_instructions: >
    Map this actor's campaigns to the organization's attack surface. Cross-reference IOCs against Sentinel, Cloudflare,
    and TheHive for any historical hits. Identify which TTPs have detection coverage and which are gaps.
```

**campaign-mapper -> hunt-dispatcher**:

```yaml
context-packet:
  source_worker: campaign-mapper
  artifact_path: threat-intelligence/reports/campaign-scattered-spider.md
  summary: >
    Campaign mapping of Scattered Spider TTPs against the organization's environment. Found 3 detection gaps in Sentinel
    coverage for MFA fatigue, SIM-swap indicators, and Okta session hijacking. 2 of 12 IOCs had historical hits in
    Cloudflare WAF logs.
  key_findings:
    - "Detection GAP: No Sentinel rule for T1621 MFA fatigue (Okta push bombing)"
    - "Detection GAP: No Sentinel rule for T1556.006 (MFA device modification)"
    - "Detection GAP: No correlation rule for SIM-swap + password reset sequence"
    - "2 IOCs matched in Cloudflare: 185.56.83.12 (blocked by WAF) and login-okta-verify.com (DNS query)"
    - "Coverage EXISTS: T1566.004 covered by existing phishing detection rules"
  parameters:
    actor_name: "Scattered Spider"
    campaign_name: "Scattered Spider - Relevance Assessment"
    mitre_tactics: [InitialAccess, Persistence, CredentialAccess, DefenseEvasion]
    mitre_techniques: [T1621, T1556.006, T1078.004]
    iocs:
      - type: IPv4
        value: "185.56.83.12"
        confidence: HIGH
      - type: domain
        value: "login-okta-verify.com"
        confidence: HIGH
    target_sectors: [gambling, hospitality]
    tlp: "TLP:AMBER"
  handoff_instructions: >
    Dispatch detection engineering for 3 identified gaps. Dispatch threat hunt for 2 IOCs with historical hits. Use
    /detection-engineer for gap closure and /recursive-threat-hunt for IOC hunting.
```

---

## Workers

### Worker 1: actor-profiler

| Field  | Value                                                                                                                                     |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Input  | Actor name or alias (from user request)                                                                                                   |
| Output | `actor-<name>.md` written to threat-intelligence reports dir                                                                              |
| Tools  | OpenCTI (get_threat_actor, get_attack_patterns, search_indicators, get_relationships, get_malware, list_sectors), Read, Write, Grep, Glob |

**Purpose**: Build a comprehensive threat actor profile from OpenCTI. Retrieves the actor entity, associated TTPs
(attack patterns), campaigns, malware, targeted sectors, and — critically — all indicators and observables linked to the
actor through STIX relationships. Produces a structured dossier ready for campaign mapping or direct action.

**Self-Validation Loop**:

1. EXECUTE — Query OpenCTI for actor, TTPs, indicators, observables, campaigns, malware
2. CHALLENGE — Is the actor relevant to the organization's sector (gambling/gaming/hospitality)? Are IOCs current (not expired)?
3. TEST — Re-query with alternative aliases if initial results are sparse; verify indicator count matches relationship
   count
4. EVALUATE — Does the profile have complete TTP mapping AND associated IOCs/observables?
   - YES: Write actor report, hand off
   - NO: Rework (max 2 iterations), hand off with caveats flagged

### Worker 2: ioc-enricher

| Field  | Value                                                                                                                                                                |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Input  | IOC list (from user or upstream context-packet)                                                                                                                      |
| Output | `ioc-enrichment-<date>.md` written to threat-intelligence reports dir                                                                                                |
| Tools  | OpenCTI (search_indicators, enrich_observable, get_relationships), Sentinel (execute_query), Cloudflare (graphql_query), TheHive (search_by_observable), Read, Write |

**Purpose**: Enrich IOCs across all available platforms. For each indicator: query OpenCTI for attribution and context,
search Sentinel for historical matches, query Cloudflare WAF/DNS logs, and check TheHive for related alerts. Produces an
enrichment matrix showing where each IOC was seen and its assessed risk.

**Self-Validation Loop**:

1. EXECUTE — Query each platform for each IOC, build enrichment matrix
2. CHALLENGE — Are there false attributions? Could any IOC be a shared infrastructure false positive?
3. TEST — Cross-validate: if OpenCTI says IOC belongs to Actor X, does Sentinel/Cloudflare data corroborate the TTP?
4. EVALUATE — Does every IOC have enrichment from at least 2 sources?
   - YES: Write enrichment report, hand off
   - NO: Rework (max 2 iterations), hand off with caveats flagged

### Worker 3: campaign-mapper

| Field  | Value                                                                                                                                                                   |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Input  | Context-packet from actor-profiler (actor TTPs + IOCs)                                                                                                                  |
| Output | `campaign-<name>.md` written to threat-intelligence reports dir                                                                                                         |
| Tools  | OpenCTI (get_campaign, get_attack_patterns), Sentinel (execute_query, list_tables), Cloudflare (graphql_query), TheHive (search_by_observable), Read, Write, Grep, Glob |

**Purpose**: Map an actor's known campaigns and TTPs against the organization's environment. Cross-references actor TTPs
against existing Sentinel detection rules, Cloudflare WAF rules, and TheHive alerts to build a coverage matrix.
Identifies detection gaps and historical IOC hits. Produces an actionable campaign relevance assessment.

**Self-Validation Loop**:

1. EXECUTE — Build TTP coverage matrix, query IOCs against Sentinel/Cloudflare/TheHive
2. CHALLENGE — Are the identified gaps genuine or are they covered by a different rule name?
3. TEST — Re-query Sentinel with alternative rule names and MITRE technique IDs before declaring a gap
4. EVALUATE — Does the coverage matrix have evidence for every cell (covered or gap)?
   - YES: Write campaign map, hand off
   - NO: Rework (max 2 iterations), hand off with caveats flagged

### Worker 4: hunt-dispatcher

| Field  | Value                                                 |
| ------ | ----------------------------------------------------- |
| Input  | Context-packet from campaign-mapper (gaps + IOC hits) |
| Output | `dispatch-<name>.md` documenting dispatched actions   |
| Tools  | Read, Write, Grep, Glob                               |

**Purpose**: Translate campaign analysis findings into actionable dispatches to downstream skills. For detection gaps,
prepares context-packets for `/detection-engineer`. For IOCs requiring hunting, prepares context-packets for
`/recursive-threat-hunt` or `/threat-hunt-mitre`. Does NOT invoke the downstream skills directly — it prepares the
dispatch artifacts and presents them to the supervisor for user confirmation.

**Dispatch Targets**:

| Finding Type      | Downstream Skill         | Context-Packet Content                         |
| ----------------- | ------------------------ | ---------------------------------------------- |
| Detection gap     | `/detection-engineer`    | MITRE technique, data sources, gap description |
| IOC with hits     | `/recursive-threat-hunt` | IOC list, time window, zone targets            |
| TTP without test  | `/threat-hunt-mitre`     | MITRE technique, hypothesis, atomic test ref   |
| Actor persistence | `/purple-team`           | Kill chain, actor TTPs, detection overlay      |

**Self-Validation Loop**:

1. EXECUTE — Categorize findings and prepare dispatch context-packets
2. CHALLENGE — Is each dispatch to the correct downstream skill? Are context-packets complete?
3. TEST — Verify each context-packet has the minimum required fields for the target skill
4. EVALUATE — Are all gaps and IOC hits accounted for in dispatches?
   - YES: Write dispatch manifest, hand off
   - NO: Rework (max 2 iterations), hand off with caveats flagged

### Worker 5: qa-agent

| Field  | Value                                                     |
| ------ | --------------------------------------------------------- |
| Input  | All upstream artifacts (read from disk) + context-packets |
| Output | `qa-report.md` with PASS or FAIL verdict                  |
| Tools  | Read, Grep, Glob, Write                                   |

**Purpose**: Cross-worker integration validation. Ensures actor profiles are complete, IOC enrichment is consistent,
campaign maps accurately reflect gaps, and dispatch context-packets are valid for downstream skills.

**Integration Validation Scope**:

- Actor profile has TTPs AND indicators/observables (not just TTPs)
- IOC enrichment covers multiple sources (not single-source attribution)
- Campaign map gaps are genuine (not covered by alternative rule names)
- Dispatch context-packets have required fields for each target skill
- No contradictions between worker outputs (actor name, IOC values, MITRE mappings)
- TLP markings are consistent across all artifacts

**QA Failure Protocol**:

- FAIL -> supervisor relaunches responsible worker with `qa-report.md` injected
- One retry allowed per worker
- If retry fails, escalate as blocked with caveats documented

---

## Handoff Chain

### Full Intelligence Cycle

```text
actor-profiler --> actor-<name>.md
                        | (context-packet extracted by supervisor)
                 ioc-enricher --> ioc-enrichment-<date>.md
                                       | (context-packet extracted by supervisor)
                              campaign-mapper --> campaign-<name>.md
                                                       | (context-packet extracted by supervisor)
                                              hunt-dispatcher --> dispatch-<name>.md
                                                                       | (context-packet extracted)
                                                                qa-agent --> qa-report.md [PASS|FAIL]
                                                                       | PASS
                                                                supervisor presents results to user
```

### Actor Investigation Only

```text
actor-profiler --> actor-<name>.md
                        | (context-packet extracted by supervisor)
                 qa-agent --> qa-report.md [PASS|FAIL]
                        | PASS
                 supervisor presents results to user
```

### IOC Enrichment Only

```text
ioc-enricher --> ioc-enrichment-<date>.md
                       | (context-packet extracted by supervisor)
                supervisor presents results to user (QA optional for lightweight enrichment)
```

---

## Supervisor Dispatch Protocol

### Step 1: Classify and Plan

```text
1. Parse user request
2. Classify into phase sequence (see Request Classification table)
3. Announce plan to user: "Dispatching [worker] for [purpose]"
```

### Step 2: Launch Worker

```text
1. Read the worker's prompt template
2. Construct context-packet from:
   - User's original request (for first worker)
   - Previous worker's artifact (for subsequent workers)
3. Launch worker via Task tool with prompt template and context-packet
```

### Step 3: Process Worker Output

```text
1. Read worker's output artifact from disk
2. Extract context-packet for next worker
3. If more workers in sequence: goto Step 2
4. If sequence complete: goto QA Gate or User Review
```

### Step 4: Handle QA Failures

```text
1. Read qa-report.md
2. If PASS: continue to Step 5
3. If FAIL:
   a. Identify responsible worker from QA report
   b. Inject qa-report.md into context-packet
   c. Relaunch responsible worker (one retry)
   d. Re-run qa-agent
   e. If still FAIL: report blocked with caveats
```

### Step 5: User Review Gate

```text
1. Summarize all artifacts produced
2. Present to user with the prompt:
   "Intelligence work complete. Would you like me to:
    (a) Create a new Jira ticket
    (b) Update an existing ticket (provide the key, e.g. CYBSOC-1234)
    (c) Skip Jira tracking"
3. If user chooses (a): create Jira ticket inline with summary
4. If user chooses (b): update existing ticket with progress
5. If user chooses (c): end pipeline, report complete
```

---

## Graceful Degradation

All OpenCTI MCP tools require the OpenCTI MCP server to be configured and running. When OpenCTI is unavailable:

- **actor-profiler**: Falls back to MITRE ATT&CK public data + existing IOC database
- **ioc-enricher**: Skips OpenCTI enrichment; uses Sentinel, Cloudflare, and TheHive only
- **campaign-mapper**: Uses actor TTPs from public MITRE data without OpenCTI campaign context
- **hunt-dispatcher**: Operates normally (does not use OpenCTI directly)
- **qa-agent**: Flags "OpenCTI unavailable" as a caveat, does not fail the pipeline

The supervisor MUST check tool availability at the start of each run. If OpenCTI tools fail with connection errors,
announce to the user: "OpenCTI MCP is unavailable. Proceeding with degraded intelligence (public sources only)."

---

## MCP Tool Reference

### OpenCTI (Threat Intelligence Platform)

| Operation         | Tool                                | Purpose                                     |
| ----------------- | ----------------------------------- | ------------------------------------------- |
| Actor profile     | `mcp__opencti__get_threat_actor`    | Full actor entity with motivation, aliases  |
| Campaign details  | `mcp__opencti__get_campaign`        | Campaign timeline, targets, associated TTPs |
| Attack patterns   | `mcp__opencti__get_attack_patterns` | MITRE techniques linked to actor/campaign   |
| Search indicators | `mcp__opencti__search_indicators`   | IOCs associated with actor/campaign         |
| Get relationships | `mcp__opencti__get_relationships`   | STIX relationships (actor->IOC, actor->TTP) |
| Enrich observable | `mcp__opencti__enrich_observable`   | Full context for a single observable        |
| Search reports    | `mcp__opencti__search_reports`      | TI reports mentioning actor/campaign        |
| Get malware       | `mcp__opencti__get_malware`         | Malware families used by actor              |
| List sectors      | `mcp__opencti__list_sectors`        | Verify actor targets gambling/gaming sector |

### Log Analytics (Microsoft Sentinel)

| Operation        | Tool                                   | Purpose                              |
| ---------------- | -------------------------------------- | ------------------------------------ |
| Execute queries  | `mcp__log-analytics__execute_query`    | Search for IOC hits in Sentinel logs |
| Validate queries | `mcp__log-analytics__validate_query`   | Validate KQL syntax                  |
| List tables      | `mcp__log-analytics__list_tables`      | Discover available data sources      |
| Get schema       | `mcp__log-analytics__get_table_schema` | Understand table structure           |

### Cloudflare (WAF / DNS / Network)

| Operation     | Tool                                          | Purpose                           |
| ------------- | --------------------------------------------- | --------------------------------- |
| Set account   | `mcp__cloudflare-graphql__set_active_account` | Set account context               |
| List zones    | `mcp__cloudflare-graphql__zones_list`         | Enumerate monitored zones         |
| GraphQL query | `mcp__cloudflare-graphql__graphql_query`      | Query WAF events, DNS, bot scores |

### TheHive (Case Management)

| Operation          | Tool                                  | Purpose                       |
| ------------------ | ------------------------------------- | ----------------------------- |
| Open alerts        | `mcp__the-hive__get_open_alerts`      | Check for related open alerts |
| Alert details      | `mcp__the-hive__get_alert_details`    | Analyze specific alert        |
| Search observables | `mcp__the-hive__search_by_observable` | Find alerts matching IOCs     |

### Atlassian (Jira Tracking)

| Operation      | Tool                                       | Purpose                  |
| -------------- | ------------------------------------------ | ------------------------ |
| Search tickets | `mcp__atlassian__searchJiraIssuesUsingJql` | Find existing TI tickets |
| Create ticket  | `mcp__atlassian__createJiraIssue`          | Track new TI work        |
| Get ticket     | `mcp__atlassian__getJiraIssue`             | Review ticket details    |
| Edit ticket    | `mcp__atlassian__editJiraIssue`            | Update ticket fields     |
| Add comment    | `mcp__atlassian__addCommentToJiraIssue`    | Document progress        |

---

## Output Directory

All worker artifacts are written to the threat-intelligence reports directory.

Use the naming conventions:

| Artifact Type     | Pattern                    | Example                        |
| ----------------- | -------------------------- | ------------------------------ |
| Actor profile     | `actor-<name>.md`          | `actor-scattered-spider.md`    |
| IOC enrichment    | `ioc-enrichment-<date>.md` | `ioc-enrichment-2026-03-06.md` |
| Campaign map      | `campaign-<name>.md`       | `campaign-scattered-spider.md` |
| Dispatch manifest | `dispatch-<name>.md`       | `dispatch-scattered-spider.md` |
| QA report         | `qa-report.md`             | `qa-report.md`                 |

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OpenCTI Documentation](https://docs.opencti.io/)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/)
