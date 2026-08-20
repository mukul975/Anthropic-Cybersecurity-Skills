# SentinelBlue Use Cases

## Use Case Format

Each use case includes:

- Actor
- Trigger
- Preconditions
- Telemetry
- Relevant skills
- System behavior
- AI behavior
- Automation policy
- Acceptance tests

## UC-001: First Launch And Local Setup

Actor: Solo security operator

Trigger: User opens SentinelBlue for the first time.

Preconditions:

- App is installed.
- No database exists.
- No model runtime configured.

Telemetry:

- None.

Relevant skills:

- `performing-log-source-onboarding-in-siem`
- `implementing-endpoint-detection-with-wazuh`

System behavior:

1. Create local application data directory.
2. Initialize SQLite database.
3. Index all repository skills.
4. Ask user to choose operating mode:
   - Desktop local-only.
   - Desktop connected to server.
   - Server/admin setup.
5. Ask user to choose model mode:
   - Download recommended GGUF.
   - Use existing local model file.
   - Connect to existing OpenAI-compatible local endpoint.
   - Run deterministic-only mode.
6. Run model health check if configured.
7. Offer to import sample logs.
8. Offer to configure Wazuh.

AI behavior:

- AI is disabled until model health is ready.
- If enabled, AI can explain setup choices, but cannot change filesystem, install services, or download models without explicit user action.

Automation policy:

- Read-only setup checks allowed.
- Downloads require confirmation.
- Service installation requires admin confirmation.

Acceptance tests:

- New user can reach dashboard without model configured.
- Skill index completes and reports count.
- Deterministic-only mode works.
- Model setup failure does not block log ingestion.

## UC-002: Wazuh Alert Triage

Actor: SOC analyst

Trigger: Wazuh alert arrives or is imported.

Preconditions:

- Wazuh connector configured with read-only API access.
- Skill index exists.
- Model runtime healthy or deterministic-only mode enabled.

Telemetry:

- Wazuh alert JSON.
- Wazuh agent inventory.
- Optional vulnerability detection status.

Relevant skills:

- `implementing-endpoint-detection-with-wazuh`
- `analyzing-security-logs-with-splunk`
- `building-incident-response-playbook`
- Skill selected by alert ATT&CK mapping.

System behavior:

1. Poll or receive Wazuh alert.
2. Normalize alert into `NormalizedEvent`.
3. Enrich with agent name, IP, OS, last keepalive, groups, rule level, rule ID.
4. Run relevant detectors if source fields match.
5. Route to skills using Wazuh tags, rule description, and ATT&CK IDs.
6. Create alert row and optionally case.
7. Display alert in queue with evidence and skill matches.

AI behavior:

- Summarize what happened.
- Explain why the Wazuh alert matters.
- Recommend investigation questions.
- Identify missing telemetry.
- Draft a case title and severity rationale.

Automation policy:

- Read Wazuh agents: allowed.
- Read recent Wazuh alerts: allowed.
- Trigger Wazuh active response: approval required.
- Isolate endpoint: approval required.

Acceptance tests:

- Wazuh alert is visible within configured polling interval.
- AI summary references alert ID and agent evidence.
- Suggested action is not executed until approved.

## UC-003: Process Injection Hunt From Sysmon

Actor: Threat hunter

Trigger: Analyst starts a T1055 process injection hunt.

Preconditions:

- Sysmon events imported.
- Event IDs 1, 8, and 10 are present.

Telemetry:

- Sysmon process creation.
- Sysmon CreateRemoteThread.
- Sysmon ProcessAccess.

Relevant skills:

- `hunting-for-process-injection-techniques`
- `detecting-t1055-process-injection-with-sysmon`
- `detecting-process-hollowing-technique`

System behavior:

1. Analyst chooses "Process Injection" hunt template.
2. App validates required telemetry coverage.
3. Detection engine runs process injection detector.
4. Detector scores source process, target process, access mask, user, parent process, and known false-positive pairs.
5. App builds relationship graph.
6. App creates findings or attaches results to existing case.

AI behavior:

- Explain why each finding is suspicious.
- Map findings to ATT&CK T1055 and relevant sub-techniques where evidence supports it.
- Suggest next evidence to collect: parent process, command line, hash, network connections, user context.
- Distinguish detection evidence from inferred intent.

Automation policy:

- Run detector: allowed.
- Query local event store: allowed.
- Collect additional endpoint data: configurable.
- Kill process/quarantine file/isolate host: approval required.

Acceptance tests:

- Known suspicious source-target pair creates alert.
- Known legitimate pair is suppressed or lower severity.
- Result includes evidence IDs and access rights.

## UC-004: Suspicious PowerShell Investigation

Actor: SOC analyst

Trigger: Detector flags encoded or download-executing PowerShell.

Preconditions:

- Sysmon or Windows event logs are imported.
- Process command line logging exists.

Telemetry:

- Sysmon Event ID 1.
- Windows PowerShell logs.
- Optional network logs.

Relevant skills:

- `detecting-suspicious-powershell-execution`
- `analyzing-powershell-script-block-logging`
- `deobfuscating-powershell-obfuscated-malware`
- `detecting-living-off-the-land-attacks`

System behavior:

1. Detector identifies suspicious PowerShell indicators.
2. App correlates parent process, user, host, command line, hashes, and network events.
3. App creates case if severity threshold is met.
4. App retrieves relevant skills and investigation checklist.

AI behavior:

- Decode readable indicators if safe.
- Summarize observed command behavior.
- Explain likely attack stage.
- Recommend containment only if evidence warrants it.

Automation policy:

- Decode command string locally: allowed.
- Search local events for related host/user: allowed.
- Disable user or isolate host: approval required.

Acceptance tests:

- EncodedCommand flag creates finding.
- Office-spawned PowerShell is high severity.
- AI summary does not claim malware unless supporting evidence exists.

## UC-005: Impossible Travel And Password Spray

Actor: Identity security analyst

Trigger: Identity logs show anomalous authentication behavior.

Preconditions:

- Identity logs imported from Okta, Entra ID, AD, or generic CSV/JSON.
- GeoIP enrichment configured or source logs include location.

Telemetry:

- Successful login events.
- Failed login events.
- Source IP.
- User.
- Timestamp.
- App/client.
- MFA status where available.

Relevant skills:

- `detecting-anomalous-authentication-patterns`
- `detecting-service-account-abuse`
- `detecting-oauth-token-theft`
- `detecting-compromised-cloud-credentials`

System behavior:

1. Normalize auth events.
2. Build user baseline from available data.
3. Run impossible travel detector.
4. Run password spray detector.
5. Group related alerts by source IP, user set, app, and time window.
6. Open or update identity case.

AI behavior:

- Explain why pattern is anomalous.
- Separate impossible travel from VPN/proxy possibilities.
- Recommend validation steps: MFA result, device, user confirmation, source ASN, known travel, conditional access logs.

Automation policy:

- Enrich IP/ASN/GeoIP: allowed.
- Create case: allowed.
- Force password reset, revoke sessions, disable account: approval required.

Acceptance tests:

- Same user logging in from distant locations in impossible time window is flagged.
- Many users failing from one IP triggers spray alert.
- AI summary includes caveat for VPN or corporate proxy.

## UC-006: DNS Tunneling Candidate

Actor: Network defender

Trigger: Zeek DNS logs or Suricata EVE logs show suspicious DNS patterns.

Preconditions:

- DNS logs imported.
- Baseline window exists or static thresholds configured.

Telemetry:

- Zeek DNS.
- Suricata DNS/EVE.
- Optional firewall/proxy egress.

Relevant skills:

- `detecting-dns-exfiltration-with-dns-query-analysis`
- `detecting-command-and-control-over-dns`
- `detecting-exfiltration-over-dns-with-zeek`
- `hunting-for-dns-tunneling-with-zeek`

System behavior:

1. Group DNS queries by host, domain, and time window.
2. Calculate query volume, subdomain entropy, average query length, NXDOMAIN ratio, and unique subdomain count.
3. Compare to thresholds/baselines.
4. Correlate with endpoint and proxy logs if available.
5. Create DNS tunneling candidate alert.

AI behavior:

- Explain suspicious DNS metrics.
- Recommend validation: domain age, reputation, packet capture, endpoint process, egress volume.
- Avoid asserting exfiltration unless data volume and evidence support it.

Automation policy:

- Enrich domain: allowed.
- Search related events: allowed.
- Block domain: approval required.

Acceptance tests:

- High-entropy repeated subdomains trigger alert.
- Known CDN/domain allowlist reduces severity.
- Summary distinguishes "candidate" from confirmed exfiltration.

## UC-007: API Gateway Abuse Detection

Actor: Application security engineer

Trigger: API gateway logs show enumeration, 401 bursts, or suspicious object access.

Preconditions:

- API access logs imported.
- Logs include user/session, source IP, endpoint, status code, method, and resource ID where available.

Telemetry:

- API Gateway JSON.
- Kong/Nginx JSON.
- App auth logs where available.

Relevant skills:

- `analyzing-api-gateway-access-logs`
- `detecting-api-enumeration-attacks`
- `performing-api-rate-limiting-bypass`
- `testing-for-host-header-injection`

System behavior:

1. Normalize API logs.
2. Run enumeration detector by user/IP/resource ID.
3. Run credential scanning detector for 401/403 bursts.
4. Run unusual method detector.
5. Link to app/user context.

AI behavior:

- Explain likely BOLA/IDOR, credential scanning, or rate-limit bypass indicators.
- Recommend app-owner validation steps.
- Draft developer ticket with evidence.

Automation policy:

- Create case/ticket draft: allowed.
- Block source IP or change WAF policy: approval required.

Acceptance tests:

- Sequential ID access from one user triggers finding.
- 401 surge from one IP triggers finding.
- AI output includes endpoint and time window.

## UC-008: IOC Feed Ingestion And Matching

Actor: Threat intelligence analyst

Trigger: New STIX/TAXII or local IOC feed is imported.

Preconditions:

- IOC source configured.
- Local event store contains searchable fields.

Telemetry:

- STIX indicators.
- Domains, IPs, hashes, URLs, emails.
- TLP and confidence where available.

Relevant skills:

- `processing-stix-taxii-feeds`
- `automating-ioc-enrichment`
- `building-ioc-enrichment-pipeline-with-opencti`
- `building-threat-feed-aggregation-with-misp`

System behavior:

1. Validate feed format.
2. Normalize indicators.
3. Store source, confidence, TLP, first seen, expiration.
4. Match against local events.
5. Create alerts for high-confidence hits.
6. Avoid broad distribution of restricted TLP content.

AI behavior:

- Summarize matching indicators and source context.
- Recommend verification.
- Explain limitations of IOC-only matches.

Automation policy:

- Ingest feed: allowed if source configured.
- Match IOCs: allowed.
- Publish indicators externally: approval required.
- Block indicators: approval required.

Acceptance tests:

- TLP:RED indicators are marked restricted.
- Expired indicators do not generate new alerts unless configured.
- IOC hit case links source feed and matching local event.

## UC-009: Local Malware Triage

Actor: Incident responder

Trigger: Suspicious file hash or sample is attached to a case.

Preconditions:

- Local malware sandbox integration is configured, or hash-only mode is enabled.
- Safe sample handling policy accepted.

Telemetry:

- File hash.
- File path.
- Endpoint context.
- Optional sandbox report.

Relevant skills:

- `performing-automated-malware-analysis-with-cape`
- `extracting-iocs-from-malware-samples`
- `analyzing-malware-behavior-with-cuckoo-sandbox`
- `conducting-malware-incident-response`

System behavior:

1. Store sample metadata.
2. Hash file.
3. Submit to local sandbox only if configured and approved.
4. Parse sandbox report.
5. Extract network/file/registry/process IOCs.
6. Add findings to case.

AI behavior:

- Summarize behavior from sandbox evidence.
- Map observed behavior to ATT&CK.
- Recommend scoping searches.

Automation policy:

- Hash file: allowed.
- Submit to local sandbox: approval or policy-controlled.
- Upload sample to external service: prohibited by default.
- Quarantine/delete file: approval required.

Acceptance tests:

- File hash-only workflow works without sandbox.
- External upload is blocked unless explicitly configured.
- Sandbox-derived IOCs are linked to report evidence.

## UC-010: Analyst Opens A Hunt From A Skill

Actor: Threat hunter

Trigger: Analyst browses skill library and selects a skill.

Preconditions:

- Skill index exists.
- Required telemetry may or may not exist.

Telemetry:

- Depends on selected skill.

Relevant skills:

- Analyst-selected.

System behavior:

1. Display skill metadata and workflow.
2. Show telemetry prerequisites.
3. Compare prerequisites to available connectors.
4. Offer "Run hunt", "Create checklist", "Create detection backlog item", or "Open case".
5. If runnable detector exists, run it.
6. If not runnable, create advisory checklist.

AI behavior:

- Convert skill workflow into environment-specific plan.
- Identify missing data sources.
- Draft detection engineering backlog item.

Automation policy:

- Advisory output: allowed.
- Read-only hunt: allowed.
- Any write/containment: policy-controlled.

Acceptance tests:

- Missing prerequisites are clearly shown.
- Skill plan does not pretend unavailable telemetry exists.
- Lab-only skill displays explicit warning.

## UC-011: Server Mode Continuous Monitoring

Actor: Security engineer

Trigger: Admin deploys SentinelBlue on a Linux server.

Preconditions:

- Server package installed.
- Config file created.
- Database path and model endpoint configured.

Telemetry:

- Wazuh API.
- File tailers.
- Network log streams.
- Optional remote collectors.

Relevant skills:

- `performing-log-source-onboarding-in-siem`
- `building-soc-metrics-and-kpi-tracking`
- `implementing-alert-fatigue-reduction`

System behavior:

1. Start backend service under `systemd`.
2. Start or connect to `llama-server`.
3. Start connector workers.
4. Expose API and web UI.
5. Emit health and metrics.
6. Restart workers on failure.

AI behavior:

- Same as desktop mode, but model may be shared across analysts.
- Server admin can disable AI generation during maintenance.

Automation policy:

- Same backend policy engine.
- RBAC controls who can approve actions.

Acceptance tests:

- Service restarts on failure.
- Health endpoint reports connector/model/database status.
- Web UI works without Tauri.
- Server can run with model unavailable.

## UC-012: Approval-Gated Containment

Actor: Incident commander

Trigger: High-confidence case recommends containment.

Preconditions:

- Case has high-severity evidence.
- Connector supports action.
- Approver has permission.

Telemetry:

- Case evidence.
- Connector target inventory.

Relevant skills:

- `containing-active-breach`
- `building-incident-response-playbook`
- Domain-specific detection skill.

System behavior:

1. Model or detector proposes action.
2. Policy engine classifies action as containment.
3. App shows expected effect, target, evidence, risk, rollback, and approver requirement.
4. Approver approves or rejects.
5. Tool adapter executes only after approval.
6. App records result and updates case timeline.

AI behavior:

- Draft rationale and rollback notes.
- Cannot approve its own action.
- Cannot execute directly.

Automation policy:

- Human approval required.
- Optional two-person approval for destructive actions.

Acceptance tests:

- Action cannot execute without approval.
- Rejected action is logged.
- Executed action stores output and target state.
