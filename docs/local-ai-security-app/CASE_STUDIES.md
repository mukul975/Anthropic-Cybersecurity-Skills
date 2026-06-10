# SentinelBlue Case Studies

## Case Study 1: Startup With Wazuh And No Full-Time SOC

### Context

A 65-person SaaS startup has a small engineering team, one security-minded platform engineer, Wazuh deployed on servers, and API gateway logs from production. They cannot send raw security logs to external AI tools because logs may contain customer identifiers, session metadata, and internal hostnames.

### Deployment

- SentinelBlue desktop app on the platform engineer's workstation.
- Wazuh connector in read-only mode.
- Local `llama-server` running a workstation GGUF model.
- API gateway JSON logs imported nightly.
- Deterministic-only fallback enabled.

### Primary Workflows

- Triage Wazuh alerts.
- Detect suspicious PowerShell or Linux shell behavior.
- Detect API enumeration.
- Generate incident summaries for engineering handoff.
- Track missing telemetry.

### Example Incident

Wazuh flags suspicious command execution on an application server. SentinelBlue routes the alert to Wazuh endpoint detection and living-off-the-land skills. It pulls Wazuh agent context, correlates nearby process logs, and creates a case.

The model summary says:

- A suspicious shell command ran as the deploy user.
- Evidence is limited to one endpoint.
- No outbound network correlation is available because proxy logs are not onboarded.
- Recommended next steps are to validate deploy activity, inspect parent process, search related hosts, and review recent CI/CD jobs.

### Automation

Allowed:

- Query Wazuh alerts.
- Query local events.
- Create case.
- Draft Jira ticket.

Approval required:

- Disable deploy user.
- Isolate host.
- Block outbound destination.

### Outcome

The engineer confirms a compromised CI token created the command execution. SentinelBlue helps scope affected hosts and produces a short incident summary. The case also records a telemetry gap: CI/CD audit logs should be onboarded.

### Product Lessons

- MVP must work even when telemetry is incomplete.
- AI output must clearly label missing data.
- Startup users need practical remediation suggestions, not only ATT&CK mapping.

## Case Study 2: Consultant Running A Local Incident Response Kit

### Context

A security consultant investigates incidents for small clients. Client policy forbids uploading logs to external services. The consultant receives exported Windows Event Logs, Sysmon JSON, DNS logs, and a suspicious file hash.

### Deployment

- SentinelBlue desktop app on encrypted laptop.
- No network model calls.
- Local model file already installed.
- Imported evidence stored in per-client workspace.
- External uploads disabled.

### Primary Workflows

- Import evidence bundle.
- Run process injection and suspicious PowerShell hunts.
- Build timeline.
- Extract IOCs.
- Generate client report.

### Example Incident

The consultant imports Sysmon events. The process injection detector identifies `powershell.exe` opening `lsass.exe` with dangerous access rights. SentinelBlue creates a case, routes to process injection and credential dumping skills, and generates a timeline.

The model summarizes:

- Evidence supports possible credential access.
- Finding is high confidence because source process and target process are both suspicious for the observed access.
- Recommended next steps include checking logon events, searching for related PowerShell command lines, validating EDR quarantines, and identifying lateral movement.

### Automation

Allowed:

- Run local detectors.
- Build report.
- Extract hash/domain/IP indicators from imported logs.

Blocked by default:

- Upload sample to public sandbox.
- Publish IOCs to shared feed.
- Modify client systems.

### Outcome

The consultant delivers a report with evidence IDs, process graph, ATT&CK mapping, and remediation steps. No client telemetry leaves the laptop.

### Product Lessons

- Offline mode is a first-class requirement.
- Evidence export and report generation matter as much as live monitoring.
- Per-client workspace separation is important for consultants and MSSPs.

## Case Study 3: Homelab User Validating Detection Coverage

### Context

A homelab user wants to learn detection engineering and map their telemetry coverage to MITRE ATT&CK. They run Wazuh all-in-one, Zeek on a span port, and Suricata EVE logging.

### Deployment

- SentinelBlue desktop app on Linux workstation.
- Local `llama-server` with smaller GGUF fallback model.
- Wazuh, Zeek, and Suricata file tailers.
- Lab mode enabled.

### Primary Workflows

- Browse skills by ATT&CK technique.
- Run hunts against sample logs.
- Create detection backlog.
- Compare available telemetry to skill prerequisites.

### Example Exercise

The user selects `hunting-for-dns-tunneling-with-zeek`. SentinelBlue checks available logs and confirms DNS telemetry exists. It runs DNS tunneling detector and displays benign lab findings. The AI generates a detection tuning note explaining thresholds and false positives.

### Automation

Allowed:

- Run read-only hunts.
- Generate Sigma draft.
- Create lab notes.

Lab-only:

- Red-team skill browsing.
- Attack simulation checklist generation.

### Outcome

The user learns that Zeek DNS is available but endpoint process-to-network correlation is missing. SentinelBlue creates a backlog item to add osquery or Sysmon endpoint telemetry.

### Product Lessons

- Lab mode is useful but must be visually and technically separated from production mode.
- The skill library is valuable for education and coverage planning, not only live incidents.

## Case Study 4: Small Enterprise Server Deployment

### Context

A 450-person company has one security engineer and a helpdesk team. They want SentinelBlue to run continuously on a private server and let analysts access a web UI. They already run Wazuh and want local AI summaries for common alerts.

### Deployment

- SentinelBlue server installed on Ubuntu with `systemd`.
- External `llama-server` running on a GPU server.
- PostgreSQL optional upgrade from SQLite.
- Web UI behind reverse proxy with TLS.
- OIDC authentication.
- Wazuh connector with read-only service account.
- Prometheus metrics enabled.

### Primary Workflows

- Continuous Wazuh alert ingestion.
- Case creation and assignment.
- AI summaries for high/critical alerts.
- Approval-gated containment recommendations.
- Weekly coverage report.

### Example Incident

Multiple failed logins from one IP across 28 users trigger password spray detector. SentinelBlue groups alerts into one identity case, routes to anomalous authentication skills, enriches source IP, and recommends blocking the source and forcing password resets for affected accounts.

### Automation

Allowed:

- Create case.
- Enrich IP.
- Notify Slack/email/webhook if configured.

Approval required:

- Block IP at firewall.
- Force password reset.
- Revoke sessions.

### Outcome

Helpdesk validates affected users and an incident commander approves blocking the IP. SentinelBlue records approvals, action output, and post-incident notes.

### Product Lessons

- Server mode must support RBAC and approval workflows.
- Audit logs are not optional.
- AI should be useful to helpdesk users without making final response decisions.

## Case Study 5: API Security Monitoring For A Product Team

### Context

A product security engineer wants to monitor API gateway logs for broken object level authorization, credential scanning, and rate-limit bypass patterns. They do not have enterprise SIEM access for application logs.

### Deployment

- SentinelBlue desktop app in deterministic-only mode.
- API gateway JSON exports imported daily.
- Local model enabled only for report drafting.

### Primary Workflows

- Detect unusual resource ID enumeration.
- Detect 401/403 surges.
- Identify unusual methods.
- Draft developer tickets with evidence.

### Example Incident

One authenticated user requests 1,200 sequential resource IDs from the same endpoint. SentinelBlue flags BOLA/IDOR candidate behavior and routes to API gateway access log analysis.

The model drafts:

- A concise engineering ticket.
- Evidence window.
- Affected endpoint.
- User/session/source IP.
- Suggested validation: authorization check on object ownership, rate-limit behavior, audit of adjacent resource IDs.

### Automation

Allowed:

- Create draft ticket.
- Export CSV of evidence.

Approval required:

- Block account.
- Change WAF policy.
- Apply rate-limit rule.

### Outcome

The product team confirms an authorization bug in a beta endpoint and ships a fix.

### Product Lessons

- Security monitoring is not limited to SOC telemetry.
- AppSec teams need workflow-specific evidence packs.
- Draft tickets should be concrete and developer-friendly.

## Case Study 6: Air-Gapped Industrial Environment

### Context

An OT/ICS team monitors a segmented environment. Internet access is unavailable. They can export logs from Windows systems, network sensors, and historian servers. They need all analysis local and auditable.

### Deployment

- SentinelBlue server mode on isolated Linux host.
- Model imported from offline media.
- Skills repository vendored with release checksum.
- No external feed ingestion.
- Updates via signed offline bundle.

### Primary Workflows

- Import logs from removable media.
- Detect unusual authentication.
- Detect suspicious network patterns.
- Use OT/ICS skills in advisory mode.
- Generate incident report.

### Example Incident

The team imports logs showing unusual Modbus command patterns and anomalous Windows authentication on an engineering workstation. SentinelBlue routes to OT/ICS detection skills, flags missing packet context, and creates an investigation checklist.

### Automation

Allowed:

- Local analysis.
- Case creation.
- Report generation.

Blocked:

- External enrichment.
- External model calls.
- Automatic containment.

### Outcome

The team uses the report to guide manual containment under existing OT change-control policy.

### Product Lessons

- Offline model import and signed offline updates are required for sensitive environments.
- Advisory mode is valuable when direct integrations are restricted.
- The UI must make data egress state obvious.

## Case Study 7: MSSP Pilot With Multiple Small Customers

### Context

An MSSP supports five small customers. Each customer has separate Wazuh deployments and different telemetry quality. The MSSP wants one server instance with tenant separation.

### Deployment

- SentinelBlue server mode.
- Tenant-aware connectors.
- Role-based access.
- One external model runtime shared across tenants.
- Tenant-specific encryption keys planned.

### Primary Workflows

- Customer-specific alert queues.
- Cross-tenant detector templates.
- Tenant-isolated cases.
- Weekly security summary per customer.

### Example Incident

Customer A and Customer C both see suspicious DNS beaconing. SentinelBlue creates separate tenant cases and prevents evidence mixing. The analyst sees a reusable detector tuning recommendation, but report content remains tenant-specific.

### Automation

Allowed:

- Tenant-local case creation.
- Tenant-local enrichment.

Approval required:

- Any tenant action.
- Cross-tenant analytics export.

### Outcome

The MSSP validates that SentinelBlue can reduce triage time without violating customer boundaries.

### Product Lessons

- Multi-tenant mode is not MVP, but architecture should avoid assumptions that block it.
- Shared model runtime must not leak prompts between tenants.
- Tenant IDs must be part of every event, case, action, and audit row in MSSP mode.
