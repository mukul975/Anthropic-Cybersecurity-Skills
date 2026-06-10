use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
};

use sentinel_api::{
    ALERTS_ROUTE, AlertSummary, ApiError, CASES_ROUTE, CaseSummary, CaseTimelineSummary,
    EVENTS_ROUTE, EventSummary, HEALTH_ROUTE, ListResponse, SKILLS_ROUTE, SkillSummary,
    bootstrap_health_response,
};
use sentinel_core::{ComponentHealth, DEFAULT_API_BIND_ADDR, HealthSnapshot};
use sentinel_db::{CORE_TABLES, Database, NewModelRun, StoredCase};
use sentinel_detect::{DetectionReport, run_default_detectors};
use sentinel_ingest::{ImportFormat, ImportOptions, ImportReport, import_file};
use sentinel_model::{
    CaseSummaryResult, ModelHealthStatus, ModelRuntimeConfig, check_model_health, summarize_case,
};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub version: String,
    pub database_path: Option<PathBuf>,
    pub model: ModelRuntimeConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: DEFAULT_API_BIND_ADDR.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            database_path: None,
            model: ModelRuntimeConfig::deterministic_only(),
        }
    }
}

impl ServerConfig {
    pub fn with_database_path(mut self, database_path: impl Into<PathBuf>) -> Self {
        self.database_path = Some(database_path.into());
        self
    }
}

pub fn health_snapshot(config: &ServerConfig) -> HealthSnapshot {
    let mut snapshot = bootstrap_health_response(&config.version);
    snapshot.components.push(database_health_component(config));
    snapshot.components.push(model_health_component(config));
    snapshot
}

pub fn health_json(config: &ServerConfig) -> String {
    let snapshot = health_snapshot(config);
    let healthy = snapshot.is_healthy();
    let components = snapshot
        .components
        .iter()
        .map(|component| {
            format!(
                "{{\"name\":\"{}\",\"status\":\"{}\",\"detail\":\"{}\"}}",
                escape_json(&component.name),
                component.status.as_str(),
                escape_json(&component.detail)
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    format!(
        "{{\"product\":\"{}\",\"version\":\"{}\",\"healthy\":{},\"bind_addr\":\"{}\",\"components\":[{}]}}",
        escape_json(&snapshot.product),
        escape_json(&snapshot.version),
        healthy,
        escape_json(&config.bind_addr),
        components
    )
}

fn database_health_component(config: &ServerConfig) -> ComponentHealth {
    let database = match &config.database_path {
        Some(path) => Database::open_initialized(path),
        None => Database::open_initialized_memory(),
    };

    match database.and_then(|database| database.health()) {
        Ok(health) if health.core_table_count == CORE_TABLES.len() => ComponentHealth::healthy(
            "database",
            format!(
                "schema_version={} applied_migrations={} core_tables={}",
                health.schema_version, health.applied_migrations, health.core_table_count
            ),
        ),
        Ok(health) => ComponentHealth::degraded(
            "database",
            format!(
                "schema_version={} applied_migrations={} core_tables={}/{}",
                health.schema_version,
                health.applied_migrations,
                health.core_table_count,
                CORE_TABLES.len()
            ),
        ),
        Err(error) => ComponentHealth::unavailable("database", error.to_string()),
    }
}

fn model_health_component(config: &ServerConfig) -> ComponentHealth {
    let health = check_model_health(&config.model);
    let detail = format!(
        "model_status={} ai_enabled={} {}",
        health.status.as_str(),
        health.ai_enabled,
        health.detail
    );
    match health.status {
        ModelHealthStatus::Ready | ModelHealthStatus::Disabled => {
            ComponentHealth::healthy("model", detail)
        }
        ModelHealthStatus::Loading | ModelHealthStatus::Degraded => {
            ComponentHealth::degraded("model", detail)
        }
        ModelHealthStatus::Unavailable => ComponentHealth::unavailable("model", detail),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status_code: u16,
    pub content_type: &'static str,
    pub body: String,
}

impl HttpResponse {
    pub fn json(status_code: u16, body: impl Into<String>) -> Self {
        Self {
            status_code,
            content_type: "application/json; charset=utf-8",
            body: body.into(),
        }
    }

    pub fn status_text(&self) -> &'static str {
        match self.status_code {
            200 => "OK",
            404 => "Not Found",
            405 => "Method Not Allowed",
            500 => "Internal Server Error",
            _ => "OK",
        }
    }

    pub fn to_http_bytes(&self) -> Vec<u8> {
        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.status_code,
            self.status_text(),
            self.content_type,
            self.body.len(),
            self.body
        );
        response.into_bytes()
    }
}

pub fn route_get(path: &str, config: &ServerConfig) -> HttpResponse {
    let (path, query) = split_path_query(path);
    match path {
        HEALTH_ROUTE => HttpResponse::json(200, health_json(config)),
        SKILLS_ROUTE => db_json_response(config, |database| {
            let q = query_value(query, "q");
            let skills = match q.as_deref() {
                Some(query) if !query.trim().is_empty() => database.search_skills(query, 100)?,
                _ => database.list_skills(100)?,
            };
            let items = skills
                .into_iter()
                .map(|skill| SkillSummary {
                    id: skill.id.to_string(),
                    name: skill.name,
                    path: skill.path,
                    domain: skill.domain,
                    subdomain: skill.subdomain,
                })
                .collect::<Vec<_>>();
            Ok(serde_json::to_string(&ListResponse {
                total: items.len(),
                items,
            })
            .expect("skills response serializes"))
        }),
        EVENTS_ROUTE => db_json_response(config, |database| {
            let events = database.list_events(100)?;
            let items = events
                .into_iter()
                .map(|event| EventSummary {
                    id: event.id.to_string(),
                    source_product: event.source_product,
                    event_time: event.event_time,
                    event_type: event.event_type,
                    host: event.host,
                    user_name: event.user_name,
                    src_ip: event.src_ip,
                    dest_ip: event.dest_ip,
                    process_name: event.process_name,
                    url: event.url,
                    dns_query: event.dns_query,
                    severity: event.severity,
                    action: event.action,
                })
                .collect::<Vec<_>>();
            Ok(serde_json::to_string(&ListResponse {
                total: items.len(),
                items,
            })
            .expect("events response serializes"))
        }),
        ALERTS_ROUTE => db_json_response(config, |database| {
            let alerts = database.list_alerts(100)?;
            let items = alerts
                .into_iter()
                .map(|alert| AlertSummary {
                    id: alert.id.to_string(),
                    title: alert.title,
                    description: alert.description,
                    severity: alert.severity,
                    confidence: alert.confidence,
                    status: alert.status,
                    attack_json: alert.attack_json,
                    evidence_json: alert.evidence_json,
                })
                .collect::<Vec<_>>();
            Ok(serde_json::to_string(&ListResponse {
                total: items.len(),
                items,
            })
            .expect("alerts response serializes"))
        }),
        CASES_ROUTE => db_json_response(config, |database| {
            let cases = database.list_cases(100)?;
            let items = cases
                .into_iter()
                .map(|case| CaseSummary {
                    id: case.id.to_string(),
                    title: case.title,
                    status: case.status,
                    severity: case.severity,
                    confidence: case.confidence,
                    disposition: case.disposition,
                    closed_at: case.closed_at,
                })
                .collect::<Vec<_>>();
            Ok(serde_json::to_string(&ListResponse {
                total: items.len(),
                items,
            })
            .expect("cases response serializes"))
        }),
        path if case_timeline_id(path).is_some() => db_json_response(config, |database| {
            let case_id = case_timeline_id(path).expect("checked above");
            let timeline = database.case_timeline(case_id)?;
            let items = timeline
                .into_iter()
                .map(|item| CaseTimelineSummary {
                    item_type: item.item_type,
                    item_id: item.item_id.to_string(),
                    case_id: item.case_id.to_string(),
                    alert_id: item.alert_id.map(|id| id.to_string()),
                    raw_event_id: item.raw_event_id.map(|id| id.to_string()),
                    normalized_event_id: item.normalized_event_id.map(|id| id.to_string()),
                    summary: item.summary,
                    timeline_time: item.timeline_time,
                })
                .collect::<Vec<_>>();
            Ok(serde_json::to_string(&ListResponse {
                total: items.len(),
                items,
            })
            .expect("case timeline response serializes"))
        }),
        _ => HttpResponse::json(
            404,
            ApiError::new("not_found", format!("No route for GET {path}")).to_json(),
        ),
    }
}

fn db_json_response(
    config: &ServerConfig,
    build: impl FnOnce(Database) -> Result<String, rusqlite::Error>,
) -> HttpResponse {
    match open_request_database(config).and_then(build) {
        Ok(body) => HttpResponse::json(200, body),
        Err(error) => HttpResponse::json(
            500,
            ApiError::new("database_error", error.to_string()).to_json(),
        ),
    }
}

fn open_request_database(config: &ServerConfig) -> Result<Database, rusqlite::Error> {
    match &config.database_path {
        Some(path) => Database::open_initialized(path),
        None => Database::open_initialized_memory(),
    }
}

pub fn route_request(method: &str, path: &str, config: &ServerConfig) -> HttpResponse {
    match method {
        "GET" => route_get(path, config),
        _ => HttpResponse::json(
            405,
            ApiError::new(
                "method_not_allowed",
                format!("Method {method} is not allowed"),
            )
            .to_json(),
        ),
    }
}

pub fn start_http_server(config: &ServerConfig) -> std::io::Result<()> {
    let listener = TcpListener::bind(&config.bind_addr)?;
    for stream in listener.incoming() {
        handle_connection(stream?, config)?;
    }
    Ok(())
}

pub fn import_file_for_server(
    config: &ServerConfig,
    path: impl Into<PathBuf>,
    source_name: impl Into<String>,
    source_product: impl Into<String>,
    format: ImportFormat,
) -> Result<ImportReport, String> {
    let database = open_request_database(config).map_err(|error| error.to_string())?;
    let source_product = source_product.into();
    let mut options = if source_product.eq_ignore_ascii_case("wazuh") {
        ImportOptions::wazuh_file(source_name)
    } else {
        ImportOptions::generic_file(source_name, source_product)
    };
    options.format = format;

    import_file(&database, path.into(), &options).map_err(|error| error.to_string())
}

pub fn import_report_json(report: &ImportReport) -> String {
    #[derive(Serialize)]
    struct Report<'a> {
        source_id: i64,
        batch_id: &'a str,
        scanned: usize,
        imported: usize,
        skipped: usize,
        failed: usize,
        normalized: usize,
        errors: Vec<ErrorRecord<'a>>,
    }

    #[derive(Serialize)]
    struct ErrorRecord<'a> {
        line: Option<usize>,
        message: &'a str,
    }

    let report = Report {
        source_id: report.source_id,
        batch_id: &report.batch_id,
        scanned: report.scanned,
        imported: report.imported,
        skipped: report.skipped,
        failed: report.failed,
        normalized: report.normalized,
        errors: report
            .errors
            .iter()
            .map(|error| ErrorRecord {
                line: error.line,
                message: &error.message,
            })
            .collect(),
    };

    serde_json::to_string(&report).expect("import report serializes")
}

pub fn run_detectors_for_server(config: &ServerConfig) -> Result<Vec<DetectionReport>, String> {
    let database = open_request_database(config).map_err(|error| error.to_string())?;
    run_default_detectors(&database).map_err(|error| error.to_string())
}

pub fn detection_reports_json(reports: &[DetectionReport]) -> String {
    serde_json::to_string(reports).expect("detection reports serialize")
}

pub fn promote_alert_for_server(
    config: &ServerConfig,
    alert_id: i64,
    title: Option<&str>,
) -> Result<StoredCase, String> {
    let database = open_request_database(config).map_err(|error| error.to_string())?;
    let case_id = database
        .promote_alert_to_case(alert_id, title)
        .map_err(|error| error.to_string())?;
    database
        .case_by_id(case_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("case {case_id} not found after promotion"))
}

pub fn close_case_for_server(
    config: &ServerConfig,
    case_id: i64,
    disposition: &str,
    notes: &str,
) -> Result<StoredCase, String> {
    let database = open_request_database(config).map_err(|error| error.to_string())?;
    database
        .close_case(case_id, disposition, notes)
        .map_err(|error| error.to_string())?;
    database
        .case_by_id(case_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("case {case_id} not found after close"))
}

pub fn case_json(case: &StoredCase) -> String {
    #[derive(Serialize)]
    struct Case<'a> {
        id: i64,
        title: &'a str,
        status: &'a str,
        severity: &'a str,
        confidence: &'a str,
        disposition: &'a str,
        closed_at: Option<&'a str>,
    }

    serde_json::to_string(&Case {
        id: case.id,
        title: &case.title,
        status: &case.status,
        severity: &case.severity,
        confidence: &case.confidence,
        disposition: &case.disposition,
        closed_at: case.closed_at.as_deref(),
    })
    .expect("case serializes")
}

pub fn summarize_case_for_server(
    config: &ServerConfig,
    case_id: i64,
) -> Result<CaseSummaryResult, String> {
    let database = open_request_database(config).map_err(|error| error.to_string())?;
    let case = database
        .case_by_id(case_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("case {case_id} not found"))?;
    let timeline = database
        .case_timeline(case_id)
        .map_err(|error| error.to_string())?;
    let result =
        summarize_case(&config.model, &case, &timeline).map_err(|error| error.to_string())?;
    let output_json = serde_json::to_string(&result).map_err(|error| error.to_string())?;
    database
        .insert_model_run(NewModelRun {
            case_id: Some(case_id),
            model_name: &result.model_name,
            prompt_hash: &result.prompt_hash,
            output_json: &output_json,
            status: "completed",
        })
        .map_err(|error| error.to_string())?;
    Ok(result)
}

pub fn case_summary_json(result: &CaseSummaryResult) -> String {
    serde_json::to_string(result).expect("case summary serializes")
}

fn handle_connection(mut stream: TcpStream, config: &ServerConfig) -> std::io::Result<()> {
    let mut buffer = [0_u8; 8192];
    let read = stream.read(&mut buffer)?;
    let request = String::from_utf8_lossy(&buffer[..read]);
    let response = match parse_request_line(&request) {
        Some((method, path)) => route_request(method, path, config),
        None => HttpResponse::json(
            500,
            ApiError::new("bad_request", "Could not parse request line").to_json(),
        ),
    };

    stream.write_all(&response.to_http_bytes())
}

fn parse_request_line(request: &str) -> Option<(&str, &str)> {
    let line = request.lines().next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    Some((method, path))
}

fn split_path_query(path: &str) -> (&str, Option<&str>) {
    match path.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path, None),
    }
}

fn query_value(query: Option<&str>, key: &str) -> Option<String> {
    query?
        .split('&')
        .filter_map(|part| part.split_once('='))
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, value)| value.replace('+', " "))
}

fn case_timeline_id(path: &str) -> Option<i64> {
    let suffix = path.strip_prefix("/api/cases/")?;
    let id = suffix.strip_suffix("/timeline")?;
    id.parse::<i64>().ok()
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_db::{NewAlert, NewEvidence, NewNormalizedEvent, NewRawEvent, NewSkill};

    #[test]
    fn default_config_uses_local_bind_addr() {
        let config = ServerConfig::default();

        assert_eq!(config.bind_addr, DEFAULT_API_BIND_ADDR);
    }

    #[test]
    fn health_json_contains_product_and_bind_addr() {
        let config = ServerConfig::default();
        let json = health_json(&config);

        assert!(json.contains("\"product\":\"SentinelBlue\""));
        assert!(json.contains("\"healthy\":true"));
        assert!(json.contains(DEFAULT_API_BIND_ADDR));
    }

    #[test]
    fn health_snapshot_includes_database_component() {
        let config = ServerConfig::default();
        let snapshot = health_snapshot(&config);

        assert!(snapshot.components.iter().any(|component| {
            component.name == "database" && component.status.as_str() == "healthy"
        }));
    }

    #[test]
    fn health_json_reports_database_status() {
        let config = ServerConfig::default();
        let json = health_json(&config);

        assert!(json.contains("\"name\":\"database\""));
        assert!(json.contains("schema_version=4"));
        assert!(json.contains("core_tables=12"));
        assert!(json.contains("\"name\":\"model\""));
        assert!(json.contains("model_status=disabled"));
    }

    #[test]
    fn get_health_route_returns_json_200() {
        let config = ServerConfig::default();
        let response = route_get("/api/health", &config);

        assert_eq!(response.status_code, 200);
        assert_eq!(response.content_type, "application/json; charset=utf-8");
        assert!(response.body.contains("\"product\":\"SentinelBlue\""));
    }

    #[test]
    fn unknown_get_route_returns_not_found() {
        let config = ServerConfig::default();
        let response = route_get("/api/missing", &config);

        assert_eq!(response.status_code, 404);
        assert!(response.body.contains("\"code\":\"not_found\""));
    }

    #[test]
    fn unsupported_method_returns_405() {
        let config = ServerConfig::default();
        let response = route_request("POST", "/api/health", &config);

        assert_eq!(response.status_code, 405);
        assert!(response.body.contains("\"code\":\"method_not_allowed\""));
    }

    #[test]
    fn db_backed_skills_route_returns_search_results() {
        let dir = tempfile::tempdir().expect("tempdir exists");
        let db_path = dir.path().join("sentinelblue.db");
        let database = Database::open_initialized(&db_path).expect("database initializes");
        let tags = vec!["network-security".to_string()];
        database
            .upsert_skill(NewSkill {
                name: "analyzing-network-traffic",
                path: "skills/analyzing-network-traffic",
                description: "Analyze packet traffic",
                domain: "cybersecurity",
                subdomain: "network-security",
                tags: &tags,
                license: "Apache-2.0",
                version: "1.0",
                author: "tester",
                checksum: "checksum-a",
                mitre_attack: &[],
                nist_csf: &[],
                mitre_atlas: &[],
                d3fend: &[],
                nist_ai_rmf: &[],
            })
            .expect("skill indexes");
        drop(database);

        let config = ServerConfig::default().with_database_path(&db_path);
        let response = route_get("/api/skills?q=packet", &config);

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"total\":1"));
        assert!(response.body.contains("analyzing-network-traffic"));
    }

    #[test]
    fn db_backed_event_alert_and_case_routes_return_lists() {
        let dir = tempfile::tempdir().expect("tempdir exists");
        let db_path = dir.path().join("sentinelblue.db");
        let database = Database::open_initialized(&db_path).expect("database initializes");
        let conn = database.connection();
        conn.execute(
            "INSERT INTO normalized_events (event_type, source_product, event_time)
             VALUES ('dns', 'zeek', '2026-06-09T12:00:00Z')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO alerts (title, severity, confidence, status)
             VALUES ('DNS beacon candidate', 'medium', 0.62, 'new')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cases (title, status, severity)
             VALUES ('Suspicious DNS activity', 'triage', 'medium')",
            [],
        )
        .unwrap();
        drop(database);

        let config = ServerConfig::default().with_database_path(&db_path);
        let events = route_get("/api/events", &config);
        let alerts = route_get("/api/alerts", &config);
        let cases = route_get("/api/cases", &config);

        assert_eq!(events.status_code, 200);
        assert!(events.body.contains("\"source_product\":\"zeek\""));
        assert_eq!(alerts.status_code, 200);
        assert!(alerts.body.contains("\"title\":\"DNS beacon candidate\""));
        assert_eq!(cases.status_code, 200);
        assert!(cases.body.contains("\"title\":\"Suspicious DNS activity\""));
    }

    #[test]
    fn server_import_file_command_imports_raw_events() {
        let dir = tempfile::tempdir().expect("tempdir exists");
        let db_path = dir.path().join("sentinelblue.db");
        let import_path = dir.path().join("events.jsonl");
        std::fs::write(
            &import_path,
            "{\"timestamp\":\"2026-06-09T12:00:00Z\",\"event\":\"one\"}\n",
        )
        .expect("fixture writes");
        let config = ServerConfig::default().with_database_path(&db_path);

        let report = import_file_for_server(
            &config,
            &import_path,
            "server-import",
            "custom",
            ImportFormat::Jsonl,
        )
        .expect("server import succeeds");

        assert_eq!(report.imported, 1);
        assert_eq!(report.skipped, 0);
        assert!(import_report_json(&report).contains("\"imported\":1"));
        let database = Database::open_initialized(&db_path).expect("database reopens");
        assert_eq!(database.raw_event_count().unwrap(), 1);
    }

    #[test]
    fn server_run_detectors_creates_alerts_and_evidence() {
        let dir = tempfile::tempdir().expect("tempdir exists");
        let db_path = dir.path().join("sentinelblue.db");
        let database = Database::open_initialized(&db_path).expect("database initializes");
        let raw_event_id = database
            .insert_raw_event(NewRawEvent {
                source_id: None,
                source_product: "sysmon",
                event_time: Some("2026-06-10T01:00:00Z"),
                raw_payload: "{}",
                raw_hash: "server-detector-hash",
                ingest_batch: "server-detector-batch",
            })
            .expect("raw event inserts");
        database
            .insert_normalized_event(NewNormalizedEvent {
                raw_event_id: Some(raw_event_id),
                event_time: Some("2026-06-10T01:00:00Z"),
                event_type: "process_start",
                source_product: "sysmon",
                host: "win-host-01",
                asset_id: "asset-win-01",
                user_name: "ACME\\alice",
                user_id: "",
                src_ip: "",
                src_port: None,
                dest_ip: "",
                dest_port: None,
                protocol: "",
                dns_query: "",
                http_method: "",
                url: "",
                status_code: None,
                process_name: "powershell.exe",
                process_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                parent_process_name: "explorer.exe",
                command_line: "powershell.exe -EncodedCommand redacted",
                file_path: "",
                file_hash_sha256: "",
                rule_id: "sysmon-1",
                rule_name: "process_start",
                severity: "info",
                action: "",
                fields_json: "{}",
            })
            .expect("normalized event inserts");
        drop(database);

        let config = ServerConfig::default().with_database_path(&db_path);
        let reports = run_detectors_for_server(&config).expect("detectors run");
        let json = detection_reports_json(&reports);
        let alerts = route_get("/api/alerts", &config);
        let database = Database::open_initialized(&db_path).expect("database reopens");
        let alert_rows = database.list_alerts(10).expect("alerts list");
        let evidence = database
            .evidence_for_alert(alert_rows[0].id)
            .expect("evidence list");

        assert_eq!(reports.len(), 8);
        assert_eq!(
            reports
                .iter()
                .map(|report| report.findings.len())
                .sum::<usize>(),
            1
        );
        assert_eq!(
            reports
                .iter()
                .map(|report| report.alerts_created)
                .sum::<usize>(),
            1
        );
        assert!(json.contains("sentinelblue.detector.powershell_encoded_command"));
        assert_eq!(alerts.status_code, 200);
        assert!(
            alerts
                .body
                .contains("Suspicious PowerShell encoded command")
        );
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].raw_event_id, Some(raw_event_id));
    }

    #[test]
    fn server_promotes_alert_closes_case_and_reads_timeline() {
        let dir = tempfile::tempdir().expect("tempdir exists");
        let db_path = dir.path().join("sentinelblue.db");
        let database = Database::open_initialized(&db_path).expect("database initializes");
        let raw_event_id = database
            .insert_raw_event(NewRawEvent {
                source_id: None,
                source_product: "wazuh",
                event_time: Some("2026-06-10T01:00:00Z"),
                raw_payload: "{}",
                raw_hash: "server-case-hash",
                ingest_batch: "server-case-batch",
            })
            .expect("raw event inserts");
        let normalized_event_id = database
            .insert_normalized_event(NewNormalizedEvent {
                raw_event_id: Some(raw_event_id),
                event_time: Some("2026-06-10T01:00:00Z"),
                event_type: "alert",
                source_product: "wazuh",
                host: "demo-host",
                asset_id: "001",
                user_name: "deploy",
                user_id: "",
                src_ip: "10.0.0.5",
                src_port: None,
                dest_ip: "",
                dest_port: None,
                protocol: "",
                dns_query: "",
                http_method: "",
                url: "",
                status_code: None,
                process_name: "powershell.exe",
                process_path: "",
                parent_process_name: "",
                command_line: "powershell.exe -EncodedCommand redacted",
                file_path: "",
                file_hash_sha256: "",
                rule_id: "100001",
                rule_name: "Suspicious command execution",
                severity: "8",
                action: "",
                fields_json: "{}",
            })
            .expect("normalized event inserts");
        let alert_id = database
            .insert_alert(NewAlert {
                detector_run_id: None,
                title: "Suspicious PowerShell encoded command",
                description: "PowerShell execution used an encoded command indicator.",
                severity: "high",
                confidence: 0.86,
                status: "new",
                attack_json: r#"[{"technique_id":"T1059.001"}]"#,
                evidence_json: "[]",
            })
            .expect("alert inserts");
        database
            .insert_evidence(NewEvidence {
                case_id: None,
                alert_id: Some(alert_id),
                raw_event_id: Some(raw_event_id),
                normalized_event_id: Some(normalized_event_id),
                evidence_type: "normalized_event",
                summary: "Encoded PowerShell evidence",
            })
            .expect("evidence inserts");
        drop(database);

        let config = ServerConfig::default().with_database_path(&db_path);
        let case = promote_alert_for_server(&config, alert_id, None).expect("alert promotes");
        let timeline = route_get(&format!("/api/cases/{}/timeline", case.id), &config);
        let closed = close_case_for_server(
            &config,
            case.id,
            "benign",
            "Confirmed approved administration.",
        )
        .expect("case closes");
        let close_json = case_json(&closed);
        let cases = route_get("/api/cases", &config);

        assert_eq!(case.status, "triage");
        assert_eq!(case.severity, "high");
        assert_eq!(timeline.status_code, 200);
        assert!(timeline.body.contains("\"item_type\":\"normalized_event\""));
        assert!(timeline.body.contains("\"item_type\":\"detector_alert\""));
        assert_eq!(closed.status, "closed");
        assert!(closed.closed_at.is_some());
        assert!(close_json.contains("\"disposition\":\"benign\""));
        assert_eq!(cases.status_code, 200);
        assert!(cases.body.contains("\"status\":\"closed\""));
        assert!(cases.body.contains("\"disposition\":\"benign\""));
    }

    #[test]
    fn server_summarizes_case_deterministically_and_persists_model_run() {
        let dir = tempfile::tempdir().expect("tempdir exists");
        let db_path = dir.path().join("sentinelblue.db");
        let database = Database::open_initialized(&db_path).expect("database initializes");
        let case_id = database
            .create_case(sentinel_db::NewCase {
                title: "Suspicious PowerShell encoded command",
                status: "triage",
                severity: "high",
                confidence: "0.86",
                disposition: "",
            })
            .expect("case creates");
        let raw_event_id = database
            .insert_raw_event(NewRawEvent {
                source_id: None,
                source_product: "wazuh",
                event_time: Some("2026-06-10T01:00:00Z"),
                raw_payload: "{}",
                raw_hash: "server-summary-hash",
                ingest_batch: "server-summary-batch",
            })
            .expect("raw event inserts");
        let normalized_event_id = database
            .insert_normalized_event(NewNormalizedEvent {
                raw_event_id: Some(raw_event_id),
                event_time: Some("2026-06-10T01:00:00Z"),
                event_type: "alert",
                source_product: "wazuh",
                host: "demo-host",
                asset_id: "001",
                user_name: "deploy",
                user_id: "",
                src_ip: "10.0.0.5",
                src_port: None,
                dest_ip: "",
                dest_port: None,
                protocol: "",
                dns_query: "",
                http_method: "",
                url: "",
                status_code: None,
                process_name: "powershell.exe",
                process_path: "",
                parent_process_name: "",
                command_line: "powershell.exe -EncodedCommand redacted",
                file_path: "",
                file_hash_sha256: "",
                rule_id: "100001",
                rule_name: "Suspicious command execution",
                severity: "8",
                action: "",
                fields_json: "{}",
            })
            .expect("normalized event inserts");
        let evidence_id = database
            .insert_evidence(NewEvidence {
                case_id: Some(case_id),
                alert_id: None,
                raw_event_id: Some(raw_event_id),
                normalized_event_id: Some(normalized_event_id),
                evidence_type: "normalized_event",
                summary: "Encoded command observed with api_key=sk-secret",
            })
            .expect("evidence inserts");
        drop(database);

        let config = ServerConfig::default().with_database_path(&db_path);
        let summary = summarize_case_for_server(&config, case_id).expect("summary generates");
        let summary_json = case_summary_json(&summary);
        let database = Database::open_initialized(&db_path).expect("database reopens");
        let model_runs = database
            .model_runs_for_case(case_id)
            .expect("model runs list");
        let timeline = database.case_timeline(case_id).expect("timeline loads");

        assert!(!summary.ai_attempted);
        assert_eq!(summary.model_health_status, "disabled");
        assert!(summary.summary.contains(&format!("#{evidence_id}")));
        assert!(summary.prompt.redaction_count >= 1);
        assert!(!summary.prompt.user.contains("sk-secret"));
        assert!(
            summary
                .claims
                .iter()
                .all(|claim| claim.inference || !claim.evidence_ids.is_empty())
        );
        assert!(summary_json.contains("deterministic-only"));
        assert_eq!(model_runs.len(), 1);
        assert_eq!(model_runs[0].prompt_hash, summary.prompt_hash);
        assert!(
            timeline
                .iter()
                .any(|item| item.item_type == "model_summary")
        );
    }

    #[test]
    fn unavailable_model_endpoint_disables_ai_summary_generation() {
        let dir = tempfile::tempdir().expect("tempdir exists");
        let db_path = dir.path().join("sentinelblue.db");
        let database = Database::open_initialized(&db_path).expect("database initializes");
        let case_id = database
            .create_case(sentinel_db::NewCase {
                title: "Suspicious DNS activity",
                status: "triage",
                severity: "medium",
                confidence: "0.70",
                disposition: "",
            })
            .expect("case creates");
        drop(database);

        let mut config = ServerConfig::default().with_database_path(&db_path);
        config.model = ModelRuntimeConfig::openai_compatible("http://127.0.0.1:1", "local-model");
        config.model.request_timeout_ms = 100;
        let summary = summarize_case_for_server(&config, case_id).expect("summary generates");

        assert!(!summary.ai_attempted);
        assert_eq!(summary.model_health_status, "unavailable");
        assert_eq!(summary.mode, "deterministic-only");
        assert!(
            summary
                .claims
                .iter()
                .all(|claim| claim.inference || !claim.evidence_ids.is_empty())
        );
    }
}
