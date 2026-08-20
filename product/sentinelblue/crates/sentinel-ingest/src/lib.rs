use std::{fmt, fs, path::Path};

use sentinel_db::{Database, NewNormalizedEvent, NewRawEvent, NewTelemetrySource};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum IngestError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Database(String),
}

impl fmt::Display for IngestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Json(error) => write!(formatter, "JSON parse error: {error}"),
            Self::Database(error) => write!(formatter, "database error: {error}"),
        }
    }
}

impl std::error::Error for IngestError {}

impl From<std::io::Error> for IngestError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for IngestError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<rusqlite::Error> for IngestError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, IngestError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    Auto,
    Json,
    Jsonl,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportOptions {
    pub source_name: String,
    pub source_type: String,
    pub connector_kind: String,
    pub source_product: String,
    pub format: ImportFormat,
    pub normalize_events: bool,
}

impl ImportOptions {
    pub fn wazuh_file(source_name: impl Into<String>) -> Self {
        Self {
            source_name: source_name.into(),
            source_type: "endpoint".to_string(),
            connector_kind: "file".to_string(),
            source_product: "wazuh".to_string(),
            format: ImportFormat::Auto,
            normalize_events: true,
        }
    }

    pub fn generic_file(source_name: impl Into<String>, source_product: impl Into<String>) -> Self {
        Self {
            source_name: source_name.into(),
            source_type: "file".to_string(),
            connector_kind: "file".to_string(),
            source_product: source_product.into(),
            format: ImportFormat::Auto,
            normalize_events: true,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImportReport {
    pub source_id: i64,
    pub batch_id: String,
    pub scanned: usize,
    pub imported: usize,
    pub skipped: usize,
    pub failed: usize,
    pub normalized: usize,
    pub errors: Vec<ImportErrorRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportErrorRecord {
    pub line: Option<usize>,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NormalizedEventDraft {
    pub event_time: Option<String>,
    pub event_type: String,
    pub source_product: String,
    pub host: String,
    pub asset_id: String,
    pub user_name: String,
    pub user_id: String,
    pub src_ip: String,
    pub src_port: Option<i64>,
    pub dest_ip: String,
    pub dest_port: Option<i64>,
    pub protocol: String,
    pub dns_query: String,
    pub http_method: String,
    pub url: String,
    pub status_code: Option<i64>,
    pub process_name: String,
    pub process_path: String,
    pub parent_process_name: String,
    pub command_line: String,
    pub file_path: String,
    pub file_hash_sha256: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub action: String,
    pub fields_json: String,
}

pub fn import_file(
    database: &Database,
    path: impl AsRef<Path>,
    options: &ImportOptions,
) -> Result<ImportReport> {
    let path = path.as_ref();
    let content = fs::read_to_string(path)?;
    let source_id = database.upsert_telemetry_source(NewTelemetrySource {
        name: &options.source_name,
        source_type: &options.source_type,
        connector_kind: &options.connector_kind,
        config_json: "{}",
        status: "enabled",
    })?;
    let parsed = parse_records(path, &content, options.format)?;
    let mut report = ImportReport {
        source_id,
        batch_id: import_batch_id(path, &content),
        failed: parsed.errors.len(),
        errors: parsed.errors,
        ..ImportReport::default()
    };

    for record in parsed.records {
        report.scanned += 1;
        let raw_hash = sha256_hex(record.payload.as_bytes());
        if database.raw_event_hash_exists(&raw_hash)? {
            report.skipped += 1;
            continue;
        }

        let raw_event_id = database.insert_raw_event(NewRawEvent {
            source_id: Some(source_id),
            source_product: &options.source_product,
            event_time: record.event_time.as_deref(),
            raw_payload: &record.payload,
            raw_hash: &raw_hash,
            ingest_batch: &report.batch_id,
        })?;
        report.imported += 1;

        if options.normalize_events {
            if let Some(normalized) = normalize_event(&options.source_product, &record.payload) {
                database.insert_normalized_event(NewNormalizedEvent {
                    raw_event_id: Some(raw_event_id),
                    event_time: normalized.event_time.as_deref(),
                    event_type: &normalized.event_type,
                    source_product: &normalized.source_product,
                    host: &normalized.host,
                    asset_id: &normalized.asset_id,
                    user_name: &normalized.user_name,
                    user_id: &normalized.user_id,
                    src_ip: &normalized.src_ip,
                    src_port: normalized.src_port,
                    dest_ip: &normalized.dest_ip,
                    dest_port: normalized.dest_port,
                    protocol: &normalized.protocol,
                    dns_query: &normalized.dns_query,
                    http_method: &normalized.http_method,
                    url: &normalized.url,
                    status_code: normalized.status_code,
                    process_name: &normalized.process_name,
                    process_path: &normalized.process_path,
                    parent_process_name: &normalized.parent_process_name,
                    command_line: &normalized.command_line,
                    file_path: &normalized.file_path,
                    file_hash_sha256: &normalized.file_hash_sha256,
                    rule_id: &normalized.rule_id,
                    rule_name: &normalized.rule_name,
                    severity: &normalized.severity,
                    action: &normalized.action,
                    fields_json: &normalized.fields_json,
                })?;
                report.normalized += 1;
            }
        }
    }

    Ok(report)
}

pub fn normalize_event(source_product: &str, payload: &str) -> Option<NormalizedEventDraft> {
    match canonical_source_product(source_product)? {
        "wazuh" => normalize_wazuh_alert(payload),
        "sysmon" => normalize_sysmon_event(payload),
        "zeek" => normalize_zeek_event(payload),
        "suricata" => normalize_suricata_eve(payload),
        "api-gateway" => normalize_api_gateway_log(payload),
        "identity" => normalize_identity_auth_event(payload),
        _ => None,
    }
}

pub fn normalize_wazuh_alert(payload: &str) -> Option<NormalizedEventDraft> {
    let value: Value = serde_json::from_str(payload).ok()?;
    let timestamp = event_time_from_value(&value);
    let rule_id = first_string(&value, &[&["rule", "id"]]);
    let rule_name = first_string(&value, &[&["rule", "description"]]);
    let severity = first_string(&value, &[&["rule", "level"]]);
    let host = first_string(&value, &[&["agent", "name"]]);
    let asset_id = first_string(&value, &[&["agent", "id"]]);
    let src_ip = first_string(&value, &[&["data", "srcip"], &["data", "src_ip"]]);
    let command_line = first_string(&value, &[&["data", "command"], &["data", "command_line"]]);
    let user_name = first_string(&value, &[&["data", "user"], &["user", "name"]]);

    if rule_id.is_none() && rule_name.is_none() && host.is_none() {
        return None;
    }

    Some(NormalizedEventDraft {
        event_time: timestamp,
        event_type: "alert".to_string(),
        source_product: "wazuh".to_string(),
        host: host.unwrap_or_default(),
        asset_id: asset_id.unwrap_or_default(),
        user_name: user_name.unwrap_or_default(),
        user_id: String::new(),
        src_ip: src_ip.unwrap_or_default(),
        src_port: None,
        dest_ip: String::new(),
        dest_port: None,
        protocol: String::new(),
        dns_query: String::new(),
        http_method: String::new(),
        url: String::new(),
        status_code: None,
        process_name: String::new(),
        process_path: String::new(),
        parent_process_name: String::new(),
        command_line: command_line.unwrap_or_default(),
        file_path: String::new(),
        file_hash_sha256: String::new(),
        rule_id: rule_id.unwrap_or_default(),
        rule_name: rule_name.unwrap_or_default(),
        severity: severity.unwrap_or_default(),
        action: String::new(),
        fields_json: value.to_string(),
    })
}

pub fn normalize_sysmon_event(payload: &str) -> Option<NormalizedEventDraft> {
    let value: Value = serde_json::from_str(payload).ok()?;
    let event_id = first_string(
        &value,
        &[
            &["Event", "System", "EventID"],
            &["winlog", "event_id"],
            &["event_id"],
            &["EventID"],
        ],
    );
    let process_path = first_string(
        &value,
        &[
            &["Event", "EventData", "Image"],
            &["winlog", "event_data", "Image"],
            &["event_data", "Image"],
            &["Image"],
        ],
    );
    let parent_process_path = first_string(
        &value,
        &[
            &["Event", "EventData", "ParentImage"],
            &["winlog", "event_data", "ParentImage"],
            &["event_data", "ParentImage"],
            &["ParentImage"],
        ],
    );

    if event_id.is_none() && process_path.is_none() {
        return None;
    }

    let mut normalized = normalized_base("sysmon", sysmon_event_type(event_id.as_deref()), &value);
    normalized.event_time = event_time_from_value(&value);
    normalized.host = first_string(
        &value,
        &[
            &["host", "name"],
            &["winlog", "computer_name"],
            &["Event", "System", "Computer"],
            &["Computer"],
        ],
    )
    .unwrap_or_default();
    normalized.asset_id = first_string(&value, &[&["host", "id"], &["agent", "id"]])
        .or_else(|| first_string(&value, &[&["Event", "EventData", "ProcessGuid"]]))
        .unwrap_or_default();
    normalized.user_name = first_string(
        &value,
        &[
            &["Event", "EventData", "User"],
            &["winlog", "event_data", "User"],
            &["event_data", "User"],
            &["user", "name"],
            &["User"],
        ],
    )
    .unwrap_or_default();
    normalized.src_ip = first_string(
        &value,
        &[
            &["Event", "EventData", "SourceIp"],
            &["winlog", "event_data", "SourceIp"],
            &["event_data", "SourceIp"],
            &["SourceIp"],
        ],
    )
    .unwrap_or_default();
    normalized.src_port = first_integer(
        &value,
        &[
            &["Event", "EventData", "SourcePort"],
            &["winlog", "event_data", "SourcePort"],
            &["event_data", "SourcePort"],
            &["SourcePort"],
        ],
    );
    normalized.dest_ip = first_string(
        &value,
        &[
            &["Event", "EventData", "DestinationIp"],
            &["winlog", "event_data", "DestinationIp"],
            &["event_data", "DestinationIp"],
            &["DestinationIp"],
        ],
    )
    .unwrap_or_default();
    normalized.dest_port = first_integer(
        &value,
        &[
            &["Event", "EventData", "DestinationPort"],
            &["winlog", "event_data", "DestinationPort"],
            &["event_data", "DestinationPort"],
            &["DestinationPort"],
        ],
    );
    normalized.protocol = first_string(
        &value,
        &[
            &["Event", "EventData", "Protocol"],
            &["winlog", "event_data", "Protocol"],
            &["event_data", "Protocol"],
            &["Protocol"],
        ],
    )
    .unwrap_or_default();
    normalized.process_path = process_path.unwrap_or_default();
    normalized.process_name = basename(&normalized.process_path);
    normalized.parent_process_name = parent_process_path
        .as_deref()
        .map(basename)
        .unwrap_or_default();
    normalized.command_line = first_string(
        &value,
        &[
            &["Event", "EventData", "CommandLine"],
            &["winlog", "event_data", "CommandLine"],
            &["event_data", "CommandLine"],
            &["CommandLine"],
        ],
    )
    .unwrap_or_default();
    normalized.file_path = first_string(
        &value,
        &[
            &["Event", "EventData", "TargetFilename"],
            &["winlog", "event_data", "TargetFilename"],
            &["event_data", "TargetFilename"],
            &["TargetFilename"],
        ],
    )
    .unwrap_or_default();
    normalized.file_hash_sha256 = sha256_from_sysmon_hashes(&value).unwrap_or_default();
    normalized.rule_id = event_id
        .as_deref()
        .map(|id| format!("sysmon-{id}"))
        .unwrap_or_default();
    normalized.rule_name = first_string(
        &value,
        &[
            &["event", "action"],
            &["winlog", "event_data", "Description"],
            &["Event", "System", "Provider", "Name"],
        ],
    )
    .unwrap_or_else(|| normalized.event_type.clone());
    normalized.severity = "info".to_string();

    Some(normalized)
}

pub fn normalize_zeek_event(payload: &str) -> Option<NormalizedEventDraft> {
    let value: Value = serde_json::from_str(payload).ok()?;
    let src_ip = first_string(&value, &[&["id.orig_h"], &["id", "orig_h"], &["src_ip"]]);
    let dest_ip = first_string(&value, &[&["id.resp_h"], &["id", "resp_h"], &["dest_ip"]]);
    let dns_query = first_string(&value, &[&["query"], &["dns", "query"]]);

    if src_ip.is_none() && dest_ip.is_none() && dns_query.is_none() {
        return None;
    }

    let event_type = if dns_query.is_some() {
        "dns_query"
    } else {
        "network_connection"
    };
    let mut normalized = normalized_base("zeek", event_type, &value);
    normalized.event_time = event_time_from_value(&value);
    normalized.asset_id = first_string(&value, &[&["uid"]]).unwrap_or_default();
    normalized.src_ip = src_ip.unwrap_or_default();
    normalized.src_port =
        first_integer(&value, &[&["id.orig_p"], &["id", "orig_p"], &["src_port"]]);
    normalized.dest_ip = dest_ip.unwrap_or_default();
    normalized.dest_port =
        first_integer(&value, &[&["id.resp_p"], &["id", "resp_p"], &["dest_port"]]);
    normalized.protocol = first_string(&value, &[&["proto"], &["protocol"]]).unwrap_or_default();
    normalized.dns_query = dns_query.unwrap_or_default();
    normalized.rule_name = first_string(&value, &[&["service"], &["qtype_name"]])
        .unwrap_or_else(|| event_type.to_string());
    normalized.action =
        first_string(&value, &[&["conn_state"], &["rcode_name"]]).unwrap_or_default();

    Some(normalized)
}

pub fn normalize_suricata_eve(payload: &str) -> Option<NormalizedEventDraft> {
    let value: Value = serde_json::from_str(payload).ok()?;
    let raw_event_type = first_string(&value, &[&["event_type"]]);
    let src_ip = first_string(&value, &[&["src_ip"], &["srcip"]]);
    let dest_ip = first_string(&value, &[&["dest_ip"], &["dst_ip"], &["destip"]]);
    let rule_id = first_string(&value, &[&["alert", "signature_id"], &["signature_id"]]);
    let rule_name = first_string(&value, &[&["alert", "signature"], &["signature"]]);

    if raw_event_type.is_none() && src_ip.is_none() && dest_ip.is_none() && rule_name.is_none() {
        return None;
    }

    let event_type = if rule_name.is_some() || raw_event_type.as_deref() == Some("alert") {
        "alert"
    } else {
        raw_event_type.as_deref().unwrap_or("network_event")
    };
    let mut normalized = normalized_base("suricata", event_type, &value);
    normalized.event_time = event_time_from_value(&value);
    normalized.asset_id = first_string(&value, &[&["flow_id"], &["pcap_cnt"]]).unwrap_or_default();
    normalized.src_ip = src_ip.unwrap_or_default();
    normalized.src_port = first_integer(&value, &[&["src_port"], &["srcport"]]);
    normalized.dest_ip = dest_ip.unwrap_or_default();
    normalized.dest_port = first_integer(&value, &[&["dest_port"], &["dst_port"], &["destport"]]);
    normalized.protocol = first_string(&value, &[&["proto"], &["app_proto"]]).unwrap_or_default();
    normalized.dns_query =
        first_string(&value, &[&["dns", "rrname"], &["dns", "query"]]).unwrap_or_default();
    normalized.http_method = first_string(&value, &[&["http", "http_method"]]).unwrap_or_default();
    normalized.url = first_string(&value, &[&["http", "url"], &["http", "hostname"], &["url"]])
        .unwrap_or_default();
    normalized.status_code = first_integer(&value, &[&["http", "status"], &["status"]]);
    normalized.rule_id = rule_id.unwrap_or_default();
    normalized.rule_name = rule_name.unwrap_or_default();
    normalized.severity =
        first_string(&value, &[&["alert", "severity"], &["severity"]]).unwrap_or_default();
    normalized.action = first_string(&value, &[&["alert", "action"], &["action"]])
        .or_else(|| first_string(&value, &[&["alert", "category"]]))
        .unwrap_or_default();

    Some(normalized)
}

pub fn normalize_api_gateway_log(payload: &str) -> Option<NormalizedEventDraft> {
    let value: Value = serde_json::from_str(payload).ok()?;
    let method = first_string(
        &value,
        &[
            &["httpMethod"],
            &["http_method"],
            &["method"],
            &["request", "method"],
            &["http", "method"],
        ],
    );
    let url = first_string(
        &value,
        &[
            &["path"],
            &["resourcePath"],
            &["requestPath"],
            &["url"],
            &["request", "uri"],
            &["http", "target"],
        ],
    );
    let src_ip = first_string(
        &value,
        &[
            &["identity", "sourceIp"],
            &["requestContext", "identity", "sourceIp"],
            &["httpRequest", "clientIp"],
            &["client_ip"],
            &["sourceIp"],
            &["src_ip"],
        ],
    );

    if method.is_none() && url.is_none() && src_ip.is_none() {
        return None;
    }

    let status_code = first_integer(
        &value,
        &[
            &["status"],
            &["statusCode"],
            &["responseStatus"],
            &["response", "status"],
            &["http", "status_code"],
        ],
    );
    let mut normalized = normalized_base("api-gateway", "api_request", &value);
    normalized.event_time = event_time_from_value(&value);
    normalized.host = first_string(
        &value,
        &[
            &["domainName"],
            &["host"],
            &["requestHost"],
            &["request", "host"],
        ],
    )
    .unwrap_or_default();
    normalized.asset_id = first_string(
        &value,
        &[
            &["requestId"],
            &["request_id"],
            &["requestContext", "requestId"],
            &["trace_id"],
        ],
    )
    .unwrap_or_default();
    normalized.user_name = first_string(
        &value,
        &[
            &["authorizer", "principalId"],
            &["requestContext", "authorizer", "principalId"],
            &["user"],
            &["user_name"],
            &["user", "name"],
        ],
    )
    .unwrap_or_default();
    normalized.user_id = first_string(
        &value,
        &[
            &["user_id"],
            &["user", "id"],
            &["claims", "sub"],
            &["requestContext", "authorizer", "claims", "sub"],
        ],
    )
    .unwrap_or_default();
    normalized.src_ip = src_ip.unwrap_or_default();
    normalized.http_method = method.unwrap_or_default();
    normalized.url = url.unwrap_or_default();
    normalized.status_code = status_code;
    normalized.severity = http_status_severity(status_code).to_string();
    normalized.action = normalized.http_method.clone();

    Some(normalized)
}

pub fn normalize_identity_auth_event(payload: &str) -> Option<NormalizedEventDraft> {
    let value: Value = serde_json::from_str(payload).ok()?;
    let user_name = first_string(
        &value,
        &[
            &["user", "name"],
            &["userName"],
            &["username"],
            &["principalName"],
            &["actor", "alternateId"],
            &["actor", "displayName"],
        ],
    );
    let action = first_string(
        &value,
        &[
            &["outcome", "result"],
            &["result"],
            &["status"],
            &["action"],
            &["eventType"],
            &["event_type"],
        ],
    );
    let src_ip = first_string(
        &value,
        &[
            &["client", "ip"],
            &["client_ip"],
            &["ipAddress"],
            &["sourceIp"],
            &["src_ip"],
            &["request", "ip"],
        ],
    );

    if user_name.is_none() && action.is_none() && src_ip.is_none() {
        return None;
    }

    let mut normalized = normalized_base("identity", "authentication", &value);
    normalized.event_time = event_time_from_value(&value);
    normalized.host = first_string(
        &value,
        &[
            &["app"],
            &["application"],
            &["client", "userAgent", "rawUserAgent"],
            &["user_agent"],
        ],
    )
    .unwrap_or_default();
    normalized.asset_id =
        first_string(&value, &[&["device", "id"], &["client", "device"]]).unwrap_or_default();
    normalized.user_name = user_name.unwrap_or_default();
    normalized.user_id = first_string(
        &value,
        &[
            &["user", "id"],
            &["userId"],
            &["actor", "id"],
            &["principalId"],
            &["subject"],
        ],
    )
    .unwrap_or_default();
    normalized.src_ip = src_ip.unwrap_or_default();
    normalized.rule_id =
        first_string(&value, &[&["eventType"], &["event_type"]]).unwrap_or_default();
    normalized.rule_name = first_string(
        &value,
        &[
            &["displayMessage"],
            &["message"],
            &["description"],
            &["event", "action"],
        ],
    )
    .unwrap_or_default();
    normalized.action = action.unwrap_or_default();
    normalized.severity = auth_severity(&normalized.action).to_string();

    Some(normalized)
}

#[derive(Debug, Clone)]
struct RawRecord {
    payload: String,
    event_time: Option<String>,
}

#[derive(Debug, Default)]
struct ParsedRecords {
    records: Vec<RawRecord>,
    errors: Vec<ImportErrorRecord>,
}

fn parse_records(path: &Path, content: &str, format: ImportFormat) -> Result<ParsedRecords> {
    match resolve_format(path, format) {
        ImportFormat::Json => parse_json_records(content),
        ImportFormat::Jsonl => Ok(parse_jsonl_records(content)),
        ImportFormat::Auto => unreachable!("format is resolved"),
    }
}

fn resolve_format(path: &Path, format: ImportFormat) -> ImportFormat {
    match format {
        ImportFormat::Auto => {
            if path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("jsonl"))
            {
                ImportFormat::Jsonl
            } else {
                ImportFormat::Json
            }
        }
        explicit => explicit,
    }
}

fn parse_json_records(content: &str) -> Result<ParsedRecords> {
    let value: Value = serde_json::from_str(content)?;
    let records = match value {
        Value::Array(items) => items
            .into_iter()
            .map(|item| {
                let payload = item.to_string();
                RawRecord {
                    event_time: event_time_from_value(&item),
                    payload,
                }
            })
            .collect(),
        item => {
            let payload = content.trim().to_string();
            vec![RawRecord {
                event_time: event_time_from_value(&item),
                payload,
            }]
        }
    };
    Ok(ParsedRecords {
        records,
        errors: Vec::new(),
    })
}

fn parse_jsonl_records(content: &str) -> ParsedRecords {
    let mut parsed = ParsedRecords::default();
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(trimmed) {
            Ok(value) => parsed.records.push(RawRecord {
                payload: trimmed.to_string(),
                event_time: event_time_from_value(&value),
            }),
            Err(error) => parsed.errors.push(ImportErrorRecord {
                line: Some(index + 1),
                message: error.to_string(),
            }),
        }
    }
    parsed
}

fn normalized_base(
    source_product: impl Into<String>,
    event_type: impl Into<String>,
    value: &Value,
) -> NormalizedEventDraft {
    NormalizedEventDraft {
        source_product: source_product.into(),
        event_type: event_type.into(),
        fields_json: value.to_string(),
        ..NormalizedEventDraft::default()
    }
}

fn canonical_source_product(source_product: &str) -> Option<&'static str> {
    let normalized = source_product.to_ascii_lowercase().replace('_', "-");
    if normalized.contains("wazuh") {
        Some("wazuh")
    } else if normalized.contains("sysmon") {
        Some("sysmon")
    } else if normalized.contains("zeek") {
        Some("zeek")
    } else if normalized.contains("suricata") || normalized == "eve" {
        Some("suricata")
    } else if normalized.contains("api-gateway")
        || normalized.contains("apigateway")
        || normalized.contains("gateway")
    {
        Some("api-gateway")
    } else if normalized.contains("identity")
        || normalized.contains("auth")
        || normalized.contains("okta")
        || normalized.contains("entra")
        || normalized.contains("azure-ad")
    {
        Some("identity")
    } else {
        None
    }
}

fn event_time_from_value(value: &Value) -> Option<String> {
    first_string(
        value,
        &[
            &["timestamp"],
            &["@timestamp"],
            &["ts"],
            &["event_time"],
            &["eventTime"],
            &["requestTime"],
            &["request_time"],
            &["time"],
            &["TimeCreated"],
            &["Event", "System", "TimeCreated", "SystemTime"],
            &["winlog", "event_data", "UtcTime"],
            &["Event", "EventData", "UtcTime"],
            &["published"],
            &["created"],
        ],
    )
}

fn first_string(value: &Value, paths: &[&[&str]]) -> Option<String> {
    paths.iter().find_map(|path| string_at(value, path))
}

fn first_integer(value: &Value, paths: &[&[&str]]) -> Option<i64> {
    paths.iter().find_map(|path| integer_at(value, path))
}

fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    match current {
        Value::String(text) => Some(text.to_string()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn integer_at(value: &Value, path: &[&str]) -> Option<i64> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    match current {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok())),
        Value::String(text) => text.parse::<i64>().ok(),
        _ => None,
    }
}

fn sysmon_event_type(event_id: Option<&str>) -> &'static str {
    match event_id {
        Some("1") => "process_start",
        Some("2") => "file_time_changed",
        Some("3") => "network_connection",
        Some("7") => "image_loaded",
        Some("10") => "process_access",
        Some("11") => "file_create",
        Some("22") => "dns_query",
        _ => "sysmon_event",
    }
}

fn basename(path: &str) -> String {
    path.rsplit(|character| character == '\\' || character == '/')
        .next()
        .unwrap_or(path)
        .to_string()
}

fn sha256_from_sysmon_hashes(value: &Value) -> Option<String> {
    let direct = first_string(
        value,
        &[
            &["Event", "EventData", "SHA256"],
            &["winlog", "event_data", "SHA256"],
            &["event_data", "SHA256"],
            &["SHA256"],
            &["hash", "sha256"],
        ],
    );
    if direct.is_some() {
        return direct.map(|hash| hash.to_ascii_lowercase());
    }

    let hashes = first_string(
        value,
        &[
            &["Event", "EventData", "Hashes"],
            &["winlog", "event_data", "Hashes"],
            &["event_data", "Hashes"],
            &["Hashes"],
        ],
    )?;
    hashes.split([',', ';', ' ']).find_map(|part| {
        let (name, hash) = part.split_once('=')?;
        name.eq_ignore_ascii_case("sha256")
            .then(|| hash.to_ascii_lowercase())
    })
}

fn http_status_severity(status_code: Option<i64>) -> &'static str {
    match status_code {
        Some(code) if code >= 500 => "high",
        Some(code) if code >= 400 => "medium",
        Some(_) => "info",
        None => "",
    }
}

fn auth_severity(action: &str) -> &'static str {
    let normalized = action.to_ascii_lowercase();
    if normalized.contains("fail")
        || normalized.contains("deny")
        || normalized.contains("reject")
        || normalized.contains("blocked")
    {
        "medium"
    } else if normalized.is_empty() {
        ""
    } else {
        "info"
    }
}

fn import_batch_id(path: &Path, content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.to_string_lossy().as_bytes());
    hasher.update(b"\0");
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_db::Database;

    const WAZUH_ALERT: &str = r#"{
  "timestamp": "2026-06-09T12:00:00Z",
  "rule": {
    "id": "100001",
    "level": 8,
    "description": "Suspicious command execution"
  },
  "agent": {
    "id": "001",
    "name": "demo-host"
  },
  "data": {
    "srcip": "10.0.0.5",
    "user": "deploy",
    "command": "powershell.exe -EncodedCommand redacted"
  }
}"#;

    const SYSMON_PROCESS: &str = r#"{
  "@timestamp": "2026-06-09T12:02:00Z",
  "winlog": {
    "event_id": 1,
    "computer_name": "win-host-01",
    "event_data": {
      "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
      "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "CommandLine": "powershell.exe -NoProfile -EncodedCommand redacted",
      "ParentImage": "C:\\Windows\\explorer.exe",
      "User": "ACME\\alice",
      "Hashes": "MD5=aaa,SHA256=BBBBCCCCDDDDEEEEFFFF0000111122223333444455556666777788889999AAAA"
    }
  },
  "host": {
    "id": "asset-win-01",
    "name": "win-host-01"
  }
}"#;

    const ZEEK_DNS: &str = r#"{
  "ts": 1770475320.125,
  "uid": "CZeekDns1",
  "id.orig_h": "10.0.0.5",
  "id.orig_p": 53744,
  "id.resp_h": "10.0.0.53",
  "id.resp_p": 53,
  "proto": "udp",
  "query": "updates.example.com",
  "qtype_name": "A",
  "rcode_name": "NOERROR"
}"#;

    const ZEEK_CONN: &str = r#"{
  "ts": 1770475321.5,
  "uid": "CZeekConn1",
  "id.orig_h": "10.0.0.5",
  "id.orig_p": 53745,
  "id.resp_h": "203.0.113.10",
  "id.resp_p": 443,
  "proto": "tcp",
  "service": "ssl",
  "conn_state": "S1"
}"#;

    const SURICATA_EVE_ALERT: &str = r#"{
  "timestamp": "2026-06-09T12:03:00.000000Z",
  "event_type": "alert",
  "src_ip": "10.0.0.5",
  "src_port": 49712,
  "dest_ip": "198.51.100.10",
  "dest_port": 443,
  "proto": "TCP",
  "alert": {
    "signature_id": 2026001,
    "signature": "ET POLICY Suspicious TLS Certificate",
    "severity": 2,
    "category": "Potential Corporate Privacy Violation",
    "action": "allowed"
  }
}"#;

    const API_GATEWAY_ACCESS: &str = r#"{
  "requestTime": "2026-06-09T12:04:00Z",
  "requestId": "req-123",
  "domainName": "api.example.com",
  "httpMethod": "POST",
  "path": "/v1/admin/users",
  "status": 403,
  "identity": {
    "sourceIp": "198.51.100.23"
  },
  "authorizer": {
    "principalId": "alice@example.com"
  }
}"#;

    const IDENTITY_AUTH: &str = r#"{
  "published": "2026-06-09T12:05:00Z",
  "eventType": "user.authentication.failed",
  "displayMessage": "User login failed",
  "actor": {
    "id": "00u123",
    "alternateId": "alice@example.com"
  },
  "client": {
    "ip": "203.0.113.44",
    "device": "Chrome on macOS"
  },
  "outcome": {
    "result": "FAILURE"
  }
}"#;

    #[test]
    fn imports_json_file_into_raw_events_and_normalizes_wazuh() {
        let database = Database::open_initialized_memory().expect("database initializes");
        let dir = tempfile::tempdir().expect("tempdir exists");
        let path = dir.path().join("wazuh-alert.json");
        std::fs::write(&path, WAZUH_ALERT).expect("fixture writes");

        let report = import_file(&database, &path, &ImportOptions::wazuh_file("wazuh-json"))
            .expect("import succeeds");

        assert_eq!(report.scanned, 1);
        assert_eq!(report.imported, 1);
        assert_eq!(report.skipped, 0);
        assert_eq!(report.failed, 0);
        assert_eq!(report.normalized, 1);
        assert_eq!(database.raw_event_count().unwrap(), 1);
        assert_eq!(database.normalized_event_count().unwrap(), 1);
        assert_eq!(database.list_events(10).unwrap()[0].source_product, "wazuh");
        assert_eq!(database.list_events(10).unwrap()[0].event_type, "alert");
        assert_eq!(database.raw_events(10).unwrap()[0].raw_payload, WAZUH_ALERT);
        assert_eq!(database.raw_events(10).unwrap()[0].raw_hash.len(), 64);
    }

    #[test]
    fn imports_jsonl_file_skips_duplicates_and_reports_failed_lines() {
        let database = Database::open_initialized_memory().expect("database initializes");
        let dir = tempfile::tempdir().expect("tempdir exists");
        let path = dir.path().join("events.jsonl");
        let content = "{\"timestamp\":\"2026-06-09T12:00:00Z\",\"event\":\"one\"}\nnot-json\n{\"timestamp\":\"2026-06-09T12:01:00Z\",\"event\":\"two\"}\n";
        std::fs::write(&path, content).expect("fixture writes");

        let options = ImportOptions {
            format: ImportFormat::Jsonl,
            ..ImportOptions::generic_file("generic-jsonl", "custom")
        };
        let first = import_file(&database, &path, &options).expect("first import succeeds");
        let second = import_file(&database, &path, &options).expect("second import succeeds");

        assert_eq!(first.scanned, 2);
        assert_eq!(first.imported, 2);
        assert_eq!(first.skipped, 0);
        assert_eq!(first.failed, 1);
        assert_eq!(first.errors[0].line, Some(2));
        assert_eq!(second.scanned, 2);
        assert_eq!(second.imported, 0);
        assert_eq!(second.skipped, 2);
        assert_eq!(second.failed, 1);
        assert_eq!(database.raw_event_count().unwrap(), 2);
        assert_eq!(
            database.raw_events(10).unwrap()[0].raw_payload,
            "{\"timestamp\":\"2026-06-09T12:00:00Z\",\"event\":\"one\"}"
        );
    }

    #[test]
    fn normalizes_wazuh_alert_fields() {
        let normalized = normalize_wazuh_alert(WAZUH_ALERT).expect("normalizes");

        assert_eq!(
            normalized.event_time.as_deref(),
            Some("2026-06-09T12:00:00Z")
        );
        assert_eq!(normalized.host, "demo-host");
        assert_eq!(normalized.asset_id, "001");
        assert_eq!(normalized.src_ip, "10.0.0.5");
        assert_eq!(normalized.user_name, "deploy");
        assert_eq!(normalized.rule_id, "100001");
        assert_eq!(normalized.rule_name, "Suspicious command execution");
        assert_eq!(normalized.severity, "8");
        assert!(normalized.command_line.contains("powershell.exe"));
    }

    #[test]
    fn imports_each_mvp_source_into_normalized_events() {
        let database = Database::open_initialized_memory().expect("database initializes");
        let dir = tempfile::tempdir().expect("tempdir exists");
        let cases = [
            ("sysmon", "sysmon.json", SYSMON_PROCESS, "process_start"),
            ("zeek", "zeek-dns.json", ZEEK_DNS, "dns_query"),
            ("suricata", "suricata.json", SURICATA_EVE_ALERT, "alert"),
            (
                "api-gateway",
                "api-gateway.json",
                API_GATEWAY_ACCESS,
                "api_request",
            ),
            ("identity", "identity.json", IDENTITY_AUTH, "authentication"),
        ];

        for (source_product, file_name, payload, expected_event_type) in cases {
            let path = dir.path().join(file_name);
            std::fs::write(&path, payload).expect("fixture writes");
            let report = import_file(
                &database,
                &path,
                &ImportOptions::generic_file(file_name, source_product),
            )
            .expect("import succeeds");

            assert_eq!(report.scanned, 1, "{source_product}");
            assert_eq!(report.imported, 1, "{source_product}");
            assert_eq!(report.normalized, 1, "{source_product}");
            assert!(
                database
                    .list_events(100)
                    .unwrap()
                    .iter()
                    .any(|event| event.source_product == source_product
                        && event.event_type == expected_event_type)
            );
        }

        assert_eq!(database.raw_event_count().unwrap(), 5);
        assert_eq!(database.normalized_event_count().unwrap(), 5);
        assert!(
            database
                .normalized_events(10)
                .unwrap()
                .iter()
                .all(|event| event.raw_event_id.is_some())
        );
    }

    #[test]
    fn normalizes_sysmon_process_fields() {
        let normalized = normalize_sysmon_event(SYSMON_PROCESS).expect("normalizes");

        assert_eq!(
            normalized.event_time.as_deref(),
            Some("2026-06-09T12:02:00Z")
        );
        assert_eq!(normalized.source_product, "sysmon");
        assert_eq!(normalized.event_type, "process_start");
        assert_eq!(normalized.host, "win-host-01");
        assert_eq!(normalized.asset_id, "asset-win-01");
        assert_eq!(normalized.user_name, "ACME\\alice");
        assert_eq!(normalized.process_name, "powershell.exe");
        assert_eq!(
            normalized.process_path,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        );
        assert_eq!(normalized.parent_process_name, "explorer.exe");
        assert!(normalized.command_line.contains("-EncodedCommand"));
        assert_eq!(normalized.rule_id, "sysmon-1");
        assert_eq!(
            normalized.file_hash_sha256,
            "bbbbccccddddeeeeffff0000111122223333444455556666777788889999aaaa"
        );
    }

    #[test]
    fn normalizes_zeek_dns_and_connection_fields() {
        let dns = normalize_zeek_event(ZEEK_DNS).expect("dns normalizes");
        let connection = normalize_zeek_event(ZEEK_CONN).expect("conn normalizes");

        assert_eq!(dns.source_product, "zeek");
        assert_eq!(dns.event_type, "dns_query");
        assert_eq!(dns.asset_id, "CZeekDns1");
        assert_eq!(dns.src_ip, "10.0.0.5");
        assert_eq!(dns.src_port, Some(53744));
        assert_eq!(dns.dest_ip, "10.0.0.53");
        assert_eq!(dns.dest_port, Some(53));
        assert_eq!(dns.protocol, "udp");
        assert_eq!(dns.dns_query, "updates.example.com");
        assert_eq!(dns.action, "NOERROR");

        assert_eq!(connection.event_type, "network_connection");
        assert_eq!(connection.asset_id, "CZeekConn1");
        assert_eq!(connection.dest_ip, "203.0.113.10");
        assert_eq!(connection.dest_port, Some(443));
        assert_eq!(connection.protocol, "tcp");
        assert_eq!(connection.rule_name, "ssl");
        assert_eq!(connection.action, "S1");
    }

    #[test]
    fn normalizes_suricata_eve_alert_fields() {
        let normalized = normalize_suricata_eve(SURICATA_EVE_ALERT).expect("normalizes");

        assert_eq!(
            normalized.event_time.as_deref(),
            Some("2026-06-09T12:03:00.000000Z")
        );
        assert_eq!(normalized.source_product, "suricata");
        assert_eq!(normalized.event_type, "alert");
        assert_eq!(normalized.src_ip, "10.0.0.5");
        assert_eq!(normalized.src_port, Some(49712));
        assert_eq!(normalized.dest_ip, "198.51.100.10");
        assert_eq!(normalized.dest_port, Some(443));
        assert_eq!(normalized.protocol, "TCP");
        assert_eq!(normalized.rule_id, "2026001");
        assert_eq!(normalized.rule_name, "ET POLICY Suspicious TLS Certificate");
        assert_eq!(normalized.severity, "2");
        assert_eq!(normalized.action, "allowed");
    }

    #[test]
    fn normalizes_api_gateway_access_fields() {
        let normalized = normalize_api_gateway_log(API_GATEWAY_ACCESS).expect("normalizes");

        assert_eq!(
            normalized.event_time.as_deref(),
            Some("2026-06-09T12:04:00Z")
        );
        assert_eq!(normalized.source_product, "api-gateway");
        assert_eq!(normalized.event_type, "api_request");
        assert_eq!(normalized.host, "api.example.com");
        assert_eq!(normalized.asset_id, "req-123");
        assert_eq!(normalized.user_name, "alice@example.com");
        assert_eq!(normalized.src_ip, "198.51.100.23");
        assert_eq!(normalized.http_method, "POST");
        assert_eq!(normalized.url, "/v1/admin/users");
        assert_eq!(normalized.status_code, Some(403));
        assert_eq!(normalized.severity, "medium");
        assert_eq!(normalized.action, "POST");
    }

    #[test]
    fn normalizes_identity_auth_json_fields() {
        let normalized = normalize_identity_auth_event(IDENTITY_AUTH).expect("normalizes");

        assert_eq!(
            normalized.event_time.as_deref(),
            Some("2026-06-09T12:05:00Z")
        );
        assert_eq!(normalized.source_product, "identity");
        assert_eq!(normalized.event_type, "authentication");
        assert_eq!(normalized.user_name, "alice@example.com");
        assert_eq!(normalized.user_id, "00u123");
        assert_eq!(normalized.src_ip, "203.0.113.44");
        assert_eq!(normalized.asset_id, "Chrome on macOS");
        assert_eq!(normalized.rule_id, "user.authentication.failed");
        assert_eq!(normalized.rule_name, "User login failed");
        assert_eq!(normalized.action, "FAILURE");
        assert_eq!(normalized.severity, "medium");
    }
}
