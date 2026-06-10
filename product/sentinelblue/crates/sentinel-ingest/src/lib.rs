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
    pub normalize_wazuh: bool,
}

impl ImportOptions {
    pub fn wazuh_file(source_name: impl Into<String>) -> Self {
        Self {
            source_name: source_name.into(),
            source_type: "endpoint".to_string(),
            connector_kind: "file".to_string(),
            source_product: "wazuh".to_string(),
            format: ImportFormat::Auto,
            normalize_wazuh: true,
        }
    }

    pub fn generic_file(source_name: impl Into<String>, source_product: impl Into<String>) -> Self {
        Self {
            source_name: source_name.into(),
            source_type: "file".to_string(),
            connector_kind: "file".to_string(),
            source_product: source_product.into(),
            format: ImportFormat::Auto,
            normalize_wazuh: false,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedEventDraft {
    pub event_time: Option<String>,
    pub event_type: String,
    pub source_product: String,
    pub host: String,
    pub asset_id: String,
    pub user_name: String,
    pub src_ip: String,
    pub command_line: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
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

        if options.normalize_wazuh && options.source_product.eq_ignore_ascii_case("wazuh") {
            if let Some(normalized) = normalize_wazuh_alert(&record.payload) {
                database.insert_normalized_event(NewNormalizedEvent {
                    raw_event_id: Some(raw_event_id),
                    event_time: normalized.event_time.as_deref(),
                    event_type: &normalized.event_type,
                    source_product: &normalized.source_product,
                    host: &normalized.host,
                    asset_id: &normalized.asset_id,
                    user_name: &normalized.user_name,
                    src_ip: &normalized.src_ip,
                    command_line: &normalized.command_line,
                    rule_id: &normalized.rule_id,
                    rule_name: &normalized.rule_name,
                    severity: &normalized.severity,
                    fields_json: &normalized.fields_json,
                })?;
                report.normalized += 1;
            }
        }
    }

    Ok(report)
}

pub fn normalize_wazuh_alert(payload: &str) -> Option<NormalizedEventDraft> {
    let value: Value = serde_json::from_str(payload).ok()?;
    let timestamp = string_at(&value, &["timestamp"]);
    let rule_id = string_at(&value, &["rule", "id"]);
    let rule_name = string_at(&value, &["rule", "description"]);
    let severity = string_at(&value, &["rule", "level"]);
    let host = string_at(&value, &["agent", "name"]);
    let asset_id = string_at(&value, &["agent", "id"]);
    let src_ip = string_at(&value, &["data", "srcip"]);
    let command_line = string_at(&value, &["data", "command"]);
    let user_name =
        string_at(&value, &["data", "user"]).or_else(|| string_at(&value, &["user", "name"]));

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
        src_ip: src_ip.unwrap_or_default(),
        command_line: command_line.unwrap_or_default(),
        rule_id: rule_id.unwrap_or_default(),
        rule_name: rule_name.unwrap_or_default(),
        severity: severity.unwrap_or_default(),
        fields_json: value.to_string(),
    })
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
                    event_time: string_at(&item, &["timestamp"]),
                    payload,
                }
            })
            .collect(),
        item => {
            let payload = content.trim().to_string();
            vec![RawRecord {
                event_time: string_at(&item, &["timestamp"]),
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
                event_time: string_at(&value, &["timestamp"]),
            }),
            Err(error) => parsed.errors.push(ImportErrorRecord {
                line: Some(index + 1),
                message: error.to_string(),
            }),
        }
    }
    parsed
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
}
