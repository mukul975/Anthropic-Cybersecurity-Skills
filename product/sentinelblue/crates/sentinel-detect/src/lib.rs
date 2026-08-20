use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use sentinel_db::{Database, NewAlert, NewDetectorRun, NewEvidence, StoredNormalizedEvent};
use serde::{Deserialize, Serialize};

pub const DEFAULT_EVENT_LIMIT: usize = 1_000;

#[derive(Debug)]
pub enum DetectionError {
    Database(String),
    Json(serde_json::Error),
}

impl fmt::Display for DetectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "database error: {error}"),
            Self::Json(error) => write!(formatter, "JSON error: {error}"),
        }
    }
}

impl std::error::Error for DetectionError {}

impl From<rusqlite::Error> for DetectionError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value.to_string())
    }
}

impl From<serde_json::Error> for DetectionError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub type Result<T> = std::result::Result<T, DetectionError>;

pub trait Detector {
    fn id(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn input_query(&self) -> &'static str;
    fn detect(&self, events: &[StoredNormalizedEvent]) -> Vec<DetectorFinding>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DetectionReport {
    pub detector_run_id: i64,
    pub detector_id: String,
    pub detector_version: String,
    pub scanned_events: usize,
    pub findings: Vec<DetectorFinding>,
    pub alerts_created: usize,
    pub evidence_created: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DetectorFinding {
    pub title: String,
    pub severity: String,
    pub confidence: f64,
    pub description: String,
    pub attack: Vec<AttackMapping>,
    pub evidence: Vec<FindingEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttackMapping {
    pub technique_id: String,
    pub technique_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingEvidence {
    pub raw_event_id: Option<i64>,
    pub normalized_event_id: i64,
    pub source_product: String,
    pub event_time: Option<String>,
    pub host: String,
    pub user_name: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedEvidenceRef {
    pub evidence_id: i64,
    pub raw_event_id: Option<i64>,
    pub normalized_event_id: i64,
}

pub fn run_default_detectors(database: &Database) -> Result<Vec<DetectionReport>> {
    let detectors: Vec<Box<dyn Detector>> = vec![
        Box::new(PowerShellEncodedCommandDetector),
        Box::new(SysmonProcessInjectionDetector),
        Box::new(PasswordSprayDetector),
        Box::new(ImpossibleTravelDetector),
        Box::new(DnsTunnelingDetector),
        Box::new(DnsBeaconingDetector),
        Box::new(ApiEnumerationDetector),
        Box::new(IocMatchDetector::default()),
    ];
    detectors
        .iter()
        .map(|detector| run_detector(database, detector.as_ref()))
        .collect()
}

pub fn run_detector(database: &Database, detector: &dyn Detector) -> Result<DetectionReport> {
    let events = database.normalized_events(DEFAULT_EVENT_LIMIT)?;
    let detector_run_id = database.start_detector_run(NewDetectorRun {
        detector_id: detector.id(),
        detector_version: detector.version(),
        input_query: detector.input_query(),
    })?;
    let findings = detector.detect(&events);
    let mut alerts_created = 0;
    let mut evidence_created = 0;

    for finding in &findings {
        let attack_json = serde_json::to_string(&finding.attack)?;
        let alert_id = database.insert_alert(NewAlert {
            detector_run_id: Some(detector_run_id),
            title: &finding.title,
            description: &finding.description,
            severity: &finding.severity,
            confidence: finding.confidence,
            status: "new",
            attack_json: &attack_json,
            evidence_json: "[]",
        })?;
        alerts_created += 1;

        let mut persisted = Vec::new();
        for evidence in &finding.evidence {
            let evidence_id = database.insert_evidence(NewEvidence {
                case_id: None,
                alert_id: Some(alert_id),
                raw_event_id: evidence.raw_event_id,
                normalized_event_id: Some(evidence.normalized_event_id),
                evidence_type: "normalized_event",
                summary: &evidence.summary,
            })?;
            evidence_created += 1;
            persisted.push(PersistedEvidenceRef {
                evidence_id,
                raw_event_id: evidence.raw_event_id,
                normalized_event_id: evidence.normalized_event_id,
            });
        }

        let evidence_json = serde_json::to_string(&persisted)?;
        database.update_alert_evidence_json(alert_id, &evidence_json)?;
    }

    database.complete_detector_run(detector_run_id, "completed", findings.len())?;

    Ok(DetectionReport {
        detector_run_id,
        detector_id: detector.id().to_string(),
        detector_version: detector.version().to_string(),
        scanned_events: events.len(),
        findings,
        alerts_created,
        evidence_created,
    })
}

pub struct PowerShellEncodedCommandDetector;

impl Detector for PowerShellEncodedCommandDetector {
    fn id(&self) -> &'static str {
        "sentinelblue.detector.powershell_encoded_command"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn name(&self) -> &'static str {
        "Suspicious PowerShell Encoded Command"
    }

    fn input_query(&self) -> &'static str {
        "normalized_events where command_line/process fields contain powershell encoded command indicators"
    }

    fn detect(&self, events: &[StoredNormalizedEvent]) -> Vec<DetectorFinding> {
        events
            .iter()
            .filter(|event| is_powershell_encoded_command(event))
            .map(|event| powershell_finding(event))
            .collect()
    }
}

pub struct SysmonProcessInjectionDetector;

impl Detector for SysmonProcessInjectionDetector {
    fn id(&self) -> &'static str {
        "sentinelblue.detector.sysmon_process_injection"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn name(&self) -> &'static str {
        "Sysmon Process Injection Candidate"
    }

    fn input_query(&self) -> &'static str {
        "normalized_events where source_product=sysmon and process access fields indicate injection"
    }

    fn detect(&self, events: &[StoredNormalizedEvent]) -> Vec<DetectorFinding> {
        events
            .iter()
            .filter(|event| is_sysmon_process_injection_candidate(event))
            .map(|event| {
                single_event_finding(
                    event,
                    "Sysmon process injection candidate",
                    "high",
                    0.78,
                    "Sysmon process access telemetry indicates possible credential theft or process injection.",
                    "T1055",
                    "Process Injection",
                )
            })
            .collect()
    }
}

pub struct PasswordSprayDetector;

impl Detector for PasswordSprayDetector {
    fn id(&self) -> &'static str {
        "sentinelblue.detector.password_spray"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn name(&self) -> &'static str {
        "Password Spray Candidate"
    }

    fn input_query(&self) -> &'static str {
        "identity/authentication normalized_events grouped by source IP and hour"
    }

    fn detect(&self, events: &[StoredNormalizedEvent]) -> Vec<DetectorFinding> {
        let mut groups: HashMap<(String, String), Vec<&StoredNormalizedEvent>> = HashMap::new();
        for event in events.iter().filter(|event| is_failed_auth_event(event)) {
            let src_ip = event.src_ip.trim();
            if src_ip.is_empty() {
                continue;
            }
            groups
                .entry((src_ip.to_string(), time_bucket(event)))
                .or_default()
                .push(event);
        }

        groups
            .into_iter()
            .filter_map(|((src_ip, _bucket), group)| {
                let users = distinct_non_empty(group.iter().map(|event| event.user_name.as_str()));
                (users.len() >= 5).then(|| {
                    grouped_finding(
                        &group,
                        format!("Password spray candidate from {src_ip}"),
                        "high",
                        0.82,
                        format!(
                            "Authentication failures from {src_ip} targeted {} distinct users in the same time bucket.",
                            users.len()
                        ),
                        "T1110.003",
                        "Password Spraying",
                    )
                })
            })
            .collect()
    }
}

pub struct ImpossibleTravelDetector;

impl Detector for ImpossibleTravelDetector {
    fn id(&self) -> &'static str {
        "sentinelblue.detector.impossible_travel"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn name(&self) -> &'static str {
        "Impossible Travel Candidate"
    }

    fn input_query(&self) -> &'static str {
        "successful identity/authentication normalized_events grouped by user and hour"
    }

    fn detect(&self, events: &[StoredNormalizedEvent]) -> Vec<DetectorFinding> {
        let mut groups: HashMap<(String, String), Vec<&StoredNormalizedEvent>> = HashMap::new();
        for event in events
            .iter()
            .filter(|event| is_successful_auth_event(event))
        {
            if event.user_name.trim().is_empty() {
                continue;
            }
            groups
                .entry((event.user_name.clone(), time_bucket(event)))
                .or_default()
                .push(event);
        }

        groups
            .into_iter()
            .filter_map(|((user_name, _bucket), group)| {
                let countries = group
                    .iter()
                    .filter_map(|event| country(event))
                    .map(|value| value.to_ascii_lowercase())
                    .collect::<HashSet<_>>();
                let source_ips = distinct_non_empty(group.iter().map(|event| event.src_ip.as_str()));
                (countries.len() >= 2 && source_ips.len() >= 2).then(|| {
                    grouped_finding(
                        &group,
                        format!("Impossible travel candidate for {user_name}"),
                        "medium",
                        0.7,
                        format!(
                            "{user_name} authenticated from {} countries and {} source IPs in the same time bucket.",
                            countries.len(),
                            source_ips.len()
                        ),
                        "T1078",
                        "Valid Accounts",
                    )
                })
            })
            .collect()
    }
}

pub struct DnsTunnelingDetector;

impl Detector for DnsTunnelingDetector {
    fn id(&self) -> &'static str {
        "sentinelblue.detector.dns_tunneling"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn name(&self) -> &'static str {
        "DNS Tunneling Candidate"
    }

    fn input_query(&self) -> &'static str {
        "dns_query normalized_events with unusually long or encoded-looking labels"
    }

    fn detect(&self, events: &[StoredNormalizedEvent]) -> Vec<DetectorFinding> {
        events
            .iter()
            .filter(|event| is_dns_tunneling_candidate(event))
            .map(|event| {
                single_event_finding(
                    event,
                    "DNS tunneling candidate",
                    "medium",
                    0.72,
                    "DNS query contains long or high-entropy labels consistent with tunneling.",
                    "T1071.004",
                    "DNS",
                )
            })
            .collect()
    }
}

pub struct DnsBeaconingDetector;

impl Detector for DnsBeaconingDetector {
    fn id(&self) -> &'static str {
        "sentinelblue.detector.dns_beaconing"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn name(&self) -> &'static str {
        "DNS Beaconing Candidate"
    }

    fn input_query(&self) -> &'static str {
        "dns_query normalized_events grouped by source IP, query, and hour"
    }

    fn detect(&self, events: &[StoredNormalizedEvent]) -> Vec<DetectorFinding> {
        let mut groups: HashMap<(String, String, String), Vec<&StoredNormalizedEvent>> =
            HashMap::new();
        for event in events.iter().filter(|event| !event.dns_query.is_empty()) {
            groups
                .entry((
                    event.src_ip.clone(),
                    event.dns_query.to_ascii_lowercase(),
                    time_bucket(event),
                ))
                .or_default()
                .push(event);
        }

        groups
            .into_iter()
            .filter_map(|((_src_ip, query, _bucket), group)| {
                (group.len() >= 3).then(|| {
                    grouped_finding(
                        &group,
                        format!("DNS beaconing candidate for {query}"),
                        "medium",
                        0.68,
                        format!(
                            "Observed {} repeated DNS queries in the same time bucket.",
                            group.len()
                        ),
                        "T1071.004",
                        "DNS",
                    )
                })
            })
            .collect()
    }
}

pub struct ApiEnumerationDetector;

impl Detector for ApiEnumerationDetector {
    fn id(&self) -> &'static str {
        "sentinelblue.detector.api_enumeration"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn name(&self) -> &'static str {
        "API Enumeration Candidate"
    }

    fn input_query(&self) -> &'static str {
        "api-gateway normalized_events grouped by source IP and hour"
    }

    fn detect(&self, events: &[StoredNormalizedEvent]) -> Vec<DetectorFinding> {
        let mut groups: HashMap<(String, String), Vec<&StoredNormalizedEvent>> = HashMap::new();
        for event in events.iter().filter(|event| {
            event.source_product == "api-gateway"
                && matches!(event.status_code, Some(401 | 403 | 404 | 405))
        }) {
            if event.src_ip.is_empty() {
                continue;
            }
            groups
                .entry((event.src_ip.clone(), time_bucket(event)))
                .or_default()
                .push(event);
        }

        groups
            .into_iter()
            .filter_map(|((src_ip, _bucket), group)| {
                let urls = distinct_non_empty(group.iter().map(|event| event.url.as_str()));
                (urls.len() >= 5).then(|| {
                    grouped_finding(
                        &group,
                        format!("API enumeration candidate from {src_ip}"),
                        "medium",
                        0.74,
                        format!(
                            "{src_ip} touched {} distinct denied or missing API paths in one time bucket.",
                            urls.len()
                        ),
                        "T1087",
                        "Account Discovery",
                    )
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct IocMatchDetector {
    ip_indicators: HashSet<String>,
    domain_indicators: HashSet<String>,
    sha256_indicators: HashSet<String>,
}

impl IocMatchDetector {
    pub fn with_indicators(
        ip_indicators: impl IntoIterator<Item = impl Into<String>>,
        domain_indicators: impl IntoIterator<Item = impl Into<String>>,
        sha256_indicators: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            ip_indicators: ip_indicators
                .into_iter()
                .map(|value| value.into())
                .collect(),
            domain_indicators: domain_indicators
                .into_iter()
                .map(|value| value.into().to_ascii_lowercase())
                .collect(),
            sha256_indicators: sha256_indicators
                .into_iter()
                .map(|value| value.into().to_ascii_lowercase())
                .collect(),
        }
    }
}

impl Detector for IocMatchDetector {
    fn id(&self) -> &'static str {
        "sentinelblue.detector.ioc_match"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn name(&self) -> &'static str {
        "IOC Match"
    }

    fn input_query(&self) -> &'static str {
        "normalized_events matched against configured or enriched indicators"
    }

    fn detect(&self, events: &[StoredNormalizedEvent]) -> Vec<DetectorFinding> {
        events
            .iter()
            .filter(|event| self.matches_event(event) || event_has_enriched_ioc_match(event))
            .map(|event| {
                single_event_finding(
                    event,
                    "IOC match",
                    "high",
                    0.9,
                    "Event matched a known or pre-enriched indicator of compromise.",
                    "T1105",
                    "Ingress Tool Transfer",
                )
            })
            .collect()
    }
}

impl IocMatchDetector {
    fn matches_event(&self, event: &StoredNormalizedEvent) -> bool {
        self.ip_indicators.contains(&event.src_ip)
            || self.ip_indicators.contains(&event.dest_ip)
            || self
                .domain_indicators
                .contains(&event.dns_query.to_ascii_lowercase())
            || self
                .domain_indicators
                .contains(&event.host.to_ascii_lowercase())
            || self
                .sha256_indicators
                .contains(&event.file_hash_sha256.to_ascii_lowercase())
    }
}

fn is_powershell_encoded_command(event: &StoredNormalizedEvent) -> bool {
    let command = format!(
        "{} {} {}",
        event.command_line, event.process_name, event.process_path
    )
    .to_ascii_lowercase();

    command.contains("powershell")
        && (command.contains("encodedcommand")
            || command.contains("-enc ")
            || command.contains("-enc\t")
            || command.ends_with("-enc")
            || command.contains(" -e "))
}

fn powershell_finding(event: &StoredNormalizedEvent) -> DetectorFinding {
    let subject = if event.host.is_empty() {
        "unknown host"
    } else {
        &event.host
    };
    let actor = if event.user_name.is_empty() {
        "unknown user"
    } else {
        &event.user_name
    };
    let command = if event.command_line.is_empty() {
        event.process_path.as_str()
    } else {
        event.command_line.as_str()
    };

    DetectorFinding {
        title: format!("Suspicious PowerShell encoded command on {subject}"),
        severity: "high".to_string(),
        confidence: 0.86,
        description: format!(
            "PowerShell execution used an encoded command indicator for {actor}: {command}"
        ),
        attack: vec![AttackMapping {
            technique_id: "T1059.001".to_string(),
            technique_name: "PowerShell".to_string(),
        }],
        evidence: vec![FindingEvidence {
            raw_event_id: event.raw_event_id,
            normalized_event_id: event.id,
            source_product: event.source_product.clone(),
            event_time: event.event_time.clone(),
            host: event.host.clone(),
            user_name: event.user_name.clone(),
            summary: format!(
                "{} event {} contains encoded PowerShell execution for host '{}' and user '{}'",
                event.source_product, event.id, event.host, event.user_name
            ),
        }],
    }
}

fn single_event_finding(
    event: &StoredNormalizedEvent,
    title: &str,
    severity: &str,
    confidence: f64,
    description: &str,
    technique_id: &str,
    technique_name: &str,
) -> DetectorFinding {
    DetectorFinding {
        title: format!("{title} on {}", display_subject(event)),
        severity: severity.to_string(),
        confidence,
        description: description.to_string(),
        attack: vec![AttackMapping {
            technique_id: technique_id.to_string(),
            technique_name: technique_name.to_string(),
        }],
        evidence: vec![evidence_from_event(event)],
    }
}

fn grouped_finding(
    events: &[&StoredNormalizedEvent],
    title: String,
    severity: &str,
    confidence: f64,
    description: String,
    technique_id: &str,
    technique_name: &str,
) -> DetectorFinding {
    DetectorFinding {
        title,
        severity: severity.to_string(),
        confidence,
        description,
        attack: vec![AttackMapping {
            technique_id: technique_id.to_string(),
            technique_name: technique_name.to_string(),
        }],
        evidence: events
            .iter()
            .map(|event| evidence_from_event(event))
            .collect(),
    }
}

fn evidence_from_event(event: &StoredNormalizedEvent) -> FindingEvidence {
    FindingEvidence {
        raw_event_id: event.raw_event_id,
        normalized_event_id: event.id,
        source_product: event.source_product.clone(),
        event_time: event.event_time.clone(),
        host: event.host.clone(),
        user_name: event.user_name.clone(),
        summary: format!(
            "{} event {} type '{}' host '{}' user '{}' src '{}' dest '{}' query '{}' url '{}'",
            event.source_product,
            event.id,
            event.event_type,
            event.host,
            event.user_name,
            event.src_ip,
            event.dest_ip,
            event.dns_query,
            event.url
        ),
    }
}

fn display_subject(event: &StoredNormalizedEvent) -> String {
    if !event.host.is_empty() {
        event.host.clone()
    } else if !event.src_ip.is_empty() {
        event.src_ip.clone()
    } else if !event.user_name.is_empty() {
        event.user_name.clone()
    } else {
        format!("event {}", event.id)
    }
}

fn is_sysmon_process_injection_candidate(event: &StoredNormalizedEvent) -> bool {
    if event.source_product != "sysmon" {
        return false;
    }
    let fields = event.fields_json.to_ascii_lowercase();
    let process_access = event.event_type == "process_access"
        || event.rule_id == "sysmon-10"
        || fields.contains("\"eventid\":10")
        || fields.contains("\"event_id\":10");
    let sensitive_target = fields.contains("lsass.exe")
        || fields.contains("samss.exe")
        || fields.contains("winlogon.exe");
    let suspicious_access = fields.contains("0x1fffff")
        || fields.contains("0x1f0fff")
        || fields.contains("0x143a")
        || fields.contains("create_remote_thread")
        || fields.contains("writeprocessmemory");

    process_access && (sensitive_target || suspicious_access)
}

fn is_failed_auth_event(event: &StoredNormalizedEvent) -> bool {
    event.event_type == "authentication"
        && contains_any(
            &event.action,
            &["fail", "deny", "reject", "blocked", "invalid"],
        )
}

fn is_successful_auth_event(event: &StoredNormalizedEvent) -> bool {
    event.event_type == "authentication"
        && contains_any(&event.action, &["success", "allow", "approved"])
}

fn is_dns_tunneling_candidate(event: &StoredNormalizedEvent) -> bool {
    if event.dns_query.is_empty() {
        return false;
    }
    let query = event.dns_query.trim_end_matches('.');
    query.len() >= 80
        || query
            .split('.')
            .any(|label| label.len() >= 45 && encoded_ratio(label) >= 0.85)
}

fn event_has_enriched_ioc_match(event: &StoredNormalizedEvent) -> bool {
    let fields = event.fields_json.to_ascii_lowercase();
    fields.contains("\"ioc_match\":true")
        || fields.contains("\"sentinelblue_ioc_match\":true")
        || event.rule_name.to_ascii_lowercase().contains("ioc")
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    let normalized = value.to_ascii_lowercase();
    needles.iter().any(|needle| normalized.contains(needle))
}

fn time_bucket(event: &StoredNormalizedEvent) -> String {
    event
        .event_time
        .as_deref()
        .and_then(|time| time.get(..13))
        .unwrap_or("unknown-time")
        .to_string()
}

fn distinct_non_empty<'a>(values: impl Iterator<Item = &'a str>) -> HashSet<String> {
    values
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn encoded_ratio(label: &str) -> f64 {
    if label.is_empty() {
        return 0.0;
    }
    let encoded = label
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || *character == '-' || *character == '_'
        })
        .count();
    encoded as f64 / label.len() as f64
}

fn country(event: &StoredNormalizedEvent) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(&event.fields_json).ok()?;
    string_at(
        &value,
        &[
            &["country"],
            &["geo", "country"],
            &["geo", "country_name"],
            &["source", "geo", "country_name"],
            &["client", "geographicalContext", "country"],
            &["client", "geo", "country"],
        ],
    )
}

fn string_at(value: &serde_json::Value, paths: &[&[&str]]) -> Option<String> {
    paths.iter().find_map(|path| {
        let mut current = value;
        for segment in *path {
            current = current.get(*segment)?;
        }
        current.as_str().map(str::to_string)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_db::{NewNormalizedEvent, NewRawEvent};

    #[test]
    fn powershell_detector_finds_wazuh_and_sysmon_command_fields() {
        let detector = PowerShellEncodedCommandDetector;
        let events = vec![
            normalized_event(
                1,
                Some(10),
                "wazuh",
                "demo-host",
                "deploy",
                "",
                "powershell.exe -EncodedCommand redacted",
            ),
            normalized_event(
                2,
                Some(11),
                "sysmon",
                "win-host-01",
                "ACME\\alice",
                "powershell.exe",
                "powershell.exe -NoProfile -EncodedCommand redacted",
            ),
            normalized_event(
                3,
                Some(12),
                "sysmon",
                "win-host-02",
                "ACME\\bob",
                "cmd.exe",
                "cmd.exe /c whoami",
            ),
        ];

        let findings = detector.detect(&events);

        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|finding| finding.severity == "high"));
        assert!(findings.iter().all(|finding| {
            finding
                .attack
                .iter()
                .any(|attack| attack.technique_id == "T1059.001")
        }));
        assert_eq!(findings[0].evidence[0].raw_event_id, Some(10));
        assert_eq!(findings[1].evidence[0].normalized_event_id, 2);
    }

    #[test]
    fn default_detector_runner_executes_initial_detector_family() {
        let database = Database::open_initialized_memory().expect("database initializes");

        let reports = run_default_detectors(&database).expect("default detectors run");
        let detector_ids = reports
            .iter()
            .map(|report| report.detector_id.as_str())
            .collect::<HashSet<_>>();

        assert_eq!(reports.len(), 8);
        for expected in [
            "sentinelblue.detector.powershell_encoded_command",
            "sentinelblue.detector.sysmon_process_injection",
            "sentinelblue.detector.password_spray",
            "sentinelblue.detector.impossible_travel",
            "sentinelblue.detector.dns_tunneling",
            "sentinelblue.detector.dns_beaconing",
            "sentinelblue.detector.api_enumeration",
            "sentinelblue.detector.ioc_match",
        ] {
            assert!(detector_ids.contains(expected), "{expected}");
        }
        for report in reports {
            let run = database
                .detector_run_by_id(report.detector_run_id)
                .unwrap()
                .expect("run exists");
            assert_eq!(run.status, "completed");
        }
    }

    #[test]
    fn sysmon_process_injection_detector_finds_sensitive_process_access() {
        let mut event = normalized_event(
            10,
            Some(20),
            "sysmon",
            "win-host-01",
            "ACME\\alice",
            "procdump.exe",
            "procdump.exe -ma lsass.exe",
        );
        event.event_type = "process_access".to_string();
        event.rule_id = "sysmon-10".to_string();
        event.fields_json =
            r#"{"TargetImage":"C:\\Windows\\System32\\lsass.exe","GrantedAccess":"0x1fffff"}"#
                .to_string();

        let findings = SysmonProcessInjectionDetector.detect(&[event]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].attack[0].technique_id, "T1055");
        assert_eq!(findings[0].evidence[0].normalized_event_id, 10);
    }

    #[test]
    fn password_spray_detector_groups_failures_by_source_ip() {
        let events = (0..5)
            .map(|index| {
                let mut event = normalized_event(
                    index + 1,
                    Some(index + 100),
                    "identity",
                    "",
                    &format!("user{index}@example.com"),
                    "",
                    "",
                );
                event.event_type = "authentication".to_string();
                event.src_ip = "203.0.113.40".to_string();
                event.action = "FAILURE".to_string();
                event
            })
            .collect::<Vec<_>>();

        let findings = PasswordSprayDetector.detect(&events);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].attack[0].technique_id, "T1110.003");
        assert_eq!(findings[0].evidence.len(), 5);
    }

    #[test]
    fn impossible_travel_detector_groups_successes_by_user_and_country() {
        let mut first = normalized_event(1, Some(101), "identity", "", "alice@example.com", "", "");
        first.event_type = "authentication".to_string();
        first.src_ip = "198.51.100.10".to_string();
        first.action = "SUCCESS".to_string();
        first.fields_json = r#"{"client":{"geographicalContext":{"country":"US"}}}"#.to_string();

        let mut second =
            normalized_event(2, Some(102), "identity", "", "alice@example.com", "", "");
        second.event_type = "authentication".to_string();
        second.src_ip = "203.0.113.20".to_string();
        second.action = "SUCCESS".to_string();
        second.fields_json = r#"{"client":{"geographicalContext":{"country":"DE"}}}"#.to_string();

        let findings = ImpossibleTravelDetector.detect(&[first, second]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].attack[0].technique_id, "T1078");
        assert_eq!(findings[0].evidence.len(), 2);
    }

    #[test]
    fn dns_detectors_find_tunneling_and_beaconing_candidates() {
        let mut tunneling = normalized_event(1, Some(101), "zeek", "", "", "", "");
        tunneling.event_type = "dns_query".to_string();
        tunneling.src_ip = "10.0.0.5".to_string();
        tunneling.dns_query =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com"
                .to_string();

        let beacon_events = (0..3)
            .map(|index| {
                let mut event =
                    normalized_event(index + 10, Some(index + 200), "zeek", "", "", "", "");
                event.event_type = "dns_query".to_string();
                event.src_ip = "10.0.0.9".to_string();
                event.dns_query = "beacon.example.com".to_string();
                event
            })
            .collect::<Vec<_>>();

        let tunnel_findings = DnsTunnelingDetector.detect(&[tunneling]);
        let beacon_findings = DnsBeaconingDetector.detect(&beacon_events);

        assert_eq!(tunnel_findings.len(), 1);
        assert_eq!(tunnel_findings[0].attack[0].technique_id, "T1071.004");
        assert_eq!(beacon_findings.len(), 1);
        assert_eq!(beacon_findings[0].evidence.len(), 3);
    }

    #[test]
    fn api_enumeration_detector_groups_denied_paths() {
        let events = (0..5)
            .map(|index| {
                let mut event =
                    normalized_event(index + 1, Some(index + 100), "api-gateway", "", "", "", "");
                event.event_type = "api_request".to_string();
                event.src_ip = "203.0.113.55".to_string();
                event.http_method = "GET".to_string();
                event.url = format!("/v1/admin/object-{index}");
                event.status_code = Some(404);
                event
            })
            .collect::<Vec<_>>();

        let findings = ApiEnumerationDetector.detect(&events);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].attack[0].technique_id, "T1087");
        assert_eq!(findings[0].evidence.len(), 5);
    }

    #[test]
    fn ioc_match_detector_matches_configured_indicators() {
        let mut event = normalized_event(1, Some(101), "suricata", "", "", "", "");
        event.dest_ip = "198.51.100.77".to_string();
        event.dns_query = "evil.example".to_string();
        let detector = IocMatchDetector::with_indicators(
            ["198.51.100.77"],
            ["evil.example"],
            ["bbbbccccddddeeeeffff0000111122223333444455556666777788889999aaaa"],
        );

        let findings = detector.detect(&[event]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].attack[0].technique_id, "T1105");
        assert_eq!(findings[0].severity, "high");
    }

    #[test]
    fn run_detector_persists_run_alerts_and_evidence() {
        let database = Database::open_initialized_memory().expect("database initializes");
        let raw_event_id = database
            .insert_raw_event(NewRawEvent {
                source_id: None,
                source_product: "sysmon",
                event_time: Some("2026-06-10T01:00:00Z"),
                raw_payload: "{}",
                raw_hash: "hash-a",
                ingest_batch: "batch-a",
            })
            .expect("raw event inserts");
        let normalized_event_id = database
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
                command_line: "powershell.exe -NoProfile -EncodedCommand redacted",
                file_path: "",
                file_hash_sha256: "",
                rule_id: "sysmon-1",
                rule_name: "process_start",
                severity: "info",
                action: "",
                fields_json: "{}",
            })
            .expect("normalized event inserts");

        let report = run_detector(&database, &PowerShellEncodedCommandDetector)
            .expect("detector run succeeds");

        assert_eq!(report.scanned_events, 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.alerts_created, 1);
        assert_eq!(report.evidence_created, 1);
        assert_eq!(
            report.findings[0].evidence[0].raw_event_id,
            Some(raw_event_id)
        );
        assert_eq!(
            report.findings[0].evidence[0].normalized_event_id,
            normalized_event_id
        );

        let run = database
            .detector_run_by_id(report.detector_run_id)
            .unwrap()
            .expect("run exists");
        assert_eq!(run.status, "completed");
        assert_eq!(run.finding_count, 1);

        let alerts = database.list_alerts(10).expect("alerts list");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, "high");
        let evidence = database
            .evidence_for_alert(alerts[0].id)
            .expect("evidence lists");
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].raw_event_id, Some(raw_event_id));
        assert_eq!(evidence[0].normalized_event_id, Some(normalized_event_id));
    }

    #[test]
    fn run_detector_records_zero_findings_without_alerts() {
        let database = Database::open_initialized_memory().expect("database initializes");

        let report = run_detector(&database, &PowerShellEncodedCommandDetector)
            .expect("detector run succeeds");

        assert_eq!(report.scanned_events, 0);
        assert_eq!(report.findings.len(), 0);
        assert_eq!(report.alerts_created, 0);
        assert_eq!(report.evidence_created, 0);
        let run = database
            .detector_run_by_id(report.detector_run_id)
            .unwrap()
            .expect("run exists");
        assert_eq!(run.status, "completed");
        assert_eq!(run.finding_count, 0);
        assert!(database.list_alerts(10).unwrap().is_empty());
    }

    fn normalized_event(
        id: i64,
        raw_event_id: Option<i64>,
        source_product: &str,
        host: &str,
        user_name: &str,
        process_name: &str,
        command_line: &str,
    ) -> StoredNormalizedEvent {
        StoredNormalizedEvent {
            id,
            raw_event_id,
            event_time: Some("2026-06-10T01:00:00Z".to_string()),
            event_type: "process_start".to_string(),
            source_product: source_product.to_string(),
            host: host.to_string(),
            asset_id: String::new(),
            user_name: user_name.to_string(),
            user_id: String::new(),
            src_ip: String::new(),
            src_port: None,
            dest_ip: String::new(),
            dest_port: None,
            protocol: String::new(),
            dns_query: String::new(),
            http_method: String::new(),
            url: String::new(),
            status_code: None,
            process_name: process_name.to_string(),
            process_path: String::new(),
            parent_process_name: String::new(),
            command_line: command_line.to_string(),
            file_path: String::new(),
            file_hash_sha256: String::new(),
            rule_id: String::new(),
            rule_name: String::new(),
            severity: String::new(),
            action: String::new(),
            fields_json: "{}".to_string(),
        }
    }
}
