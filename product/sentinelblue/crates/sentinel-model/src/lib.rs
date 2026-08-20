use std::{
    fmt,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

use sentinel_db::{CaseTimelineItem, StoredCase};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum ModelError {
    InvalidEndpoint(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint(endpoint) => {
                write!(formatter, "invalid model endpoint: {endpoint}")
            }
            Self::Io(error) => write!(formatter, "model I/O error: {error}"),
            Self::Json(error) => write!(formatter, "model JSON error: {error}"),
        }
    }
}

impl std::error::Error for ModelError {}

impl From<std::io::Error> for ModelError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for ModelError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub type Result<T> = std::result::Result<T, ModelError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelRuntimeMode {
    DeterministicOnly,
    OpenAiCompatible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRuntimeConfig {
    pub mode: ModelRuntimeMode,
    pub endpoint_url: Option<String>,
    pub model_name: String,
    pub request_timeout_ms: u64,
}

impl Default for ModelRuntimeConfig {
    fn default() -> Self {
        Self::deterministic_only()
    }
}

impl ModelRuntimeConfig {
    pub fn deterministic_only() -> Self {
        Self {
            mode: ModelRuntimeMode::DeterministicOnly,
            endpoint_url: None,
            model_name: "deterministic-case-summary".to_string(),
            request_timeout_ms: 750,
        }
    }

    pub fn openai_compatible(
        endpoint_url: impl Into<String>,
        model_name: impl Into<String>,
    ) -> Self {
        Self {
            mode: ModelRuntimeMode::OpenAiCompatible,
            endpoint_url: Some(endpoint_url.into()),
            model_name: model_name.into(),
            request_timeout_ms: 1_500,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelHealthStatus {
    Loading,
    Ready,
    Degraded,
    Unavailable,
    Disabled,
}

impl ModelHealthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loading => "loading",
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelHealth {
    pub status: ModelHealthStatus,
    pub detail: String,
    pub ai_enabled: bool,
}

impl ModelHealth {
    pub fn new(status: ModelHealthStatus, detail: impl Into<String>) -> Self {
        Self {
            ai_enabled: status == ModelHealthStatus::Ready,
            status,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseSummaryPrompt {
    pub system: String,
    pub user: String,
    pub redaction_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseSummaryResult {
    pub case_id: i64,
    pub mode: String,
    pub model_name: String,
    pub model_health_status: String,
    pub ai_attempted: bool,
    pub prompt_hash: String,
    pub prompt: CaseSummaryPrompt,
    pub summary: String,
    pub claims: Vec<SummaryClaim>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryClaim {
    pub text: String,
    pub evidence_ids: Vec<i64>,
    pub inference: bool,
}

pub fn check_model_health(config: &ModelRuntimeConfig) -> ModelHealth {
    match config.mode {
        ModelRuntimeMode::DeterministicOnly => ModelHealth::new(
            ModelHealthStatus::Disabled,
            "deterministic-only mode; local AI calls disabled",
        ),
        ModelRuntimeMode::OpenAiCompatible => {
            let Some(endpoint) = &config.endpoint_url else {
                return ModelHealth::new(
                    ModelHealthStatus::Unavailable,
                    "OpenAI-compatible mode requires --model-endpoint",
                );
            };
            let parsed = match HttpEndpoint::parse(endpoint) {
                Ok(parsed) => parsed,
                Err(error) => {
                    return ModelHealth::new(
                        ModelHealthStatus::Degraded,
                        format!("{error}; only plain http local endpoints are supported"),
                    );
                }
            };
            match http_request(&parsed, "GET", "/health", None, config.request_timeout_ms) {
                Ok(response) => classify_health_response(response.status_code, &response.body),
                Err(error) => ModelHealth::new(
                    ModelHealthStatus::Unavailable,
                    format!("model endpoint unavailable: {error}"),
                ),
            }
        }
    }
}

pub fn classify_health_response(status_code: u16, body: &str) -> ModelHealth {
    let lowered = body.to_ascii_lowercase();
    match status_code {
        200 => ModelHealth::new(ModelHealthStatus::Ready, "model endpoint reports ready"),
        202 => ModelHealth::new(ModelHealthStatus::Loading, "model endpoint is loading"),
        503 if lowered.contains("loading") => {
            ModelHealth::new(ModelHealthStatus::Loading, "model endpoint is loading")
        }
        500..=599 => ModelHealth::new(
            ModelHealthStatus::Unavailable,
            format!("model endpoint returned HTTP {status_code}"),
        ),
        _ => ModelHealth::new(
            ModelHealthStatus::Degraded,
            format!("model endpoint returned HTTP {status_code}"),
        ),
    }
}

pub fn build_case_summary_prompt(
    case: &StoredCase,
    timeline: &[CaseTimelineItem],
) -> CaseSummaryPrompt {
    let system = "You are SentinelBlue's local case summarizer. Cite evidence IDs for every factual claim. Mark any unsupported reasoning as inference. Do not expose secrets.".to_string();
    let mut redaction_count = 0;
    let evidence_lines = if timeline.is_empty() {
        "No case evidence is available.".to_string()
    } else {
        timeline
            .iter()
            .map(|item| {
                let redacted = redact_secret_like_values(&item.summary);
                redaction_count += redacted.redaction_count;
                format!(
                    "- evidence_id={} type={} time={} raw_event_id={} normalized_event_id={} summary={}",
                    item.item_id,
                    item.item_type,
                    item.timeline_time,
                    option_id(item.raw_event_id),
                    option_id(item.normalized_event_id),
                    redacted.text
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let user_raw = format!(
        "Case #{case_id}: {title}\nStatus: {status}\nSeverity: {severity}\nConfidence: {confidence}\nDisposition: {disposition}\n\nEvidence timeline:\n{evidence_lines}\n\nReturn JSON with summary and claims. Each claim must include evidence_ids or inference=true.",
        case_id = case.id,
        title = case.title,
        status = case.status,
        severity = case.severity,
        confidence = case.confidence,
        disposition = case.disposition,
    );
    let redacted_user = redact_secret_like_values(&user_raw);
    redaction_count += redacted_user.redaction_count;

    CaseSummaryPrompt {
        system,
        user: redacted_user.text,
        redaction_count,
    }
}

pub fn summarize_case(
    config: &ModelRuntimeConfig,
    case: &StoredCase,
    timeline: &[CaseTimelineItem],
) -> Result<CaseSummaryResult> {
    let prompt = build_case_summary_prompt(case, timeline);
    let health = check_model_health(config);
    let prompt_hash = prompt_hash(&prompt);

    if config.mode == ModelRuntimeMode::OpenAiCompatible
        && health.status == ModelHealthStatus::Ready
    {
        let ai_text = call_openai_compatible(config, &prompt)?;
        return Ok(CaseSummaryResult {
            case_id: case.id,
            mode: "openai-compatible".to_string(),
            model_name: config.model_name.clone(),
            model_health_status: health.status.as_str().to_string(),
            ai_attempted: true,
            prompt_hash,
            prompt,
            summary: ai_text.clone(),
            claims: vec![SummaryClaim {
                text: ai_text,
                evidence_ids: Vec::new(),
                inference: true,
            }],
        });
    }

    Ok(deterministic_summary_result(
        config,
        case,
        timeline,
        prompt,
        health,
        prompt_hash,
    ))
}

pub fn deterministic_summary_result(
    config: &ModelRuntimeConfig,
    case: &StoredCase,
    timeline: &[CaseTimelineItem],
    prompt: CaseSummaryPrompt,
    health: ModelHealth,
    prompt_hash: String,
) -> CaseSummaryResult {
    let cited_items = timeline
        .iter()
        .filter(|item| {
            matches!(
                item.item_type.as_str(),
                "normalized_event" | "detector_alert" | "analyst_note" | "model_summary" | "action"
            )
        })
        .collect::<Vec<_>>();
    let summary = if cited_items.is_empty() {
        format!(
            "Case {} has no evidence timeline entries available. Treat any assessment as inference.",
            case.id
        )
    } else {
        let ids = cited_items
            .iter()
            .map(|item| format!("#{}", item.item_id))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "Case {} is in '{}' status with '{}' severity. Summary is based on evidence {}.",
            case.id, case.status, case.severity, ids
        )
    };
    let claims = if cited_items.is_empty() {
        vec![SummaryClaim {
            text: "No evidence-backed claims can be made from this case timeline.".to_string(),
            evidence_ids: Vec::new(),
            inference: true,
        }]
    } else {
        cited_items
            .iter()
            .map(|item| SummaryClaim {
                text: format!("Timeline item {} records {}.", item.item_id, item.item_type),
                evidence_ids: vec![item.item_id],
                inference: false,
            })
            .collect()
    };

    CaseSummaryResult {
        case_id: case.id,
        mode: "deterministic-only".to_string(),
        model_name: config.model_name.clone(),
        model_health_status: health.status.as_str().to_string(),
        ai_attempted: false,
        prompt_hash,
        prompt,
        summary,
        claims,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionResult {
    pub text: String,
    pub redaction_count: usize,
}

pub fn redact_secret_like_values(input: &str) -> RedactionResult {
    let mut redaction_count = 0;
    let tokens = input.split_whitespace().collect::<Vec<_>>();
    let mut redacted_tokens = Vec::with_capacity(tokens.len());
    let mut index = 0;

    while index < tokens.len() {
        if tokens[index].eq_ignore_ascii_case("bearer") && index + 1 < tokens.len() {
            redacted_tokens.push(tokens[index].to_string());
            redacted_tokens.push(format!(
                "[REDACTED]{}",
                trailing_punctuation(tokens[index + 1])
            ));
            redaction_count += 1;
            index += 2;
        } else {
            let token = tokens[index];
            let redacted = redact_token(token);
            if redacted != token {
                redaction_count += 1;
            }
            redacted_tokens.push(redacted);
            index += 1;
        }
    }

    RedactionResult {
        text: redacted_tokens.join(" "),
        redaction_count,
    }
}

fn redact_token(token: &str) -> String {
    let lowered = token.to_ascii_lowercase();
    let secret_markers = [
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "auth_token",
        "password",
        "passwd",
        "secret",
        "authorization",
    ];
    if !secret_markers.iter().any(|marker| lowered.contains(marker)) {
        return token.to_string();
    }

    for separator in ['=', ':'] {
        if let Some(index) = token.find(separator) {
            let prefix = &token[..=index];
            let suffix = trailing_punctuation(&token[index + 1..]);
            return format!("{prefix}[REDACTED]{suffix}");
        }
    }
    "[REDACTED]".to_string()
}

fn trailing_punctuation(value: &str) -> &str {
    let mut suffix_start = value.len();
    for (index, character) in value.char_indices().rev() {
        if character.is_ascii_alphanumeric()
            || matches!(character, '-' | '_' | '.' | '/' | '+' | '=')
        {
            break;
        }
        suffix_start = index;
    }
    &value[suffix_start..]
}

fn option_id(value: Option<i64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string())
}

pub fn prompt_hash(prompt: &CaseSummaryPrompt) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prompt.system.as_bytes());
    hasher.update(b"\0");
    hasher.update(prompt.user.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn call_openai_compatible(
    config: &ModelRuntimeConfig,
    prompt: &CaseSummaryPrompt,
) -> Result<String> {
    let endpoint = config
        .endpoint_url
        .as_deref()
        .ok_or_else(|| ModelError::InvalidEndpoint("missing endpoint".to_string()))?;
    let parsed = HttpEndpoint::parse(endpoint)?;
    let request = serde_json::json!({
        "model": config.model_name,
        "messages": [
            {"role": "system", "content": prompt.system},
            {"role": "user", "content": prompt.user}
        ],
        "temperature": 0.0,
        "stream": false
    });
    let response = http_request(
        &parsed,
        "POST",
        "/v1/chat/completions",
        Some(&request.to_string()),
        config.request_timeout_ms,
    )?;
    if !(200..300).contains(&response.status_code) {
        return Err(ModelError::InvalidEndpoint(format!(
            "model endpoint returned HTTP {}",
            response.status_code
        )));
    }
    let value: serde_json::Value = serde_json::from_str(&response.body)?;
    let content = value
        .get("choices")
        .and_then(|choices| choices.get(0))
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(|content| content.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if content.is_empty() {
        return Err(ModelError::InvalidEndpoint(
            "model response did not include choices[0].message.content".to_string(),
        ));
    }
    Ok(content)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpEndpoint {
    host: String,
    port: u16,
}

impl HttpEndpoint {
    fn parse(endpoint: &str) -> Result<Self> {
        let without_scheme = endpoint
            .strip_prefix("http://")
            .ok_or_else(|| ModelError::InvalidEndpoint(endpoint.to_string()))?;
        let host_port = without_scheme
            .split('/')
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ModelError::InvalidEndpoint(endpoint.to_string()))?;
        let (host, port) = match host_port.rsplit_once(':') {
            Some((host, port)) => {
                let port = port
                    .parse::<u16>()
                    .map_err(|_| ModelError::InvalidEndpoint(endpoint.to_string()))?;
                (host.to_string(), port)
            }
            None => (host_port.to_string(), 80),
        };
        Ok(Self { host, port })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpResponse {
    status_code: u16,
    body: String,
}

fn http_request(
    endpoint: &HttpEndpoint,
    method: &str,
    path: &str,
    body: Option<&str>,
    timeout_ms: u64,
) -> Result<HttpResponse> {
    let timeout = Duration::from_millis(timeout_ms.max(100));
    let address = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| {
            ModelError::InvalidEndpoint(format!("{}:{}", endpoint.host, endpoint.port))
        })?;
    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let body = body.unwrap_or("");
    let content_headers = if body.is_empty() {
        String::new()
    } else {
        format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )
    };
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\n{content_headers}Connection: close\r\n\r\n{body}",
        host = endpoint.host,
    );
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .unwrap_or((response.as_str(), ""));
    let status_code = head
        .lines()
        .next()
        .and_then(|status| status.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .unwrap_or(0);
    Ok(HttpResponse {
        status_code,
        body: body.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, thread};

    fn test_case() -> StoredCase {
        StoredCase {
            id: 42,
            title: "Suspicious PowerShell encoded command".to_string(),
            status: "triage".to_string(),
            severity: "high".to_string(),
            confidence: "0.86".to_string(),
            disposition: String::new(),
            closed_at: None,
        }
    }

    fn timeline(summary: &str) -> Vec<CaseTimelineItem> {
        vec![CaseTimelineItem {
            item_type: "normalized_event".to_string(),
            item_id: 7,
            case_id: 42,
            alert_id: Some(3),
            raw_event_id: Some(1),
            normalized_event_id: Some(2),
            summary: summary.to_string(),
            timeline_time: "2026-06-10T01:00:00Z".to_string(),
        }]
    }

    #[test]
    fn health_classifier_reports_required_states() {
        assert_eq!(
            classify_health_response(200, "{}").status,
            ModelHealthStatus::Ready
        );
        assert_eq!(
            classify_health_response(202, "{}").status,
            ModelHealthStatus::Loading
        );
        assert_eq!(
            classify_health_response(429, "{}").status,
            ModelHealthStatus::Degraded
        );
        assert_eq!(
            classify_health_response(500, "{}").status,
            ModelHealthStatus::Unavailable
        );
    }

    #[test]
    fn deterministic_only_health_disables_ai() {
        let health = check_model_health(&ModelRuntimeConfig::deterministic_only());

        assert_eq!(health.status, ModelHealthStatus::Disabled);
        assert!(!health.ai_enabled);
    }

    #[test]
    fn prompt_redacts_secret_like_values() {
        let case = test_case();
        let prompt = build_case_summary_prompt(
            &case,
            &timeline("Authorization: Bearer abc123 password=secret api_key:sk-local"),
        );

        assert!(prompt.redaction_count >= 3);
        assert!(!prompt.user.contains("abc123"));
        assert!(!prompt.user.contains("secret"));
        assert!(!prompt.user.contains("sk-local"));
        assert!(prompt.user.contains("[REDACTED]"));
    }

    #[test]
    fn deterministic_summary_cites_evidence_ids() {
        let result = summarize_case(
            &ModelRuntimeConfig::deterministic_only(),
            &test_case(),
            &timeline("Encoded PowerShell evidence"),
        )
        .expect("summary succeeds");

        assert!(!result.ai_attempted);
        assert_eq!(result.mode, "deterministic-only");
        assert!(result.summary.contains("#7"));
        assert!(
            result
                .claims
                .iter()
                .all(|claim| claim.inference || !claim.evidence_ids.is_empty())
        );
        assert_eq!(result.claims[0].evidence_ids, vec![7]);
    }

    #[test]
    fn unavailable_model_does_not_attempt_ai_generation() {
        let mut config = ModelRuntimeConfig::openai_compatible("http://127.0.0.1:1", "local-model");
        config.request_timeout_ms = 100;

        let result = summarize_case(&config, &test_case(), &timeline("Evidence"))
            .expect("summary falls back deterministically");

        assert!(!result.ai_attempted);
        assert_eq!(result.model_health_status, "unavailable");
        assert_eq!(result.mode, "deterministic-only");
    }

    #[test]
    fn ready_openai_compatible_endpoint_can_generate_summary() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener binds");
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for index in 0..2 {
                let (mut stream, _) = listener.accept().expect("connection accepts");
                let mut buffer = [0_u8; 4096];
                let read = stream.read(&mut buffer).expect("request reads");
                let request = String::from_utf8_lossy(&buffer[..read]);
                let body = if index == 0 && request.starts_with("GET /health") {
                    "{}".to_string()
                } else {
                    r#"{"choices":[{"message":{"content":"AI draft summary. Evidence [7]."}}]}"#
                        .to_string()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("response writes");
            }
        });

        let mut config = ModelRuntimeConfig::openai_compatible(
            format!("http://127.0.0.1:{port}"),
            "local-model",
        );
        config.request_timeout_ms = 1_000;
        let result = summarize_case(&config, &test_case(), &timeline("Evidence"))
            .expect("AI summary succeeds");

        assert!(result.ai_attempted);
        assert_eq!(result.model_health_status, "ready");
        assert_eq!(result.summary, "AI draft summary. Evidence [7].");
        assert!(result.claims[0].inference);
    }
}
