use std::{fs, path::PathBuf};

use sentinel_ingest::ImportFormat;
use sentinel_server::{
    HttpResponse, ServerConfig, case_json, case_summary_json, close_case_for_server,
    detection_reports_json, import_file_for_server, import_report_json, promote_alert_for_server,
    route_get, run_detectors_for_server, summarize_case_for_server,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;

const DESKTOP_DATABASE_FILE: &str = "sentinelblue.db";

#[derive(Debug, Deserialize, Serialize)]
struct ImportTelemetryRequest {
    path: String,
    source_name: String,
    source_product: String,
    format: String,
}

#[derive(Debug, Deserialize)]
struct CaseIdRequest {
    case_id: String,
}

#[derive(Debug, Deserialize)]
struct PromoteAlertRequest {
    alert_id: String,
    title: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CloseCaseRequest {
    case_id: String,
    disposition: String,
    notes: String,
}

#[tauri::command]
fn select_import_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    app.dialog()
        .file()
        .add_filter("Telemetry", &["json", "jsonl", "log", "txt", "csv"])
        .blocking_pick_file()
        .map(|path| {
            path.into_path()
                .map(|path| path.to_string_lossy().to_string())
                .map_err(|error| error.to_string())
        })
        .transpose()
}

#[tauri::command]
fn desktop_load_dashboard_data(app: AppHandle) -> Result<Value, String> {
    let config = desktop_server_config(&app)?;
    let mut health = route_get_value(&config, "/api/health")?;
    add_desktop_health_component(&mut health);

    Ok(json!({
        "health": health,
        "skills": route_get_value(&config, "/api/skills?q=network")?,
        "events": route_get_value(&config, "/api/events")?,
        "alerts": route_get_value(&config, "/api/alerts")?,
        "cases": route_get_value(&config, "/api/cases")?,
    }))
}

#[tauri::command]
fn desktop_load_case_timeline(app: AppHandle, request: CaseIdRequest) -> Result<Value, String> {
    let case_id = parse_id(&request.case_id, "case_id")?;
    let config = desktop_server_config(&app)?;
    route_get_value(&config, &format!("/api/cases/{case_id}/timeline"))
}

#[tauri::command]
fn desktop_import_telemetry_file(
    app: AppHandle,
    request: ImportTelemetryRequest,
) -> Result<Value, String> {
    let import_path = non_empty(request.path, "path")?;
    let source_name = non_empty_or(request.source_name, "manual-file");
    let source_product = non_empty_or(request.source_product, "custom");
    let format = parse_import_format(&request.format)?;
    let config = desktop_server_config(&app)?;
    let report = import_file_for_server(&config, import_path, source_name, source_product, format)?;

    json_value(import_report_json(&report))
}

#[tauri::command]
fn desktop_run_detectors(app: AppHandle) -> Result<Value, String> {
    let config = desktop_server_config(&app)?;
    let reports = run_detectors_for_server(&config)?;

    json_value(detection_reports_json(&reports))
}

#[tauri::command]
fn desktop_promote_alert(app: AppHandle, request: PromoteAlertRequest) -> Result<Value, String> {
    let alert_id = parse_id(&request.alert_id, "alert_id")?;
    let title = request
        .title
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let config = desktop_server_config(&app)?;
    let case = promote_alert_for_server(&config, alert_id, title)?;

    json_value(case_json(&case))
}

#[tauri::command]
fn desktop_summarize_case(app: AppHandle, request: CaseIdRequest) -> Result<Value, String> {
    let case_id = parse_id(&request.case_id, "case_id")?;
    let config = desktop_server_config(&app)?;
    let summary = summarize_case_for_server(&config, case_id)?;

    json_value(case_summary_json(&summary))
}

#[tauri::command]
fn desktop_close_case(app: AppHandle, request: CloseCaseRequest) -> Result<Value, String> {
    let case_id = parse_id(&request.case_id, "case_id")?;
    let disposition = non_empty(request.disposition, "disposition")?;
    let notes = non_empty(request.notes, "notes")?;
    let config = desktop_server_config(&app)?;
    let case = close_case_for_server(&config, case_id, &disposition, &notes)?;

    json_value(case_json(&case))
}

fn desktop_server_config(app: &AppHandle) -> Result<ServerConfig, String> {
    let database_path = desktop_database_path(app)?;
    Ok(ServerConfig::default().with_database_path(database_path))
}

fn desktop_database_path(app: &AppHandle) -> Result<PathBuf, String> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    fs::create_dir_all(&data_dir).map_err(|error| error.to_string())?;
    Ok(data_dir.join(DESKTOP_DATABASE_FILE))
}

fn route_get_value(config: &ServerConfig, path: &str) -> Result<Value, String> {
    response_value(route_get(path, config), path)
}

fn response_value(response: HttpResponse, path: &str) -> Result<Value, String> {
    if response.status_code == 200 {
        return json_value(response.body);
    }

    let message = serde_json::from_str::<Value>(&response.body)
        .ok()
        .and_then(|body| {
            body.get("error")
                .and_then(|error| error.get("message"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("{path} returned {}", response.status_code));

    Err(message)
}

fn json_value(body: String) -> Result<Value, String> {
    serde_json::from_str(&body).map_err(|error| error.to_string())
}

fn add_desktop_health_component(health: &mut Value) {
    if let Some(object) = health.as_object_mut() {
        object.insert(
            "bind_addr".to_string(),
            Value::String("desktop-direct".to_string()),
        );
        if let Some(components) = object.get_mut("components").and_then(Value::as_array_mut) {
            components.push(json!({
                "name": "desktop-runtime",
                "status": "healthy",
                "detail": "direct Tauri commands use app data SQLite; no external backend required"
            }));
        }
    }
}

fn parse_id(value: &str, label: &str) -> Result<i64, String> {
    value
        .trim()
        .parse::<i64>()
        .map_err(|_| format!("{label} must be an integer"))
}

fn parse_import_format(value: &str) -> Result<ImportFormat, String> {
    match value.trim().to_lowercase().as_str() {
        "" | "auto" => Ok(ImportFormat::Auto),
        "json" => Ok(ImportFormat::Json),
        "jsonl" => Ok(ImportFormat::Jsonl),
        other => Err(format!("unsupported import format: {other}")),
    }
}

fn non_empty(value: String, label: &str) -> Result<String, String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(format!("{label} is required"));
    }
    Ok(value)
}

fn non_empty_or(value: String, default: &str) -> String {
    let value = value.trim().to_string();
    if value.is_empty() {
        default.to_string()
    } else {
        value
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            select_import_file,
            desktop_load_dashboard_data,
            desktop_load_case_timeline,
            desktop_import_telemetry_file,
            desktop_run_detectors,
            desktop_promote_alert,
            desktop_summarize_case,
            desktop_close_case
        ])
        .run(tauri::generate_context!())
        .expect("failed to run SentinelBlue desktop shell");
}
