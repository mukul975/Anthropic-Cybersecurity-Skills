use tauri_plugin_dialog::DialogExt;

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

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![select_import_file])
        .run(tauri::generate_context!())
        .expect("failed to run SentinelBlue desktop shell");
}
