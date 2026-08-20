use std::{
    env,
    path::PathBuf,
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use sentinel_ingest::ImportFormat;
use sentinel_model::ModelRuntimeConfig;
use sentinel_server::{
    ServerConfig, case_json, case_summary_json, close_case_for_server, detection_reports_json,
    health_json, import_file_for_server, import_report_json, promote_alert_for_server,
    run_detectors_for_server, run_smoke_workflow, smoke_workflow_report_json, start_http_server,
    summarize_case_for_server,
};

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return;
    }

    let config = match parse_config(&args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            print_help();
            process::exit(2);
        }
    };

    if args.iter().any(|arg| arg == "--print-health") {
        println!("{}", health_json(&config));
        return;
    }

    if args.iter().any(|arg| arg == "--smoke-workflow") {
        let mut smoke_config = config;
        if smoke_config.database_path.is_none() {
            smoke_config.database_path = Some(default_smoke_database_path());
        }
        let sample_path = arg_value(&args, "--sample-file")
            .unwrap_or_else(|| "sample-data/wazuh-alert.sample.json".to_string());
        match run_smoke_workflow(&smoke_config, sample_path) {
            Ok(report) => {
                println!("{}", smoke_workflow_report_json(&report));
                return;
            }
            Err(error) => {
                eprintln!("smoke workflow failed: {error}");
                process::exit(1);
            }
        }
    }

    if args.iter().any(|arg| arg == "--run-detectors") {
        match run_detectors_for_server(&config) {
            Ok(reports) => {
                println!("{}", detection_reports_json(&reports));
                return;
            }
            Err(error) => {
                eprintln!("detector run failed: {error}");
                process::exit(1);
            }
        }
    }

    if let Some(alert_id) = arg_value(&args, "--promote-alert") {
        let alert_id = match alert_id.parse::<i64>() {
            Ok(alert_id) => alert_id,
            Err(_) => {
                eprintln!("--promote-alert requires an integer alert id");
                process::exit(2);
            }
        };
        let case_title = arg_value(&args, "--case-title");
        match promote_alert_for_server(&config, alert_id, case_title.as_deref()) {
            Ok(case) => {
                println!("{}", case_json(&case));
                return;
            }
            Err(error) => {
                eprintln!("case promotion failed: {error}");
                process::exit(1);
            }
        }
    }

    if let Some(case_id) = arg_value(&args, "--close-case") {
        let case_id = match case_id.parse::<i64>() {
            Ok(case_id) => case_id,
            Err(_) => {
                eprintln!("--close-case requires an integer case id");
                process::exit(2);
            }
        };
        let disposition = arg_value(&args, "--disposition").unwrap_or_default();
        let notes = arg_value(&args, "--notes").unwrap_or_default();
        match close_case_for_server(&config, case_id, &disposition, &notes) {
            Ok(case) => {
                println!("{}", case_json(&case));
                return;
            }
            Err(error) => {
                eprintln!("case close failed: {error}");
                process::exit(1);
            }
        }
    }

    if let Some(case_id) = arg_value(&args, "--summarize-case") {
        let case_id = match case_id.parse::<i64>() {
            Ok(case_id) => case_id,
            Err(_) => {
                eprintln!("--summarize-case requires an integer case id");
                process::exit(2);
            }
        };
        match summarize_case_for_server(&config, case_id) {
            Ok(summary) => {
                println!("{}", case_summary_json(&summary));
                return;
            }
            Err(error) => {
                eprintln!("case summary failed: {error}");
                process::exit(1);
            }
        }
    }

    if let Some(import_path) = arg_value(&args, "--import-file") {
        let source_name =
            arg_value(&args, "--source-name").unwrap_or_else(|| "manual-file".to_string());
        let source_product =
            arg_value(&args, "--source-product").unwrap_or_else(|| "custom".to_string());
        let format = match arg_value(&args, "--format").as_deref() {
            Some("json") => ImportFormat::Json,
            Some("jsonl") => ImportFormat::Jsonl,
            _ => ImportFormat::Auto,
        };
        match import_file_for_server(&config, import_path, source_name, source_product, format) {
            Ok(report) => {
                println!("{}", import_report_json(&report));
                return;
            }
            Err(error) => {
                eprintln!("import failed: {error}");
                process::exit(1);
            }
        }
    }

    eprintln!("starting sentinel-server on {}", config.bind_addr);
    if let Err(error) = start_http_server(&config) {
        eprintln!("server failed: {error}");
        process::exit(1);
    }
}

fn parse_config(args: &[String]) -> Result<ServerConfig, String> {
    let mut config = ServerConfig::default();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--print-health" | "--serve" | "--run-detectors" | "--smoke-workflow" => {
                index += 1;
            }
            "--import-file" | "--source-name" | "--source-product" | "--format"
            | "--promote-alert" | "--case-title" | "--close-case" | "--disposition" | "--notes"
            | "--summarize-case" | "--model-endpoint" | "--model-name" | "--sample-file" => {
                let _value = args
                    .get(index + 1)
                    .ok_or_else(|| format!("{} requires a value", args[index]))?;
                index += 2;
            }
            "--bind" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--bind requires an address".to_string())?;
                config.bind_addr = value.clone();
                index += 2;
            }
            "--database" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--database requires a path".to_string())?;
                config.database_path = Some(PathBuf::from(value));
                index += 2;
            }
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
    }
    if let Some(endpoint) = arg_value(args, "--model-endpoint") {
        let model_name =
            arg_value(args, "--model-name").unwrap_or_else(|| "local-model".to_string());
        config.model = ModelRuntimeConfig::openai_compatible(endpoint, model_name);
    }

    Ok(config)
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|window| window[0] == name)
        .map(|window| window[1].clone())
}

fn default_smoke_database_path() -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    env::temp_dir().join(format!(
        "sentinelblue-smoke-{}-{timestamp}.db",
        process::id()
    ))
}

fn print_help() {
    println!("sentinel-server");
    println!();
    println!("Usage:");
    println!("  sentinel-server --print-health");
    println!(
        "  sentinel-server --import-file ./alerts.json --database ./sentinelblue.db --source-product wazuh"
    );
    println!("  sentinel-server --run-detectors --database ./sentinelblue.db");
    println!("  sentinel-server --promote-alert 1 --database ./sentinelblue.db");
    println!(
        "  sentinel-server --close-case 1 --database ./sentinelblue.db --disposition benign --notes \"Reviewed evidence\""
    );
    println!(
        "  sentinel-server --summarize-case 1 --database ./sentinelblue.db [--model-endpoint http://127.0.0.1:8080 --model-name local-model]"
    );
    println!(
        "  sentinel-server --smoke-workflow [--database ./smoke.db] [--sample-file sample-data/wazuh-alert.sample.json]"
    );
    println!("  sentinel-server --serve [--bind 127.0.0.1:8741] [--database ./sentinelblue.db]");
    println!("  sentinel-server --help");
}
