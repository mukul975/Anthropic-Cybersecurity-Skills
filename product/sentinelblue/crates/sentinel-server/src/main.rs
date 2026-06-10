use std::{env, path::PathBuf, process};

use sentinel_ingest::ImportFormat;
use sentinel_server::{
    ServerConfig, detection_reports_json, health_json, import_file_for_server, import_report_json,
    run_detectors_for_server, start_http_server,
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
            "--print-health" | "--serve" | "--run-detectors" => {
                index += 1;
            }
            "--import-file" | "--source-name" | "--source-product" | "--format" => {
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

    Ok(config)
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|window| window[0] == name)
        .map(|window| window[1].clone())
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
    println!("  sentinel-server --serve [--bind 127.0.0.1:8741] [--database ./sentinelblue.db]");
    println!("  sentinel-server --help");
}
