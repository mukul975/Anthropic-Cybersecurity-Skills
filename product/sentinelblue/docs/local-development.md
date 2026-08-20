# Local Development

Run these commands from `product/sentinelblue` unless noted otherwise.

## Rust

```bash
cargo test
cargo run -p sentinel-server -- --print-health
cargo run -p sentinel-server -- --print-health --database ./sentinelblue.dev.db
cargo run -p sentinel-server -- --smoke-workflow
cargo run -p sentinel-server -- --import-file ./sample-data/wazuh-alert.sample.json --database ./sentinelblue.dev.db --source-name sample-wazuh --source-product wazuh
cargo run -p sentinel-server -- --run-detectors --database ./sentinelblue.dev.db
cargo run -p sentinel-server -- --promote-alert 1 --database ./sentinelblue.dev.db
cargo run -p sentinel-server -- --summarize-case 1 --database ./sentinelblue.dev.db
cargo run -p sentinel-server -- --summarize-case 1 --database ./sentinelblue.dev.db --model-endpoint http://127.0.0.1:8080 --model-name local-model
cargo run -p sentinel-server -- --close-case 1 --database ./sentinelblue.dev.db --disposition benign --notes "Confirmed approved administration"
cargo run -p sentinel-server -- --serve --database ./sentinelblue.dev.db
```

`--smoke-workflow` creates a disposable database when `--database` is omitted. It imports the sample Wazuh alert, runs detectors, promotes the alert, summarizes the case, closes the case, and validates timeline evidence.

## Web

```bash
cd web
npm install
npm run build
npm run dev
```

The web dev server proxies `/api` to `http://127.0.0.1:8741`, which is the default `sentinel-server --serve` bind address.

## Local API Mutations

Start the backend first:

```bash
cargo run -p sentinel-server -- --serve --database ./sentinelblue.dev.db
```

Then call the narrow local workflow routes:

```bash
curl -sS -X POST http://127.0.0.1:8741/api/import-file \
  -H 'Content-Type: application/json' \
  -d '{"path":"./sample-data/wazuh-alert.sample.json","source_name":"sample-wazuh","source_product":"wazuh","format":"auto"}'

curl -sS -X POST http://127.0.0.1:8741/api/detectors/run -d '{}'
curl -sS -X POST http://127.0.0.1:8741/api/alerts/1/promote -d '{}'
curl -sS -X POST http://127.0.0.1:8741/api/cases/1/summarize -d '{}'
curl -sS -X POST http://127.0.0.1:8741/api/cases/1/close \
  -H 'Content-Type: application/json' \
  -d '{"disposition":"benign","notes":"Confirmed approved administration"}'
```

## Desktop

```bash
cd apps/desktop
npm install
npm run tauri:dev
cargo check -p sentinelblue-desktop
```

The desktop shell uses the shared web app from `web/`. In Tauri, the web client uses narrow native commands backed by the shared SentinelBlue Rust crates and an app-data SQLite database. Browser-based web development still uses the local API server on `http://127.0.0.1:8741`.
