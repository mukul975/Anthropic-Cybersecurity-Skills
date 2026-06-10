# Local Development

Run these commands from `product/sentinelblue` unless noted otherwise.

## Rust

```bash
cargo test
cargo run -p sentinel-server -- --print-health
cargo run -p sentinel-server -- --print-health --database ./sentinelblue.dev.db
cargo run -p sentinel-server -- --import-file ./sample-data/wazuh-alert.sample.json --database ./sentinelblue.dev.db --source-name sample-wazuh --source-product wazuh
cargo run -p sentinel-server -- --run-detectors --database ./sentinelblue.dev.db
cargo run -p sentinel-server -- --promote-alert 1 --database ./sentinelblue.dev.db
cargo run -p sentinel-server -- --summarize-case 1 --database ./sentinelblue.dev.db
cargo run -p sentinel-server -- --summarize-case 1 --database ./sentinelblue.dev.db --model-endpoint http://127.0.0.1:8080 --model-name local-model
cargo run -p sentinel-server -- --close-case 1 --database ./sentinelblue.dev.db --disposition benign --notes "Confirmed approved administration"
cargo run -p sentinel-server -- --serve --database ./sentinelblue.dev.db
```

## Web

```bash
cd web
npm install
npm run build
npm run dev
```

The web dev server proxies `/api` to `http://127.0.0.1:8741`, which is the default `sentinel-server --serve` bind address.

## Desktop

```bash
cd apps/desktop
npm install
npm run tauri:dev
```

The desktop shell uses the shared web app from `web/`.
