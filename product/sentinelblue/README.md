# SentinelBlue Product Workspace

SentinelBlue is the product workspace for the local-first AI security monitoring app described in `docs/local-ai-security-app`.

## Workspace Layout

- `crates/`: Rust backend crates and the server binary.
- `web/`: Browser UI built with Vite and TypeScript.
- `apps/desktop/`: Tauri desktop shell that loads the web UI and talks to the backend.
- `packaging/`: Desktop, server, Docker, and systemd packaging assets.
- `sample-data/`: Small telemetry fixtures for development.
- `docs/`: Product workspace documentation.
- `models/`: Model manifest and bootstrap notes.

## Local Development

Run Rust tests:

```bash
cargo test
```

Run the server health smoke command:

```bash
cargo run -p sentinel-server -- --print-health
```

Run the server health smoke command with a real SQLite database file:

```bash
cargo run -p sentinel-server -- --print-health --database ./sentinelblue.dev.db
```

Import a local telemetry file:

```bash
cargo run -p sentinel-server -- \
  --import-file ./sample-data/wazuh-alert.sample.json \
  --database ./sentinelblue.dev.db \
  --source-name sample-wazuh \
  --source-product wazuh
```

Run deterministic detectors against normalized events:

```bash
cargo run -p sentinel-server -- --run-detectors --database ./sentinelblue.dev.db
```

Promote an alert into a case and close it after review:

```bash
cargo run -p sentinel-server -- --promote-alert 1 --database ./sentinelblue.dev.db
cargo run -p sentinel-server -- \
  --close-case 1 \
  --database ./sentinelblue.dev.db \
  --disposition benign \
  --notes "Confirmed approved administration"
```

Generate an evidence-cited case summary without requiring a model:

```bash
cargo run -p sentinel-server -- --summarize-case 1 --database ./sentinelblue.dev.db
```

Generate a case summary through a local OpenAI-compatible model endpoint:

```bash
cargo run -p sentinel-server -- \
  --summarize-case 1 \
  --database ./sentinelblue.dev.db \
  --model-endpoint http://127.0.0.1:8080 \
  --model-name local-model
```

Run the local HTTP API:

```bash
cargo run -p sentinel-server -- --serve --database ./sentinelblue.dev.db
```

Install web dependencies:

```bash
cd web
npm install
```

Build the web UI:

```bash
cd web
npm run build
```

Run the web UI during development:

```bash
cd web
npm run dev
```

The Vite dev server proxies `/api` to `sentinel-server` on `127.0.0.1:8741`, so keep the local API server running when using API-backed UI screens.

The UI can call local workflow routes for import, detector runs, alert promotion, case summaries, and case closure. See `docs/local-development.md` for curl examples.

Run the desktop shell after installing desktop dependencies:

```bash
cd apps/desktop
npm install
npm run tauri:dev
```
