# SentinelBlue Desktop Shell

This directory contains the Tauri shell for SentinelBlue. The shell points to the shared web UI in `../../web` and will call backend APIs or Tauri commands as product goals add those surfaces.

The desktop shell exposes one narrow command today: selecting a local telemetry file path for import. Investigation workflow execution still goes through the local SentinelBlue HTTP API.

## Commands

```bash
npm install
npm run tauri:dev
npm run tauri:build
```

Run the backend before starting desktop development:

```bash
cd ../..
cargo run -p sentinel-server -- --serve --database ./sentinelblue.dev.db
```

Verify the Tauri command bridge from the workspace root:

```bash
cargo check -p sentinelblue-desktop
```
