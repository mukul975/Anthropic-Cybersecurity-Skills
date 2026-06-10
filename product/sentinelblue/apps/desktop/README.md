# SentinelBlue Desktop Shell

This directory contains the Tauri shell for SentinelBlue. The shell points to the shared web UI in `../../web` and uses registered Tauri commands for the local investigation workflow.

The desktop shell exposes narrow commands for selecting a local telemetry file, loading dashboard data, importing telemetry, running detectors, promoting alerts, summarizing cases, closing cases, and loading case timelines. These commands reuse the shared `sentinel-server` library with an app-data SQLite database, so the desktop workflow does not require a separately started HTTP server.

## Commands

```bash
npm install
npm run tauri:dev
npm run tauri:build
```

Verify the Tauri command bridge from the workspace root:

```bash
cargo check -p sentinelblue-desktop
```
