#!/usr/bin/env python3
"""Web Shell Detection - Analyzes process and file events for web shell indicators on web servers."""

import json, csv, argparse, datetime, re
from collections import defaultdict
from pathlib import Path

WEB_SERVER_PROCESSES = {"w3wp.exe", "httpd.exe", "nginx.exe", "apache.exe", "tomcat.exe", "java.exe", "php-cgi.exe", "node.exe"}
SUSPICIOUS_CHILDREN = {"cmd.exe", "powershell.exe", "bash", "sh", "whoami.exe", "net.exe", "net1.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe", "ping.exe", "nslookup.exe", "certutil.exe"}
WEBSHELL_EXTENSIONS = {".aspx", ".asp", ".php", ".jsp", ".jspx", ".cfm", ".ashx", ".asmx"}
WEB_DIRECTORIES = [r"\\inetpub\\", r"\\wwwroot\\", r"\\htdocs\\", r"\\webapps\\", r"\\www\\", r"\\html\\"]

def parse_logs(path):
    p = Path(path)
    if p.suffix == ".json":
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else data.get("events", [])
    elif p.suffix == ".csv":
        with open(p, encoding="utf-8-sig") as f:
            return [dict(r) for r in csv.DictReader(f)]
    return []

def detect_webshell_process(event):
    eid = str(event.get("EventCode", event.get("EventID", "")))
    if eid != "1": return None
    parent = (event.get("ParentImage", event.get("InitiatingProcessFileName", ""))).lower()
    image = (event.get("Image", event.get("FileName", ""))).lower()
    parent_name = parent.split("\\")[-1].split("/")[-1]
    image_name = image.split("\\")[-1].split("/")[-1]
    if parent_name not in WEB_SERVER_PROCESSES: return None
    if image_name not in SUSPICIOUS_CHILDREN: return None
    return {
        "detection_type": "WEBSHELL_PROCESS_SPAWN",
        "technique": "T1505.003",
        "web_server": parent_name, "child_process": image_name,
        "command_line": event.get("CommandLine", event.get("ProcessCommandLine", "")),
        "hostname": event.get("Computer", event.get("DeviceName", "unknown")),
        "user": event.get("User", event.get("AccountName", "unknown")),
        "timestamp": event.get("UtcTime", event.get("Timestamp", "")),
        "risk_score": 80, "risk_level": "CRITICAL",
        "indicators": [f"Web server {parent_name} spawned {image_name}"],
    }

def detect_webshell_file(event):
    eid = str(event.get("EventCode", event.get("EventID", "")))
    if eid != "11": return None
    target = event.get("TargetFilename", event.get("FolderPath", "")).lower()
    if not any(re.search(p, target, re.IGNORECASE) for p in WEB_DIRECTORIES): return None
    ext = "." + target.split(".")[-1] if "." in target else ""
    if ext not in WEBSHELL_EXTENSIONS: return None
    return {
        "detection_type": "WEBSHELL_FILE_CREATION",
        "technique": "T1505.003",
        "file_path": target, "extension": ext,
        "creating_process": event.get("Image", event.get("InitiatingProcessFileName", "")),
        "hostname": event.get("Computer", event.get("DeviceName", "unknown")),
        "timestamp": event.get("UtcTime", event.get("Timestamp", "")),
        "risk_score": 70, "risk_level": "HIGH",
        "indicators": [f"Web shell file created: {ext} in web directory"],
    }

def run_hunt(input_path, output_dir):
    print(f"[*] Web Shell Hunt - {datetime.datetime.now().isoformat()}")
    events = parse_logs(input_path)
    findings = []
    for e in events:
        r = detect_webshell_process(e)
        if r: findings.append(r)
        r = detect_webshell_file(e)
        if r: findings.append(r)
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    with open(Path(output_dir) / "webshell_findings.json", "w", encoding="utf-8") as f:
        json.dump({"hunt_id": f"TH-WEBSHELL-{datetime.date.today()}", "findings": findings}, f, indent=2)
    print(f"[+] {len(findings)} findings written to {output_dir}")

def main():
    p = argparse.ArgumentParser(description="Web Shell Detection")
    sp = p.add_subparsers(dest="cmd")
    h = sp.add_parser("hunt"); h.add_argument("--input", "-i", required=True); h.add_argument("--output", "-o", default="./webshell_output")
    sp.add_parser("queries")
    args = p.parse_args()
    if args.cmd == "hunt": run_hunt(args.input, args.output)
    elif args.cmd == "queries":
        print('''index=sysmon EventCode=1
| where match(ParentImage, "(?i)(w3wp|httpd|nginx|tomcat|java)\\.exe")
| where match(Image, "(?i)(cmd|powershell|whoami|net|ipconfig)\\.exe")
| table _time Computer ParentImage Image CommandLine''')
    else: p.print_help()

if __name__ == "__main__": main()
