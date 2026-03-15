#!/usr/bin/env python3
"""IBM QRadar SIEM correlation and offense management agent."""

import json
import sys
import urllib.request
import urllib.parse
import ssl
from datetime import datetime


class QRadarClient:
    """Client for QRadar REST API operations."""

    def __init__(self, host, api_token, verify_ssl=False):
        self.base_url = f"https://{host}/api"
        self.headers = {
            "SEC": api_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.ctx = ssl.create_default_context()
        if not verify_ssl:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method, endpoint, data=None):
        url = f"{self.base_url}/{endpoint}"
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=self.headers, method=method)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=60) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return {"error": e.code, "message": e.read().decode()}
        except Exception as e:
            return {"error": str(e)}

    def search_aql(self, query):
        """Execute an AQL query and return results."""
        encoded = urllib.parse.quote(query)
        result = self._request("POST", f"ariel/searches?query_expression={encoded}")
        if "error" in result:
            return result
        search_id = result.get("search_id")
        if not search_id:
            return result
        import time
        for _ in range(30):
            status = self._request("GET", f"ariel/searches/{search_id}")
            if status.get("status") == "COMPLETED":
                return self._request("GET", f"ariel/searches/{search_id}/results")
            time.sleep(2)
        return {"error": "AQL query timed out"}

    def get_offenses(self, status_filter="OPEN", limit=50):
        """Retrieve offenses filtered by status."""
        params = f"?filter=status%3D%22{status_filter}%22&Range=items%3D0-{limit-1}"
        return self._request("GET", f"siem/offenses{params}")

    def get_offense_details(self, offense_id):
        """Get detailed information about a specific offense."""
        return self._request("GET", f"siem/offenses/{offense_id}")

    def close_offense(self, offense_id, closing_reason_id, note="Closed by automation"):
        """Close an offense with a reason and note."""
        params = f"?closing_reason_id={closing_reason_id}&status=CLOSED"
        result = self._request("POST", f"siem/offenses/{offense_id}{params}")
        if "error" not in result:
            self.add_note(offense_id, note)
        return result

    def add_note(self, offense_id, note_text):
        """Add an investigation note to an offense."""
        data = {"note_text": note_text}
        return self._request("POST", f"siem/offenses/{offense_id}/notes", data)

    def get_reference_set(self, name):
        """Retrieve a reference set and its entries."""
        encoded = urllib.parse.quote(name)
        return self._request("GET", f"reference_data/sets/{encoded}")

    def add_to_reference_set(self, name, value):
        """Add a value to a reference set."""
        encoded = urllib.parse.quote(name)
        return self._request("POST", f"reference_data/sets/{encoded}?value={urllib.parse.quote(value)}")

    def create_reference_set(self, name, element_type="IP", ttl="30 days"):
        """Create a new reference set."""
        data = {
            "name": name,
            "element_type": element_type,
            "timeout_type": "LAST_SEEN",
            "time_to_live": ttl,
        }
        return self._request("POST", "reference_data/sets", data)

    def get_rules(self, limit=50):
        """List custom rules."""
        return self._request("GET", f"analytics/rules?Range=items%3D0-{limit-1}")


def brute_force_aql(client, hours=24):
    """AQL query to detect brute force followed by success."""
    query = f"""
    SELECT sourceIP, destinationIP, username,
           QIDNAME(qid) AS event_name, COUNT(*) as cnt
    FROM events
    WHERE category = 'Authentication'
      AND QIDNAME(qid) ILIKE '%fail%'
      AND startTime > NOW() - {hours}*60*60*1000
    GROUP BY sourceIP, destinationIP, username, qid
    HAVING COUNT(*) > 10
    ORDER BY cnt DESC
    LIMIT 50
    """
    return client.search_aql(query)


def lateral_movement_aql(client, hours=24):
    """AQL query to detect lateral movement patterns."""
    query = f"""
    SELECT sourceIP, COUNT(DISTINCT destinationIP) as dest_count,
           COUNT(*) as event_count, username
    FROM events
    WHERE category = 'Authentication'
      AND sourceIP NOT IN (SELECT ip FROM reference_data.sets('Domain_Controllers'))
      AND startTime > NOW() - {hours}*60*60*1000
    GROUP BY sourceIP, username
    HAVING COUNT(DISTINCT destinationIP) > 5
    ORDER BY dest_count DESC
    LIMIT 30
    """
    return client.search_aql(query)


def generate_report(client):
    """Generate a QRadar offense summary report."""
    offenses = client.get_offenses("OPEN", 100)
    if isinstance(offenses, dict) and "error" in offenses:
        return offenses
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "open_offenses": len(offenses) if isinstance(offenses, list) else 0,
        "offenses": offenses[:20] if isinstance(offenses, list) else offenses,
    }


if __name__ == "__main__":
    import os
    host = os.environ.get("QRADAR_HOST", "qradar.example.com")
    token = os.environ.get("QRADAR_TOKEN", "")
    if not token:
        print("Set QRADAR_HOST and QRADAR_TOKEN environment variables")
        sys.exit(1)

    client = QRadarClient(host, token)
    action = sys.argv[1] if len(sys.argv) > 1 else "report"

    if action == "report":
        print(json.dumps(generate_report(client), indent=2))
    elif action == "offenses":
        print(json.dumps(client.get_offenses(), indent=2))
    elif action == "offense" and len(sys.argv) > 2:
        print(json.dumps(client.get_offense_details(sys.argv[2]), indent=2))
    elif action == "brute-force":
        print(json.dumps(brute_force_aql(client), indent=2))
    elif action == "lateral-movement":
        print(json.dumps(lateral_movement_aql(client), indent=2))
    elif action == "aql" and len(sys.argv) > 2:
        print(json.dumps(client.search_aql(" ".join(sys.argv[2:])), indent=2))
    else:
        print("Usage: agent.py [report|offenses|offense <id>|brute-force|lateral-movement|aql <query>]")
