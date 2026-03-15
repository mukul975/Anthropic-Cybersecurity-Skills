#!/usr/bin/env python3
"""Agent for threat modeling with OWASP Threat Dragon.

Programmatically creates Threat Dragon JSON threat models, applies
STRIDE analysis to DFD elements, manages threat inventory, and
generates summary reports for security design reviews.
"""

import json
import sys
import uuid
from datetime import datetime
from pathlib import Path


STRIDE_BY_ELEMENT = {
    "process": ["Spoofing", "Tampering", "Repudiation",
                "Information Disclosure", "Denial of Service",
                "Elevation of Privilege"],
    "data_store": ["Tampering", "Information Disclosure",
                   "Denial of Service"],
    "data_flow": ["Tampering", "Information Disclosure",
                  "Denial of Service"],
    "external_entity": ["Spoofing", "Repudiation"],
}

STRIDE_MITIGATIONS = {
    "Spoofing": ["Implement strong authentication (MFA)",
                 "Use mutual TLS for service-to-service"],
    "Tampering": ["Use integrity checks (HMAC, digital signatures)",
                  "Implement input validation"],
    "Repudiation": ["Enable comprehensive audit logging",
                    "Use tamper-evident log storage"],
    "Information Disclosure": ["Encrypt data at rest and in transit",
                               "Implement least-privilege access"],
    "Denial of Service": ["Implement rate limiting",
                          "Use auto-scaling and circuit breakers"],
    "Elevation of Privilege": ["Enforce RBAC and least privilege",
                               "Validate authorization on every request"],
}


class ThreatModelAgent:
    """Creates and manages OWASP Threat Dragon threat models."""

    def __init__(self, title, owner="Security Team", description=""):
        self.model = {
            "version": "2.2.0",
            "summary": {
                "title": title,
                "owner": owner,
                "description": description,
                "id": 0,
            },
            "detail": {
                "contributors": [],
                "diagrams": [],
                "diagramTop": 0,
                "reviewer": "",
                "threatTop": 0,
            },
        }
        self.threats = []
        self.threat_counter = 0

    def add_diagram(self, title, diagram_type="STRIDE"):
        """Add a new data flow diagram to the threat model."""
        diagram_id = len(self.model["detail"]["diagrams"])
        diagram = {
            "id": diagram_id,
            "title": title,
            "diagramType": diagram_type,
            "placeholder": f"New {diagram_type} diagram",
            "thumbnail": "",
            "version": "2.2.0",
            "cells": [],
        }
        self.model["detail"]["diagrams"].append(diagram)
        return diagram_id

    def add_element(self, diagram_id, element_type, name,
                    x=100, y=100, description=""):
        """Add a DFD element to a diagram."""
        element_id = str(uuid.uuid4())
        type_map = {
            "process": "tm.Process",
            "data_store": "tm.Store",
            "data_flow": "tm.Flow",
            "external_entity": "tm.Actor",
            "trust_boundary": "tm.Boundary",
        }
        cell = {
            "type": type_map.get(element_type, "tm.Process"),
            "id": element_id,
            "name": name,
            "description": description,
            "position": {"x": x, "y": y},
            "size": {"width": 100, "height": 60},
            "threats": [],
            "hasOpenThreats": False,
        }
        self.model["detail"]["diagrams"][diagram_id]["cells"].append(cell)
        return element_id

    def apply_stride(self, diagram_id, element_id, element_type):
        """Apply STRIDE analysis to a DFD element and generate threats."""
        categories = STRIDE_BY_ELEMENT.get(element_type, [])
        generated = []
        diagram = self.model["detail"]["diagrams"][diagram_id]
        element = next((c for c in diagram["cells"] if c["id"] == element_id), None)
        if not element:
            return []

        for category in categories:
            self.threat_counter += 1
            threat = {
                "id": str(self.threat_counter),
                "title": f"{category} - {element['name']}",
                "type": category,
                "status": "Open",
                "severity": "Medium",
                "description": f"Potential {category.lower()} threat "
                               f"against {element['name']}",
                "mitigation": "; ".join(
                    STRIDE_MITIGATIONS.get(category, ["Review required"])),
                "modelType": "STRIDE",
                "element_id": element_id,
            }
            element["threats"].append(threat)
            element["hasOpenThreats"] = True
            self.threats.append(threat)
            generated.append(threat)

        self.model["detail"]["threatTop"] = self.threat_counter
        return generated

    def update_threat_status(self, threat_id, status, mitigation=None):
        """Update a threat's status (Open, Mitigated, Not Applicable)."""
        for threat in self.threats:
            if threat["id"] == str(threat_id):
                threat["status"] = status
                if mitigation:
                    threat["mitigation"] = mitigation
                return threat
        return None

    def get_threat_summary(self):
        """Summarize threats by status and category."""
        summary = {"total": len(self.threats), "by_status": {},
                   "by_type": {}, "by_severity": {}}
        for t in self.threats:
            summary["by_status"][t["status"]] = \
                summary["by_status"].get(t["status"], 0) + 1
            summary["by_type"][t["type"]] = \
                summary["by_type"].get(t["type"], 0) + 1
            summary["by_severity"][t["severity"]] = \
                summary["by_severity"].get(t["severity"], 0) + 1
        return summary

    def save_model(self, output_path):
        """Save the threat model as Threat Dragon JSON file."""
        with open(output_path, "w") as f:
            json.dump(self.model, f, indent=2)
        return output_path

    def generate_report(self):
        """Generate threat model assessment report."""
        summary = self.get_threat_summary()
        report = {
            "title": self.model["summary"]["title"],
            "owner": self.model["summary"]["owner"],
            "report_date": datetime.utcnow().isoformat(),
            "diagrams": len(self.model["detail"]["diagrams"]),
            "threat_summary": summary,
            "open_threats": [t for t in self.threats if t["status"] == "Open"],
            "mitigated_threats": [t for t in self.threats
                                  if t["status"] == "Mitigated"],
        }
        print(json.dumps(report, indent=2))
        return report


def main():
    title = sys.argv[1] if len(sys.argv) > 1 else "Sample Application"
    output = sys.argv[2] if len(sys.argv) > 2 else "./threat_model.json"

    agent = ThreatModelAgent(title, owner="Security Team",
                             description="Automated threat model")
    did = agent.add_diagram("Main Data Flow")
    web = agent.add_element(did, "external_entity", "Web Browser", 50, 50)
    api = agent.add_element(did, "process", "API Gateway", 250, 50)
    db = agent.add_element(did, "data_store", "Database", 450, 50)
    flow1 = agent.add_element(did, "data_flow", "HTTPS Request", 150, 100)

    agent.apply_stride(did, web, "external_entity")
    agent.apply_stride(did, api, "process")
    agent.apply_stride(did, db, "data_store")
    agent.apply_stride(did, flow1, "data_flow")

    agent.save_model(output)
    agent.generate_report()


if __name__ == "__main__":
    main()
