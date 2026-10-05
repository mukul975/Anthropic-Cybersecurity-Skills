"""Offline regression checks for the documented Wazuh 4.x logtest envelope."""

import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock


spec = importlib.util.spec_from_file_location(
    "wazuh_detection_agent", Path(__file__).with_name("agent.py")
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

# Synthetic values with the structure from the official logtest documentation:
# https://documentation.wazuh.com/current/user-manual/ruleset/testing.html
MATCH = {
    "error": 0,
    "data": {
        "token": "synthetic-session",
        "alert": True,
        "output": {
            "decoder": {"name": "sshd", "parent": "sshd"},
            "rule": {"id": "5710", "level": 5, "description": "Test login"},
        },
    },
}


class LogtestTests(unittest.TestCase):
    def run_response(self, response):
        # Avoid authentication, filesystem writes and real manager access.
        agent = module.WazuhDetectionAgent.__new__(module.WazuhDetectionAgent)
        agent._api = Mock(return_value=response)
        result = agent.test_logtest("synthetic log", log_format="json")
        agent._api.assert_called_once_with(
            "PUT", "/logtest",
            data={"log_format": "json", "location": "test", "event": "synthetic log"},
        )
        return result

    def test_extracts_nested_detection_metadata(self):
        result = self.run_response(copy.deepcopy(MATCH))
        self.assertEqual(result, {
            "decoder": "sshd", "rule_id": "5710", "rule_level": 5,
            "rule_description": "Test login", "output": MATCH["data"]["output"],
        })

    def test_decoded_event_without_rule_is_valid(self):
        response = copy.deepcopy(MATCH)
        del response["data"]["output"]["rule"]
        response["data"]["alert"] = False
        result = self.run_response(response)
        self.assertEqual(result["decoder"], "sshd")
        self.assertIsNone(result["rule_id"])
        self.assertIsNone(result["rule_level"])
        self.assertNotIn("error", result)

    def test_empty_output_is_valid_unmatched_event(self):
        response = {"error": 0, "data": {"output": {}, "alert": False}}
        result = self.run_response(response)
        self.assertIsNone(result["decoder"])
        self.assertIsNone(result["rule_id"])
        self.assertEqual(result["output"], {})

    def test_transport_failure_and_api_errors_are_not_detections(self):
        for response in (None, [], {}, {"error": 1000},
                         {"error": 1000, "data": MATCH["data"]}):
            with self.subTest(response=response):
                self.assertIn("error", self.run_response(response))

    def test_invalid_data_envelopes_are_reported(self):
        for data in (None, [], "unexpected", 7):
            with self.subTest(data=data):
                result = self.run_response({"error": 0, "data": data})
                self.assertEqual(result, {"error": "Invalid logtest response"})

    def test_invalid_output_is_not_a_successful_empty_detection(self):
        for output in (None, [], "unexpected", 7):
            with self.subTest(output=output):
                result = self.run_response({"error": 0, "data": {"output": output}})
                self.assertEqual(result, {"error": "Invalid logtest output"})
        self.assertIn("error", self.run_response({"error": 0, "data": {}}))

    def test_invalid_rule_and_decoder_metadata_are_reported(self):
        for name in ("decoder", "rule"):
            for value in (None, [], "unexpected", 7):
                with self.subTest(name=name, value=value):
                    response = copy.deepcopy(MATCH)
                    response["data"]["output"][name] = value
                    self.assertIn("error", self.run_response(response))


if __name__ == "__main__":
    unittest.main()
