"""Offline tests for password selection and private prompt failures."""

from contextlib import redirect_stderr
import getpass
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch
import warnings


spec = importlib.util.spec_from_file_location(
    "wazuh_password_agent", Path(__file__).with_name("agent.py")
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PasswordInputTests(unittest.TestCase):
    def test_environment_password_skips_prompt(self):
        with patch.dict(module.os.environ, {"WAZUH_API_PASSWORD": "fake-env"}, clear=True):
            with patch.object(module.getpass, "getpass") as prompt:
                self.assertEqual(module.read_password(None), "fake-env")
                prompt.assert_not_called()

    def test_legacy_argument_keeps_precedence(self):
        with patch.dict(module.os.environ, {"WAZUH_API_PASSWORD": "fake-env"}, clear=True):
            with patch.object(module.getpass, "getpass") as prompt:
                self.assertEqual(module.read_password("fake-argument"), "fake-argument")
                prompt.assert_not_called()

    def test_absent_environment_uses_hidden_prompt(self):
        with patch.dict(module.os.environ, {}, clear=True):
            with patch.object(module.getpass, "getpass", return_value="fake-prompt") as prompt:
                self.assertEqual(module.read_password(None), "fake-prompt")
                prompt.assert_called_once_with("Wazuh API password: ")

    def test_empty_sources_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            module.read_password("")
        with patch.dict(module.os.environ, {"WAZUH_API_PASSWORD": ""}, clear=True):
            with patch.object(module.getpass, "getpass") as prompt:
                with self.assertRaisesRegex(ValueError, "must not be empty"):
                    module.read_password(None)
                prompt.assert_not_called()
        with patch.dict(module.os.environ, {}, clear=True):
            with patch.object(module.getpass, "getpass", return_value=""):
                with self.assertRaisesRegex(ValueError, "must not be empty"):
                    module.read_password(None)

    def test_password_characters_are_not_normalized(self):
        self.assertEqual(module.read_password(" fake password "), " fake password ")

    def test_echoed_fallback_is_refused(self):
        def echoed_fallback(*args):
            warnings.warn("Synthetic fallback", getpass.GetPassWarning)
            self.fail("The fallback must stop before reading echoed input")

        with patch.dict(module.os.environ, {}, clear=True):
            with patch.object(module.getpass, "getpass", side_effect=echoed_fallback):
                with self.assertRaisesRegex(ValueError, "Cannot read a hidden password"):
                    module.read_password(None)

    def test_unavailable_prompt_has_no_raw_error_details(self):
        for error in (EOFError("fake-secret"), OSError("fake-secret")):
            with self.subTest(error=type(error).__name__):
                with patch.dict(module.os.environ, {}, clear=True):
                    with patch.object(module.getpass, "getpass", side_effect=error):
                        with self.assertRaises(ValueError) as raised:
                            module.read_password(None)
                        self.assertNotIn("fake-secret", str(raised.exception))

    def test_cli_passes_environment_password_to_agent(self):
        with patch.dict(module.os.environ, {"WAZUH_API_PASSWORD": "fake-env"}, clear=True):
            with patch.object(module, "WazuhDetectionAgent") as agent:
                with patch.object(module.os, "makedirs"):
                    module.main(["https://manager.example:55000", "--output-dir", "test-output"])
                agent.assert_called_once_with(
                    "https://manager.example:55000", "wazuh-wui", "fake-env",
                    output_dir="test-output",
                )
                agent.return_value.generate_report.assert_called_once_with()

    def test_cli_legacy_argument_is_still_accepted(self):
        with patch.object(module, "WazuhDetectionAgent") as agent:
            with patch.object(module.os, "makedirs"):
                module.main(["https://manager.example:55000", "--password", "fake-argument"])
            self.assertEqual(agent.call_args.args[2], "fake-argument")

    def test_cli_empty_password_stops_before_side_effects(self):
        stderr = io.StringIO()
        with patch.dict(module.os.environ, {"WAZUH_API_PASSWORD": ""}, clear=True):
            with patch.object(module, "WazuhDetectionAgent") as agent:
                with patch.object(module.os, "makedirs") as mkdir:
                    with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
                        module.main(["https://manager.example:55000"])
                    self.assertEqual(raised.exception.code, 2)
                    agent.assert_not_called()
                    mkdir.assert_not_called()
        self.assertIn("password must not be empty", stderr.getvalue())

    def test_cli_cancelled_prompt_returns_130(self):
        stderr = io.StringIO()
        with patch.dict(module.os.environ, {}, clear=True):
            with patch.object(module.getpass, "getpass", side_effect=KeyboardInterrupt):
                with patch.object(module, "WazuhDetectionAgent") as agent:
                    with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
                        module.main(["https://manager.example:55000"])
                    self.assertEqual(raised.exception.code, 130)
                    agent.assert_not_called()
        self.assertEqual(stderr.getvalue(), "Password entry cancelled.\n")


if __name__ == "__main__":
    unittest.main()
