"""REA Inspector: no-install, no-driver portable CLI integration tests."""
import contextlib
import io
import json
import pathlib
import unittest
from unittest import mock

import rea_diagnostic


class DiagnosticCLITests(unittest.TestCase):
    def test_help_has_only_offline_commands(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(rea_diagnostic.main(["--help"]), 0)
        self.assertIn("REA Inspector", output.getvalue())
        for command in ("correlate", "xor-check", "inspect-output",
                        "intake", "import-capture", "selfcheck"):
            self.assertIn(command, output.getvalue())

    def test_selfcheck_never_claims_vm_validation(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(rea_diagnostic.main(["selfcheck"]), 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["schema"], "rea-diagnostic-portable-selfcheck-v1")
        self.assertTrue(report["portable_offline_analyzer"])
        self.assertFalse(report["installs_drivers"])
        self.assertFalse(report["modifies_disk_protection"])
        self.assertFalse(report["runs_original_installer"])
        self.assertFalse(report["windows7_compatibility_verified"])
        self.assertFalse(report["certification_receipt_created"])

    def test_unknown_command_and_extra_selfcheck_parameters_fail(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(rea_diagnostic.main(["install-driver"]), 2)
            self.assertEqual(rea_diagnostic.main(["selfcheck", "--archive", "x"]), 2)

    def test_exact_delegation_to_offline_modules(self):
        for name, module_name in (
            ("correlate", "rea_runtime_file_correlation"),
            ("xor-check", "rea_xor_differential"),
            ("inspect-output", "rea_output_structure"),
            ("intake", "rea_capture_evidence_intake"),
            ("import-capture", "rea_private_capture_export"),
        ):
            module = getattr(rea_diagnostic, module_name)
            with self.subTest(name=name), mock.patch.object(module, "main", return_value=0) as called:
                args = ["--archive", "test-not-real.zip"]
                self.assertEqual(rea_diagnostic.main([name] + args), 0)
                called.assert_called_once_with(args)

    def test_help_for_subcommand_reaches_target(self):
        for name in rea_diagnostic.COMMANDS:
            with self.subTest(name=name):
                module_function = rea_diagnostic.COMMANDS[name]
                with self.assertRaises(SystemExit) as captured, contextlib.redirect_stdout(io.StringIO()):
                    module_function(["--help"])
                self.assertEqual(captured.exception.code, 0)

    def test_windows_build_script_never_schedules_cloud_runner_or_product(self):
        script = pathlib.Path(__file__).resolve().parent.parent / "packaging/build_windows.ps1"
        source = script.read_text(encoding="utf-8")
        self.assertIn("--onedir", source)
        self.assertIn("--noupx", source)
        self.assertIn("REA-Inspector", source)
        self.assertIn("win7-x86", source)
        self.assertIn("win7-x64", source)
        self.assertNotIn("Start-Service", source)
        self.assertNotIn("Start-Process", source)
        self.assertNotIn("workflow_dispatch", source)


if __name__ == "__main__":
    unittest.main()
