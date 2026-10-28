"""Synthetic-only CFG and structural contract tests (no proprietary binaries)."""
import json
import os
import shutil
import struct
import tempfile
import unittest
import zipfile

from tools.rea_function_cfg import (
    analyze_pe_file, analyze_archive, build_graph, inspect_function,
)
try:
    from tests.test_rea_loop import fixture_with_call
except ImportError:
    from tests.test_rea_loop import fixture_with_calls as fixture_with_call


def inst(va, size, mnemonic, operands=""):
    return {"va": va, "size": size, "mnemonic": mnemonic, "operands": operands}


class PureCFGTests(unittest.TestCase):
    def test_branch_dominators_and_unreachable(self):
        instructions = [
            inst(0x100, 2, "jne", "0x108"),
            inst(0x102, 5, "call", "0x500"),
            inst(0x107, 1, "ret"),
            inst(0x108, 1, "ret"),
            inst(0x109, 1, "nop"),
        ]
        report = inspect_function(instructions, 0x100, {0x500: "DeviceIoControl"})
        self.assertEqual(report["reachable_instructions"], 4)
        self.assertEqual(report["unreachable_instructions"], 1)
        self.assertEqual(report["calls_to_imports"][0]["api"], "DeviceIoControl")
        self.assertEqual(report["conditional_guards"][0]["branch_va"], "0x100")

    def test_natural_loop(self):
        instructions = [
            inst(0x200, 1, "inc", "eax"),
            inst(0x201, 2, "jne", "0x200"),
            inst(0x203, 1, "ret"),
        ]
        report = inspect_function(instructions, 0x200)
        self.assertEqual(len(report["loop_back_edges"]), 1)
        self.assertEqual(
            report["loop_back_edges"][0]["type"],
            "natural_loop_back_edge_candidate",
        )

    def test_jump_outside_window_is_unresolved(self):
        report = inspect_function([inst(0x100, 2, "jmp", "0x200")], 0x100)
        self.assertEqual(report["unresolved_edges"][0]["reason"], "edge_out_of_window")

    def test_indirect_branch_not_fabricated(self):
        report = inspect_function([inst(0x100, 2, "jmp", "eax")], 0x100)
        self.assertEqual(report["unresolved_edges"][0]["reason"], "indirect_jump")

    def test_duplicate_instruction_address_rejected(self):
        with self.assertRaises(ValueError):
            build_graph([inst(0x100, 1, "nop"), inst(0x100, 1, "ret")], 0x100)


@unittest.skipUnless(shutil.which("objdump"), "Requires GNU objdump")
class SyntheticPECFGTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = os.path.join(self.tempdir.name, "sample.exe")
        with open(self.path, "wb") as out:
            out.write(fixture_with_call())

    def test_static_call_x86(self):
        report = analyze_pe_file(self.path, 0x401180, 0x401185)
        self.assertEqual(report["decoded_instructions"], 1)
        self.assertEqual(report["reachable_instructions"], 1)
        self.assertEqual(report["calls_to_imports"][0]["api"], "DeviceIoControl")
        self.assertEqual(len(report["input_sha256"]), 64)

    def test_zip_no_retained_executable(self):
        package = os.path.join(self.tempdir.name, "sample.zip")
        with zipfile.ZipFile(package, "w") as out:
            out.writestr("samples/sample.exe", fixture_with_call())
        report = analyze_archive(package, "samples/sample.exe", 0x401180, 0x401185)
        self.assertEqual(report["source"], "samples/sample.exe")
        self.assertNotIn("payload", json.dumps(report))
        self.assertFalse(os.path.exists(os.path.join(self.tempdir.name, "analysis.exe")))

    def test_undecodable_start_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_pe_file(self.path, 0x401182, 0x401185)

    def test_unsupported_machine_is_rejected(self):
        payload = bytearray(fixture_with_call())
        struct.pack_into("<H", payload, 0x84, 0x8664)
        with open(self.path, "wb") as out:
            out.write(payload)
        with self.assertRaises(ValueError):
            analyze_pe_file(self.path, 0x401180, 0x401185)


if __name__ == "__main__":
    unittest.main()
