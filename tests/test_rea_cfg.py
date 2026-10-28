"""Testes locais com PE sintetico; nao dependem do binario comercial."""
import os
import shutil
import struct
import tempfile
import unittest
import zipfile

from tests.test_rea_loop import fixture_with_call
from tools.rea_cfg import (
    analyze_path, analyze_zip, disassemble_window, render_markdown, stack_trace,
    DisassemblyError,
)

HAS_OBJDUMP = bool(shutil.which("objdump"))


def dynamic_fixture():
    data = bytearray(fixture_with_call())
    instructions = bytes.fromhex(
        "8b4d08"  # mov ecx, [ebp+8]
        "6a00"    # push 0
        "50"      # push eax
        "6a00"    # push 0
        "57"      # push edi
        "6a00"    # push 0
        "56"      # push esi
        "51"      # push ecx -- dwIoControlCode symbolically from caller
        "53"      # push ebx -- hDevice
    )
    assert len(instructions) == 14
    data[0x572:0x580] = instructions
    return bytes(data)


@unittest.skipUnless(HAS_OBJDUMP, "GNU objdump necessario")
class CFGTests(unittest.TestCase):
    def with_pe(self, data):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = os.path.join(folder.name, "mock.exe")
        with open(path, "wb") as stream:
            stream.write(data)
        return path

    def test_decoded_call_matches_thunk(self):
        path = self.with_pe(fixture_with_call())
        result = analyze_path(path)
        self.assertEqual(result["validation"]["total_candidates"], 1)
        call = result["calls"][0]
        self.assertEqual(call["api"], "DeviceIoControl")
        self.assertGreaterEqual(call["alignment_count"], 1)
        self.assertEqual(call["instruction_bytes"][:2], "e8")
        self.assertIn("0x1180", render_markdown(result))

    def test_dynamic_stack_argument_source(self):
        path = self.with_pe(dynamic_fixture())
        result = analyze_path(path)
        call = result["calls"][0]
        trace = call["stack_trace"]
        self.assertEqual(len(trace["arguments"]), 8)
        self.assertTrue(trace["complete_eight_argument_sequence"])
        self.assertEqual(trace["arguments"][1]["argument"], "dwIoControlCode")
        self.assertIn("[ebp+0x8]", trace["second_argument_source"]["source"])
        self.assertEqual(trace["arguments"][0]["operand"], "ebx")

    def test_zip_member_isolation(self):
        data = dynamic_fixture()
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = os.path.join(folder.name, "sample.zip")
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("Faronics_DFS/DFStd.exe", data)
            archive.writestr("../ignored.exe", b"oops")
        result = analyze_zip(path, "Faronics_DFS/DFStd.exe")
        self.assertEqual(result["source"], "Faronics_DFS/DFStd.exe")
        self.assertEqual(len(result["calls"]), 1)
        self.assertFalse(os.path.exists(os.path.join(folder.name, "analysis.exe")))

    def test_duplicate_entry_rejected(self):
        import warnings
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = os.path.join(folder.name, "sample.zip")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("Faronics_DFS/DFStd.exe", dynamic_fixture())
                archive.writestr("Faronics_DFS/DFStd.exe", dynamic_fixture())
        with self.assertRaises(ValueError):
            analyze_zip(path, "Faronics_DFS/DFStd.exe")

    def test_empty_unsafe_window(self):
        path = self.with_pe(dynamic_fixture())
        with self.assertRaises(DisassemblyError):
            disassemble_window(path, 0x1000, 0x5000)


class StackTraceTests(unittest.TestCase):
    def test_unknown_register(self):
        instructions = [
            {"mnemonic": "push", "operands": "ecx", "address": 0x4100, "size": 1},
            {"mnemonic": "call", "operands": "0x900d6e", "address": 0x4101, "size": 5},
        ]
        trace = stack_trace(instructions, 1, {}, "DeviceIoControl")
        self.assertEqual(len(trace["arguments"]), 1)
        self.assertIsNone(trace["second_argument_source"])

    def test_no_false_constant(self):
        instructions = [
            {"mnemonic": "push", "operands": "ecx", "address": 0x4100, "size": 1},
            {"mnemonic": "push", "operands": "ebx", "address": 0x4101, "size": 1},
            {"mnemonic": "call", "operands": "0x900d6e", "address": 0x4102, "size": 5},
        ]
        trace = stack_trace(instructions, 2, {}, "DeviceIoControl")
        self.assertIsNone(trace["constant_candidate"])


if __name__ == "__main__":
    unittest.main()
