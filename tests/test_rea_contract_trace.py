"""REA cycle 6 tests: use synthetic PE files, never proprietary executables."""
import os
import struct
import tempfile
import unittest
import zipfile

from tools.rea_structural import PEView
from tools.rea_contract_trace import (
    all_import_slots, analyze_archive, analyze_path, ascii_at_va,
    image_base, instruction_evidence, little_endian_table, mapped_bytes,
    resolve_iat_jump,
)
try:
    from tests.test_rea_loop import fixture_with_call as fixture
except ImportError:
    from tests.test_rea_loop import fixture_with_calls as fixture


class ContractFixtures(unittest.TestCase):
    def setUp(self):
        self.binary = bytearray(fixture())
        self.view = PEView(bytes(self.binary))

    def test_image_base_and_imports(self):
        self.assertEqual(image_base(self.view), 0x400000)
        slots = all_import_slots(self.view)
        self.assertEqual(slots[0x402050]['name'], 'DeviceIoControl')

    def test_exact_import_thunk(self):
        slots = all_import_slots(self.view)
        thunk = resolve_iat_jump(self.view, 0x401100, slots)
        self.assertEqual(thunk['name'], 'DeviceIoControl')
        self.assertEqual(thunk['iat_va'], '0x00402050')

    def test_invalid_thunk_does_not_make_up_api(self):
        self.assertIsNone(resolve_iat_jump(self.view, 0x401120,
                                           all_import_slots(self.view)))

    def test_little_endian_dword_table(self):
        values = (0x71c08, 0x7200c, 0x71fc4, 0x71fc0)
        struct.pack_into('<4I', self.binary, 0x720, *values)
        view = PEView(bytes(self.binary))
        self.assertEqual(little_endian_table(view, 0x402120, 4), list(values))

    def test_unmapped_and_oversize_tables_rejected(self):
        with self.assertRaises(ValueError):
            little_endian_table(self.view, 0x402120, 257)
        with self.assertRaises(ValueError):
            mapped_bytes(self.view, 0xDEADBEEF, 1)

    def test_ascii_path_read_is_bounded(self):
        value = b'\\\\.\\C:\x00'
        self.binary[0x740:0x740 + len(value)] = value
        self.assertEqual(ascii_at_va(PEView(bytes(self.binary)), 0x402140),
                         '\\\\.\\C:')

    def test_instruction_evidence_requires_boundary(self):
        insns = [{'va': 0x1234, 'mnemonic': 'mov', 'operands': 'eax,[edi]'}]
        self.assertTrue(instruction_evidence(insns, 0x1234, 'mov', '[edi]')['present'])
        self.assertFalse(instruction_evidence(insns, 0x1234, 'call')['present'])
        self.assertFalse(instruction_evidence(insns, 0x1235)['present'])

    def test_sha256_pin_rejects_other_version(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'fixture.exe')
            with open(path, 'wb') as target:
                target.write(self.binary)
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                analyze_path(path)

    def test_missing_member_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'fixture.zip')
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('fixture.exe', self.binary)
            with self.assertRaisesRegex(ValueError, 'Missing or duplicate'):
                analyze_archive(path, 'missing.exe')


if __name__ == '__main__':
    unittest.main()
