"""Testes de parsing com fixtures PE sintéticas e ZIPs temporários."""
import json
import os
import struct
import tempfile
import unittest
import zipfile

from tools.rea_structural import PEError, PEView, inspect_archive, markdown_report


def fixture_pe():
    b = bytearray(4096)
    b[:2] = b'MZ'
    struct.pack_into('<I', b, 0x3c, 0x80)
    b[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHI', b, 0x84, 0x14c, 3, 0)
    struct.pack_into('<H', b, 0x94, 224)
    opt = 0x98
    struct.pack_into('<H', b, opt, 0x10b)
    struct.pack_into('<I', b, opt + 16, 0x1000)
    struct.pack_into('<I', b, opt + 60, 0x400)
    struct.pack_into('<I', b, opt + 92, 16)
    for i, (name, rva, offset) in enumerate([
        ('.text', 0x1000, 0x400),
        ('.idata', 0x2000, 0x600),
        ('.rsrc', 0x3000, 0xa00),
    ]):
        at = opt + 224 + 40 * i
        b[at:at + len(name)] = name.encode()
        struct.pack_into('<IIII', b, at + 8, 0x400, rva, 0x400, offset)
    struct.pack_into('<II', b, opt + 96 + 8, 0x2000, 0x28)
    struct.pack_into('<IIIII', b, 0x600, 0x2050, 0, 0, 0x2080, 0x2050)
    b[0x680:0x68d] = b'KERNEL32.DLL\0'
    struct.pack_into('<II', b, 0x650, 0x20a0, 0x20c0)
    b[0x6a0:0x6a2 + len(b'DeviceIoControl\0')] = b'\0\0DeviceIoControl\0'
    b[0x6c0:0x6c2 + len(b'CreateFileW\0')] = b'\0\0CreateFileW\0'
    struct.pack_into('<II', b, opt + 96 + 16, 0x3000, 0x100)
    struct.pack_into('<HH', b, 0xa0c, 0, 1)
    struct.pack_into('<II', b, 0xa10, 10, 0x20)
    struct.pack_into('<IIII', b, 0xa20, 0x3080, 4, 0, 0)
    b[0xa80:0xa84] = b'TEST'
    return bytes(b)


class StructuralTests(unittest.TestCase):
    def test_imports_and_categories(self):
        report = PEView(fixture_pe()).summary()
        self.assertEqual(report['machine'], '0x014c')
        self.assertEqual(report['imports'][0]['dll'], 'KERNEL32.DLL')
        self.assertEqual(report['api_groups']['driver_handle_or_ipc'],
                         ['CreateFileW', 'DeviceIoControl'])

    def test_resource_hash_and_offset(self):
        resources = PEView(fixture_pe()).resources()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['path'], ['10'])
        self.assertEqual(resources[0]['size'], 4)
        self.assertEqual(len(resources[0]['sha256']), 64)

    def test_invalid_pe(self):
        data = bytearray(fixture_pe())
        data[0x80:0x84] = b'NOPE'
        with self.assertRaises(PEError):
            PEView(bytes(data))

    def test_invalid_rva(self):
        data = bytearray(fixture_pe())
        struct.pack_into('<I', data, 0x600, 0xffffff00)
        with self.assertRaises(PEError):
            PEView(bytes(data)).imports()

    def test_zip_inventory_and_markdown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'test.zip')
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('sample.exe', fixture_pe())
                archive.writestr('readme.txt', 'test')
            report = inspect_archive(path)
            self.assertEqual(len(report['artifacts']), 1)
            self.assertEqual(report['artifacts'][0]['pe']['resources'][0]['path'], ['10'])
            self.assertIn('DeviceIoControl', markdown_report(report))
            json.dumps(report)

    def test_zip_traversal_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'test.zip')
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('../payload.exe', fixture_pe())
            report = inspect_archive(path)
            self.assertEqual(report['artifacts'], [])
            self.assertEqual(len(report['warnings']), 1)

    def test_non_pe_does_not_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'test.zip')
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('sample.exe', b'not a PE')
            report = inspect_archive(path)
            self.assertIn('parse_error', report['artifacts'][0])


if __name__ == '__main__':
    unittest.main()
