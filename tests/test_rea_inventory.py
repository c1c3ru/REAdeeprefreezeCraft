import os
import struct
import tempfile
import unittest
import zipfile

from tools.rea_inventory import inspect_pe, inspect_zip, main


def mock_pe():
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHI", data, 0x84, 0x14c, 1, 123456)
    struct.pack_into("<H", data, 0x84 + 16, 224)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x10b)
    struct.pack_into("<H", data, opt + 70, 0)
    sec = opt + 224
    data[sec:sec + 5] = b".text"
    struct.pack_into("<I", data, sec + 16, 256)
    struct.pack_into("<I", data, sec + 20, 512)
    data[512:528] = b"DeviceIoControl\0"
    return bytes(data)


class PeTests(unittest.TestCase):
    def test_parse_pe32(self):
        pe = inspect_pe(mock_pe())
        self.assertEqual(pe["format"], "PE32")
        self.assertEqual(pe["machine"], "0x014c")
        self.assertEqual(pe["sections"][0]["name"], ".text")
        self.assertIn("DeviceIoControl", pe["string_references"])

    def test_not_pe(self):
        self.assertIsNone(inspect_pe(b"not-an-executable"))

    def test_truncated_pe(self):
        data = bytearray(64)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3c, 0xffffffff)
        with self.assertRaises(ValueError):
            inspect_pe(bytes(data))


class ZipTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "sample.zip")

    def test_inventory_hash_and_pe(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("safe/DFStd.exe", mock_pe())
            archive.writestr("safe/readme.txt", "texto")
        report = inspect_zip(self.path)
        self.assertEqual(report["member_count"], 2)
        self.assertEqual(report["members"][0]["pe"]["format"], "PE32")
        self.assertEqual(len(report["archive_sha256"]), 64)
        self.assertEqual(main([self.path]), 0)

    def test_path_traversal_never_processed(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("../../escape.exe", mock_pe())
        report = inspect_zip(self.path)
        self.assertEqual(report["member_count"], 0)
        self.assertTrue(report["warnings"])
        self.assertEqual(main([self.path]), 2)

    def test_size_guard(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("safe/a.exe", mock_pe())
        with self.assertRaises(ValueError):
            inspect_zip(self.path, max_member=10)


if __name__ == "__main__":
    unittest.main()
