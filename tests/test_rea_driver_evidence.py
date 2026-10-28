"""REA-009 driver provenance: fixture-only tests, no third-party driver bytes."""
import hashlib
import pathlib
import struct
import tempfile
import unittest
import zipfile

from tools.rea_driver_evidence import (
    EvidenceError, analyze_archive, certificate_surface, safe_name, scan_pe,
)
from tools.rea_structural import PEView
from tests.test_rea_structural import fixture_pe


def with_certificate():
    raw = bytearray(fixture_pe())
    offset = len(raw)
    # WIN_CERTIFICATE: length 16, revision 0x200, type 2, DER-like prefix.
    blob = b"\x30\x06\x02\x01\x01\x02\x01\x01"
    raw.extend(struct.pack("<IHH", 16, 0x200, 2) + blob)
    opt = struct.unpack_from("<I", raw, 0x3c)[0] + 24
    struct.pack_into("<II", raw, opt + 96 + 4 * 8, offset, 16)
    return bytes(raw)


class DriverEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = pathlib.Path(self.tmp.name) / "fixture.zip"

    def create_zip(self, entries):
        with zipfile.ZipFile(str(self.path), "w") as z:
            for name, data in entries:
                z.writestr(name, data)
        return self.path

    def test_valid_certificate_is_only_presence(self):
        raw = with_certificate()
        sig = certificate_surface(raw, PEView(raw))
        self.assertTrue(sig["present"])
        self.assertEqual(sig["win_certificate_count"], 1)
        self.assertEqual(sig["certificates"][0]["certificate_type"], "0x0002")
        self.assertTrue(sig["certificates"][0]["pkcs7_der_prefix_present"])
        self.assertFalse(sig["signature_cryptographically_verified"])
        self.assertFalse(sig["chain_trust_verified"])

    def test_unsigned_pe_is_not_assumed_trusted(self):
        sig = scan_pe(fixture_pe(), "app.exe")["certificate_surface"]
        self.assertFalse(sig["present"])
        self.assertEqual(sig["certificates"], [])

    def test_certificate_offset_is_file_offset_not_rva(self):
        raw = with_certificate()
        s = scan_pe(raw, "installer.exe")
        self.assertEqual(s["certificate_surface"]["directory_file_offset"], 4096)
        self.assertEqual(s["certificate_surface"]["directory_size"], 16)

    def test_malformed_cert_table_fails_closed(self):
        raw = bytearray(with_certificate())
        opt = struct.unpack_from("<I", raw, 0x3c)[0] + 24
        struct.pack_into("<II", raw, opt + 96 + 4 * 8, 999999, 16)
        with self.assertRaisesRegex(EvidenceError, "security directory bounds"):
            scan_pe(bytes(raw), "app.exe")

    def test_invalid_win_certificate_length_is_rejected(self):
        raw = bytearray(with_certificate())
        struct.pack_into("<I", raw, 4096, 999)
        with self.assertRaisesRegex(EvidenceError, "WIN_CERTIFICATE"):
            scan_pe(bytes(raw), "app.exe")

    def test_overlay_is_not_claimed_as_driver(self):
        raw = fixture_pe() + b"UNCLASSIFIED_PAYLOAD"
        out = scan_pe(raw, "installer.exe")
        self.assertGreater(out["unclassified_overlay"]["size_bytes"], 0)
        self.assertFalse(out["unclassified_overlay"]["driver_found_in_overlay"])
        self.assertFalse(out["unclassified_overlay"]["executable_code_recovered"])

    def test_driver_filename_reference_is_not_a_binary(self):
        raw = fixture_pe() + b"FarSpace.sys DeepFrzx64.sys"
        out = scan_pe(raw, "installer.exe")
        names = {x["filename"] for x in out["driver_filename_references"]}
        self.assertEqual(names, {"FarSpace.sys", "DeepFrzx64.sys"})
        self.assertFalse(out["is_named_sys"])

    def test_valid_named_sys_pe_is_confirmed_only_when_present(self):
        self.create_zip([("system/driver.sys", fixture_pe())])
        r = analyze_archive(self.path)
        self.assertEqual(r["confirmed_sys_pe_count"], 1)
        self.assertEqual(r["confirmed_sys_pe"][0]["machine"], "0x014c")
        self.assertFalse(r["confirmed_sys_pe"][0]["certificate_surface"]["present"])
        self.assertFalse(r["scope_closed"])

    def test_sys_name_without_pe_cannot_be_confirmed(self):
        self.create_zip([("fake.sys", b"not a PE")])
        r = analyze_archive(self.path)
        self.assertEqual(r["confirmed_sys_pe_count"], 0)
        self.assertIn("named_executable_without_PE_header",
                      [s["reason"] for s in r["unresolved"]])

    def test_sample_zip_without_sys_leaves_task_unresolved(self):
        self.create_zip([("bin/setup.exe", fixture_pe()),
                         ("readme.txt", b"DeepFrz.sys")])
        r = analyze_archive(self.path)
        self.assertEqual(r["confirmed_sys_pe_count"], 0)
        self.assertEqual(r["direct_zip_members_examined"], 2)
        self.assertEqual(r["cryptographically_verified_signatures"], 0)

    def test_hash_pin_fails_closed(self):
        self.create_zip([("installer.exe", fixture_pe())])
        with self.assertRaisesRegex(EvidenceError, "SHA-256"):
            analyze_archive(self.path, "0" * 64)

    def test_safe_zip_paths(self):
        self.assertTrue(safe_name("bin/driver.sys"))
        self.assertFalse(safe_name("../escape.sys"))
        self.assertFalse(safe_name("/system32/driver.sys"))
        self.assertFalse(safe_name("C:\\Windows\\driver.sys"))

    def test_document_is_deterministic(self):
        self.create_zip([("setup.exe", with_certificate())])
        self.assertEqual(analyze_archive(self.path), analyze_archive(self.path))


if __name__ == "__main__":
    unittest.main()
