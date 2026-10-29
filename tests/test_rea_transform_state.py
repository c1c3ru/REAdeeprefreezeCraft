"""REA-015/J: synthetic-only tests for flag, key selection and byte arithmetic."""
import hashlib
import pathlib
import tempfile
import unittest
import zipfile

from tools.rea_transform_state import (
    ANCHORS, StateEvidenceError, analyze_archive, analyze_pe,
    candidate_key_byte, configured_flag, copied_flag, derive_state_word,
    hypothetical_transform, select_words, s16, s32, trunc_divmod,
    validate_direct_calls,
)
from tests.test_rea_structural import fixture_pe


class TransformStateTests(unittest.TestCase):
    def test_flag_clears_only_bit_three(self):
        self.assertEqual(copied_flag(0xff), 0xf7)
        for source in (0, 1, 8, 9, 0x12345678, 0xffffffff):
            got = copied_flag(source)
            self.assertEqual(got & 1, source & 1)
            self.assertFalse(got & 8)
            self.assertEqual(got & ~8, source & ~8)

    def test_default_flag_nine_enables_low_bit_after_mask(self):
        self.assertEqual(copied_flag(9), 1)

    def test_boolean_setters_preserve_independent_bits(self):
        self.assertEqual(configured_flag(False, False), 0)
        self.assertEqual(configured_flag(False, True), 1)
        self.assertEqual(configured_flag(True, False), 8)
        self.assertEqual(configured_flag(True, True), 9)
        self.assertEqual(copied_flag(configured_flag(True, True)), 1)
        with self.assertRaises(ValueError):
            configured_flag(1, True)

    def test_flag_rejects_invalid_dword(self):
        for value in (-1, 0x100000000, "1", None):
            with self.assertRaises(ValueError):
                copied_flag(value)

    def test_select_fallback_when_secondary_all_zero(self):
        primary = (1, 2, 3, 4)
        secondary = (0, 0, 0, 0)
        self.assertEqual(select_words(primary, secondary), primary)

    def test_select_nonzero_secondary_even_if_primary_nonzero(self):
        self.assertEqual(select_words((1, 2, 3, 4), (0, 0, 1, 0)),
                         (0, 0, 1, 0))

    def test_select_rejects_bad_word_size_and_negative_value(self):
        with self.assertRaises(ValueError):
            select_words((1, 2, 3), (0, 0, 0, 0))
        with self.assertRaises(ValueError):
            select_words((-1, 2, 3, 4), (0, 0, 0, 0))

    def test_state_xor_fold_positive(self):
        self.assertEqual(derive_state_word((0x12345678, 0, 0, 0)),
                         0x12345678 ^ 0x1234)
        self.assertEqual(derive_state_word((1, 2, 3, 4)),
                         1 ^ 2 ^ 3 ^ 4)

    def test_state_xor_fold_negative_arithmetic_shift(self):
        self.assertEqual(s32(0x80000000), -0x80000000)
        self.assertEqual(derive_state_word((0x80000000, 0, 0, 0)),
                         0x7fff8000)

    def test_x86_signed_division_truncation_not_python_floor(self):
        for x, q, r in [(-1, 0, -1), (-178, -1, -1),
                        (178, 1, 1), (-354, -2, 0)]:
            self.assertEqual(trunc_divmod(x, 177), (q, r))

    def test_signed_16bit_edge_mapping(self):
        self.assertEqual(s16(0xffff), -1)
        self.assertEqual(s16(0x8000), -32768)
        self.assertEqual(s16(0x7fff), 32767)
        self.assertEqual(s16(0x10000), 0)

    def test_key_byte_hardcoded_synthetic_vectors(self):
        positions = (0, 1, 2, 3, 176, 177, 178, 65535)
        expected = {
            0x0000: (0, 42, 84, 130, 250, 2, 40, 43),
            0x0001: (42, 84, 130, 169, 2, 40, 82, 0),
            0x8000: (102, 77, 25, 225, 150, 96, 79, 50),
            0xffff: (43, 0, 42, 84, 16, 250, 2, 87),
        }
        for seed, vec in expected.items():
            self.assertEqual(tuple(candidate_key_byte(seed, i) for i in positions),
                             vec)

    def test_key_byte_periodic_16bit_index(self):
        self.assertEqual(candidate_key_byte(0x12345678, 6),
                         candidate_key_byte(0x00005678, 6))
        self.assertEqual(candidate_key_byte(0, 65535),
                         candidate_key_byte(0, 131071))

    def test_key_byte_rejects_invalid_inputs(self):
        with self.assertRaises(ValueError):
            candidate_key_byte(-1, 0)
        with self.assertRaises(ValueError):
            candidate_key_byte(0, -1)

    def test_synthetic_transform_is_reversible(self):
        plain = b"synthetic only / no embedded installer bytes"
        args = (0x00000001, (0, 0, 0, 0), (1, 2, 3, 4), 1)
        first = hypothetical_transform(plain, *args)
        self.assertTrue(first["applied"])
        second = hypothetical_transform(bytes.fromhex(first["output_hex"]), *args)
        self.assertEqual(bytes.fromhex(second["output_hex"]), plain)

    def test_synthetic_transform_skips_if_flag_not_set(self):
        plain = b"test"
        r = hypothetical_transform(plain, 0x00000008,
                                   (1, 2, 3, 4), (0, 0, 0, 0), 1)
        self.assertFalse(r["applied"])
        self.assertEqual(r["output_hex"], plain.hex())

    def test_synthetic_transform_skips_zero_keys(self):
        r = hypothetical_transform(b"abc", 1,
                                   (0, 0, 0, 0), (0, 0, 0, 0), 1)
        self.assertFalse(r["applied"])

    def test_synthetic_transform_skips_other_state(self):
        r = hypothetical_transform(b"abc", 1,
                                   (1, 0, 0, 0), (0, 0, 0, 0), 2)
        self.assertFalse(r["applied"])

    def test_synthetic_transform_bounded(self):
        with self.assertRaises(ValueError):
            hypothetical_transform(b"A" * 4097, 1,
                                   (1, 0, 0, 0), (0, 0, 0, 0), 1)

    def test_direct_edges_are_opcode_validated(self):
        edges = validate_direct_calls()
        self.assertEqual(len(edges), 7)
        assert_set = {(x["caller_va"], x["callee_va"]) for x in edges}
        self.assertIn(("0x0074f8c0", "0x0074f8d4"), assert_set)
        self.assertIn(("0x0074f893", "0x0074f8ac"), assert_set)
        self.assertIn(("0x00750b43", "0x0074f804"), assert_set)
        self.assertIn(("0x00750c84", "0x0074f804"), assert_set)

    def test_unique_anchor_ids_and_addresses(self):
        self.assertEqual(len(ANCHORS), len({a[0] for a in ANCHORS}))
        self.assertEqual(len(ANCHORS), len({a[1] for a in ANCHORS}))
        self.assertEqual(len(ANCHORS), 74)

    def test_unpinned_pe_never_claims_original_analysis(self):
        with self.assertRaisesRegex(StateEvidenceError, "SHA-256"):
            analyze_pe(fixture_pe())

    def test_unpinned_zip_fails_before_pe_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "synthetic.zip"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("Faronics_DFS/DFStd.exe", fixture_pe())
            with self.assertRaisesRegex(StateEvidenceError, "archive SHA-256"):
                analyze_archive(path)


if __name__ == "__main__":
    unittest.main()
