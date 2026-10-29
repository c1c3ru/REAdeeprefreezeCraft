"""REA-015/P synthetic-only tests."""
import unittest
from tools.rea_runtime_buffer_diff import BufferDiffError, profile


def payload(before, after, offset=0):
    return {"schema": "rea-015-local-buffer-pairs-v1",
            "pairs": [{"offset": offset, "before_hex": before, "after_hex": after}]}


class BufferDiffTests(unittest.TestCase):
    def test_constant_xor_compatibility(self):
        result = profile(payload("00112233", "aabb8899"))
        self.assertTrue(result["pairs"][0]["single_byte_xor_mask_consistent"])
        self.assertEqual(result["pairs"][0]["bytes_changed"], 4)
        self.assertFalse(result["full_body_transformation_proven"])

    def test_nonconstant_pattern(self):
        result = profile(payload("00000000", "01020102"))
        self.assertFalse(result["pairs"][0]["single_byte_xor_mask_consistent"])

    def test_identical_pair_is_not_proof(self):
        result = profile(payload("123456", "123456"))
        self.assertTrue(result["pairs"][0]["all_bytes_unchanged"])
        self.assertEqual(result["pairs"][0]["bytes_changed"], 0)

    def test_rejects_length_mismatch(self):
        with self.assertRaises(BufferDiffError):
            profile(payload("00", "0001"))

    def test_rejects_malformed_hex_and_bool_offset(self):
        with self.assertRaises(BufferDiffError):
            profile(payload("zz", "00"))
        with self.assertRaises(BufferDiffError):
            profile(payload("00", "00", True))


if __name__ == "__main__":
    unittest.main()
