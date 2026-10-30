"""REA-015/R: exclusively synthetic differential input/output checks."""
import copy
import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from tests.test_rea_runtime_file_correlation import fixture
from tools.rea_runtime_file_correlation import digest
from tools.rea_transform_state import (
    candidate_key_byte, derive_state_word,
)
from tools.rea_xor_differential import (
    DifferentialEvidenceError, analyze_pairs, main, output_header_hint, parse_hex,
)

PRIMARY = [1, 2, 3, 4]
SECONDARY = [0, 0, 0, 0]


def paired_fixture(start=0, size=8, flag=1, state=1):
    trace, resources = fixture()
    source = resources["overlay"][96 + start:96 + start + size]
    if flag & 1 and state == 1:
        seed = derive_state_word(PRIMARY)
        output = bytes(x ^ candidate_key_byte(seed, start + i)
                       for i, x in enumerate(source))
        branch = True
    else:
        output = source
        branch = False
    pairs = {"schema": "rea-015-xor-paired-observation-v1",
             "capture_id": trace["capture"]["capture_id"],
             "samples": [{
                 "sample_id": "synthetic-pair-1",
                 "read_seq": 3,
                 "pid": 123,
                 "handle": "0x30",
                 "offset_in_read": start,
                 "byte_index_in_transform_block": start,
                 "pre_hex": source.hex(),
                 "post_hex": output.hex(),
                 "owner_flag_0x60": flag,
                 "primary_words": PRIMARY[:],
                 "secondary_words": SECONDARY[:],
                 "active_words": PRIMARY[:],
                 "state_kind": state,
                 "branch_observed": branch,
                 "reported_key_source": "unknown",
             }]}
    return trace, resources, pairs


def compare(trace, resources, pairs):
    with mock.patch("tools.rea_runtime_file_correlation.CHILD_SHA",
                    digest(resources["child_pe"])), mock.patch(
                    "tools.rea_runtime_file_correlation.OVERLAY_SHA",
                    digest(resources["overlay"])):
        return analyze_pairs(trace, pairs, resources)


class XorDifferentialTests(unittest.TestCase):
    def test_synthetic_matched_pre_post_still_not_runtime_proof(self):
        t, r, p = paired_fixture()
        out = compare(t, r, p)
        self.assertEqual(out["samples_reported"], 1)
        self.assertEqual(out["samples_consistent_with_candidate_model"], 1)
        self.assertEqual(out["candidate_consistent_unique_body_bytes"], 8)
        check = out["pair_checks"][0]
        self.assertEqual(check["overlay_body_range"], [96, 104])
        self.assertTrue(check["pre_sample_matches_pinned_source"])
        self.assertTrue(check["branch_matches_static_candidate_rule"])
        self.assertTrue(check["active_key_matches_static_selection_rule"])
        self.assertTrue(check["candidate_model_matches_reported_post"])
        self.assertFalse(out["key_origin_verified"])
        self.assertFalse(out["original_executable_run_verified"])
        self.assertFalse(out["cloud_installer_transformation_proven"])
        self.assertFalse(out["output_format_classified"])
        self.assertFalse(out["certification_receipt_created"])
        self.assertNotIn("pre_hex", json.dumps(out))
        self.assertNotIn("post_hex", json.dumps(out))
        self.assertNotIn("active_words", json.dumps(out))

    def test_subrange_offset_and_index_have_distinct_semantics(self):
        t, r, p = paired_fixture(start=2, size=3)
        out = compare(t, r, p)
        self.assertEqual(out["samples_consistent_with_candidate_model"], 1)
        self.assertEqual(out["pair_checks"][0]["overlay_body_range"], [98, 101])

    def test_wrong_post_bytes_are_reported_not_accepted(self):
        t, r, p = paired_fixture()
        p["samples"][0]["post_hex"] = "ff" * 8
        out = compare(t, r, p)
        self.assertEqual(out["samples_consistent_with_candidate_model"], 0)
        self.assertFalse(out["pair_checks"][0]["candidate_model_matches_reported_post"])

    def test_wrong_pre_bytes_have_no_provenance_match(self):
        t, r, p = paired_fixture()
        p["samples"][0]["pre_hex"] = "00" * 8
        out = compare(t, r, p)
        self.assertFalse(out["pair_checks"][0]["pre_sample_matches_pinned_source"])
        self.assertEqual(out["candidate_consistent_unique_body_bytes"], 0)

    def test_wrong_active_key_does_not_count_as_consistent(self):
        t, r, p = paired_fixture()
        p["samples"][0]["active_words"] = [4, 3, 2, 1]
        out = compare(t, r, p)
        self.assertFalse(out["pair_checks"][0]["active_key_matches_static_selection_rule"])
        self.assertEqual(out["samples_consistent_with_candidate_model"], 0)

    def test_observed_branch_disagrees_with_flag_rule(self):
        t, r, p = paired_fixture()
        p["samples"][0]["branch_observed"] = False
        out = compare(t, r, p)
        self.assertFalse(out["pair_checks"][0]["branch_matches_static_candidate_rule"])
        self.assertEqual(out["samples_consistent_with_candidate_model"], 0)

    def test_skipped_branch_and_unchanged_bytes(self):
        t, r, p = paired_fixture(flag=0)
        out = compare(t, r, p)
        self.assertTrue(out["pair_checks"][0]["paired_sample_consistent"])
        self.assertFalse(out["cloud_installer_transformation_proven"])

    def test_secondary_key_precedence_and_time_label_not_authenticated(self):
        t, r, p = paired_fixture()
        sample = p["samples"][0]
        sample["secondary_words"] = [5, 0, 0, 0]
        sample["active_words"] = [5, 0, 0, 0]
        sample["reported_key_source"] = "localtime_fallback"
        seed = derive_state_word(sample["secondary_words"])
        pre = bytes.fromhex(sample["pre_hex"])
        sample["post_hex"] = bytes(
            byte ^ candidate_key_byte(seed, i)
            for i, byte in enumerate(pre)).hex()
        out = compare(t, r, p)
        self.assertEqual(out["samples_consistent_with_candidate_model"], 1)
        self.assertFalse(out["pair_checks"][0]["key_origin_verified"])

    def test_duplicate_and_overlapping_samples_rejected(self):
        t, r, p = paired_fixture()
        second = copy.deepcopy(p["samples"][0])
        second["sample_id"] = "synthetic-pair-2"
        p["samples"].append(second)
        with self.assertRaisesRegex(DifferentialEvidenceError, "Overlapping"):
            compare(t, r, p)
        p["samples"][1]["sample_id"] = p["samples"][0]["sample_id"]
        with self.assertRaisesRegex(DifferentialEvidenceError, "Duplicate"):
            compare(t, r, p)

    def test_samples_must_match_read_and_body_bounds(self):
        t, r, p = paired_fixture()
        for key, value in (("read_seq", 50), ("pid", 999),
                           ("handle", "0x20"), ("offset_in_read", 8)):
            candidate = copy.deepcopy(p)
            candidate["samples"][0][key] = value
            with self.subTest(key=key):
                with self.assertRaises(DifferentialEvidenceError):
                    compare(t, r, candidate)

    def test_reject_invalid_words_hex_and_branch(self):
        t, r, p = paired_fixture()
        for key, value in (("primary_words", [1, 2, 3]),
                           ("active_words", [True, 2, 3, 4]),
                           ("pre_hex", "GG"),
                           ("pre_hex", "0"),
                           ("post_hex", "00"),
                           ("branch_observed", 1),
                           ("reported_key_source", "guessed_verified"),
                           ("byte_index_in_transform_block", -1)):
            candidate = copy.deepcopy(p)
            candidate["samples"][0][key] = value
            with self.subTest(key=key):
                with self.assertRaises(DifferentialEvidenceError):
                    compare(t, r, candidate)

    def test_read_hash_mismatch_prevents_positive_evidence(self):
        t, r, p = paired_fixture()
        t["events"][2]["buffer_sha256"] = "f" * 64
        out = compare(t, r, p)
        self.assertEqual(out["samples_consistent_with_candidate_model"], 0)
        self.assertFalse(out["pair_checks"][0]["read_correlated_to_pinned_source"])

    def test_capture_label_mismatch_rejected(self):
        t, r, p = paired_fixture()
        p["capture_id"] = "other-synthetic"
        with self.assertRaisesRegex(DifferentialEvidenceError, "Capture"):
            compare(t, r, p)

    def test_cli_rejects_foreign_zip_before_any_processing(self):
        t, r, p = paired_fixture()
        with tempfile.TemporaryDirectory() as d:
            folder = pathlib.Path(d)
            (folder / "trace.json").write_text(json.dumps(t), encoding="utf-8")
            (folder / "pairs.json").write_text(json.dumps(p), encoding="utf-8")
            (folder / "wrong.zip").write_bytes(b"synthetic ZIP placeholder")
            self.assertNotEqual(main(["--archive", str(folder / "wrong.zip"),
                                      "--trace", str(folder / "trace.json"),
                                      "--pairs", str(folder / "pairs.json")]), 0)


    def test_output_header_magic_is_only_a_candidate(self):
        self.assertEqual(output_header_hint(b"MZ"),
                         "mz_prefix_only_unverified")
        self.assertEqual(output_header_hint(b"PK\\x03\\x04" + b"\\x00" * 26),
                         "zip_local_header_magic_only_unverified")
        self.assertEqual(output_header_hint(b"\\x1f\\x8b\\x08" + b"x"),
                         "gzip_magic_only_unverified")
        self.assertEqual(output_header_hint(b"7z\\xbc\\xaf\\x27\\x1c"),
                         "7z_magic_only_unverified")
        self.assertEqual(output_header_hint(b"opaque"),
                         "unclassified")
        header = bytearray(128)
        header[:2] = b"MZ"
        header[0x3c:0x40] = (64).to_bytes(4, "little")
        header[64:68] = b"PE\\x00\\x00"
        header[68:70] = (0x14c).to_bytes(2, "little")
        header[88:90] = (0x10b).to_bytes(2, "little")
        self.assertEqual(output_header_hint(bytes(header)),
                         "partial_pe_header_candidate_not_validated")
        header[64:68] = b"FAIL"
        self.assertEqual(output_header_hint(bytes(header)),
                         "mz_prefix_only_unverified")

    def test_report_never_confuses_magic_with_format_validation(self):
        t, r, p = paired_fixture()
        out = compare(t, r, p)
        check = out["pair_checks"][0]
        self.assertEqual(check["candidate_output_header_hint"], "unclassified")
        self.assertFalse(check["output_format_verified"])
        self.assertFalse(out["output_format_classified"])

    def test_parse_hex_input_is_bounded(self):
        with self.assertRaises(DifferentialEvidenceError):
            parse_hex("ab" * 4097, "oversize")
        with self.assertRaises(DifferentialEvidenceError):
            parse_hex("", "empty")


if __name__ == "__main__":
    unittest.main()
