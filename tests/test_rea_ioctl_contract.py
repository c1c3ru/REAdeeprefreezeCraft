"""REA-008 user-mode IOCTL contract tests, synthetic control/API outcomes only."""
import hashlib
import pathlib
import tempfile
import unittest

from tools.rea_ioctl_contract import (
    ANCHORS, EXPECTED_CODES, ContractError, analyze_file, contract_document,
    hypothetical_caller, hypothetical_helper, validate_anchors,
)


class IoctlContractTests(unittest.TestCase):
    def test_eight_control_codes_ordered(self):
        doc = contract_document()
        self.assertEqual(len(doc["ioctl_code_candidates"]), 8)
        self.assertEqual(doc["ioctl_code_candidates"][0], "0x00071c08")
        self.assertEqual(doc["ioctl_code_candidates"][-1], "0x00071fec")

    def test_eight_ioctl_argument_slots_and_output_alias(self):
        doc = contract_document()
        args = doc["deviceiocontrol_arguments"]
        self.assertEqual([x["slot"] for x in args], list(range(1, 9)))
        self.assertEqual(args[2]["source"], "literal NULL")
        self.assertEqual(args[3]["source"], "literal 0")
        self.assertIn("[ebp+0xc]", args[4]["source"])
        self.assertIn("[ebp+0x10]", args[5]["source"])
        self.assertIn("[ebp+0x14]", args[6]["source"])
        self.assertIn("[ebp-0x4c]", doc["caller_arguments"][1]["source"])
        self.assertFalse(doc["behaviorally_equivalent"])

    def test_createfilea_arguments_and_handle_cleanup_evidence(self):
        doc = contract_document()
        args = doc["createfilea_arguments"]
        self.assertEqual([a["slot"] for a in args], list(range(1, 8)))
        self.assertIn("[esi]", args[0]["source"])
        self.assertIn("OPEN_EXISTING", args[4]["source"])
        self.assertIn("EBX", doc["closehandle_arguments"][0]["source"])
        self.assertIn("[ebp-0x13c]", doc["getsystemdirectorya_arguments"][0]["source"])

    def test_helper_no_system_directory_short_circuits(self):
        result = hypothetical_helper(False, [(True, True), (True, True)])
        self.assertEqual(result["return"], 0)
        self.assertEqual(result["attempts"], 0)

    def test_helper_first_path_success_closes_handle(self):
        result = hypothetical_helper(True, [(True, True), (False, False)])
        self.assertEqual(result["return"], 1)
        self.assertEqual(result["attempts"], 1)
        self.assertTrue(result["trace"][-1]["closed"])

    def test_helper_invalid_handle_skips_ioctl_and_close(self):
        result = hypothetical_helper(True, [(False, False), (False, False)])
        self.assertEqual(result["return"], 0)
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(len(result["trace"]), 2)

    def test_helper_ioctl_fails_then_second_succeeds(self):
        result = hypothetical_helper(True, [(True, False), (True, True)])
        self.assertEqual(result["return"], 1)
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(sum(1 for x in result["trace"] if x.get("closed")), 2)

    def test_caller_stops_at_first_success_even_invalid_output(self):
        outcomes = [(False, 0, 0)] * 3 + [(True, 0, 123)] + [(True, 4, 1)] * 4
        result = hypothetical_caller(outcomes)
        self.assertEqual(result["return"], 0)
        self.assertEqual(len(result["codes_attempted"]), 4)
        self.assertTrue(result["stopped_on_first_helper_success"])

    def test_caller_valid_four_byte_positive_output(self):
        outcomes = [(False, 0, 0)] * 7 + [(True, 4, 42)]
        result = hypothetical_caller(outcomes)
        self.assertEqual(result["return"], 1)
        self.assertEqual(len(result["codes_attempted"]), 8)

    def test_caller_rejects_zero_and_invalid_bytes_returned(self):
        for returned, value in [(4, 0), (3, 1), (5, 1), (4, -1)]:
            outcomes = [(True, returned, value)] + [(False, 0, 0)] * 7
            self.assertEqual(hypothetical_caller(outcomes)["return"], 0)

    def test_caller_all_fail_returns_zero(self):
        result = hypothetical_caller([(False, 0, 0)] * 8)
        self.assertEqual(result["return"], 0)
        self.assertEqual(len(result["codes_attempted"]), 8)
        self.assertFalse(result["stopped_on_first_helper_success"])

    def test_bad_outcome_count_rejected(self):
        with self.assertRaises(ValueError):
            hypothetical_caller([(False, 0, 0)])
        with self.assertRaises(ValueError):
            hypothetical_helper(True, [(False, False)])

    def test_anchors_are_strict_and_fail_closed(self):
        source = [
            {"va": va, "mnemonic": op, "operands": args or "stub"}
            for va, (op, args) in ANCHORS["caller"].items()
        ]
        self.assertEqual(len(validate_anchors(source, ANCHORS["caller"])),
                         len(ANCHORS["caller"]))
        source[-1]["operands"] = "tampered"
        with self.assertRaisesRegex(ContractError, "Operand mismatch"):
            validate_anchors(source, ANCHORS["caller"])

    def test_reject_nonmatching_pe_hash_before_objdump(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "foreign.exe"
            p.write_bytes(b"MZ" + b"\0" * 300)
            with self.assertRaisesRegex(ContractError, "SHA-256"):
                analyze_file(p)

    def test_model_reproducible(self):
        self.assertEqual(contract_document(), contract_document())
        self.assertEqual(hypothetical_caller([(True, 4, 1)] * 8),
                         hypothetical_caller([(True, 4, 1)] * 8))


if __name__ == "__main__":
    unittest.main()
