"""REA-007 bounded path/exit tests. Synthetic control-flow only."""
import os
import tempfile
import unittest

from tools.rea_path_coverage import analyze_file, analyze_paths, markdown
from tests.test_rea_loop import fixture_with_call


def inst(va, size, mnemonic, operands=""):
    return {"va": va, "size": size, "mnemonic": mnemonic, "operands": operands}


class ExitPathTests(unittest.TestCase):
    def test_two_outcomes_and_two_returns(self):
        instructions = [
            inst(0x100, 2, "cmp", "esi,0x8"),
            inst(0x102, 2, "jb", "0x107"),
            inst(0x104, 1, "ret"),
            inst(0x107, 1, "ret"),
        ]
        r = analyze_paths(instructions, 0x100)
        self.assertEqual(r["conditional_count"], 1)
        self.assertEqual(r["conditional_sites"][0]["explored_outcomes"],
                         ["not_taken", "taken"])
        self.assertEqual(r["conditional_sites"][0]["predicate_candidate"]["operands"],
                         "esi,0x8")
        self.assertEqual(r["terminal_path_samples"]["explicit_return"], 2)
        self.assertTrue(r["all_syntactic_outcomes_explored"])

    def test_loop_is_cut_and_not_counted_as_return(self):
        instructions = [
            inst(0x200, 1, "inc", "esi"),
            inst(0x201, 2, "jb", "0x200"),
            inst(0x203, 1, "ret"),
        ]
        r = analyze_paths(instructions, 0x200)
        self.assertEqual(r["conditional_count"], 1)
        self.assertGreaterEqual(r["terminal_path_samples"]["loop_visit_limit"], 1)
        self.assertEqual(r["terminal_path_samples"]["explicit_return"], 2)
        self.assertEqual(len(r["backward_edges"]), 1)

    def test_indirect_jump_is_not_converted_to_fallthrough(self):
        r = analyze_paths([inst(0x100, 2, "jmp", "eax")], 0x100)
        self.assertEqual(r["terminal_path_samples"]["indirect_or_unresolved_target"], 1)
        self.assertEqual(r["return_sites"], [])
        self.assertFalse(r["unresolved_edges"] == [])

    def test_out_of_window_conditional_target_is_unresolved(self):
        r = analyze_paths([
            inst(0x100, 2, "je", "0x200"),
            inst(0x102, 1, "ret"),
        ], 0x100)
        self.assertEqual(r["terminal_path_samples"]["edge_out_of_window"], 1)
        self.assertEqual(r["terminal_path_samples"]["explicit_return"], 1)
        self.assertEqual(r["conditional_sites"][0]["outcomes"][1]["in_window"], False)

    def test_call_is_assumed_to_return_not_proven(self):
        r = analyze_paths([
            inst(0x100, 5, "call", "0x500"),
            inst(0x105, 1, "ret"),
        ], 0x100)
        self.assertEqual(r["terminal_path_samples"]["explicit_return"], 1)
        self.assertTrue(any("non-returning" in s for s in r["warnings"]))

    def test_small_state_cap_reports_truncation(self):
        r = analyze_paths([
            inst(0x100, 2, "je", "0x104"),
            inst(0x102, 1, "ret"),
            inst(0x104, 1, "ret"),
        ], 0x100, max_states=1)
        self.assertTrue(r["truncated"])
        self.assertFalse(r["all_syntactic_outcomes_explored"])

    def test_small_path_cap_reports_truncation(self):
        r = analyze_paths([
            inst(0x100, 2, "je", "0x104"),
            inst(0x102, 1, "ret"),
            inst(0x104, 1, "ret"),
        ], 0x100, max_paths=1)
        self.assertTrue(r["truncated"])

    def test_invalid_limits_rejected(self):
        with self.assertRaises(ValueError):
            analyze_paths([inst(0x100, 1, "ret")], 0x100, max_visits=0)
        with self.assertRaises(ValueError):
            analyze_paths([inst(0x100, 1, "ret")], 0x100, max_paths=10001)

    def test_unreachable_branch_not_reported(self):
        r = analyze_paths([
            inst(0x100, 1, "ret"),
            inst(0x101, 2, "je", "0x105"),
            inst(0x103, 1, "ret"),
            inst(0x105, 1, "ret"),
        ], 0x100)
        self.assertEqual(r["conditional_count"], 0)
        self.assertEqual(r["reachable_instruction_count"], 1)

    def test_determinism(self):
        insns = [
            inst(0x100, 2, "jne", "0x104"),
            inst(0x102, 1, "ret"),
            inst(0x104, 1, "ret"),
        ]
        self.assertEqual(analyze_paths(insns, 0x100), analyze_paths(insns, 0x100))

    def test_fails_closed_on_unrecognized_binary_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = os.path.join(directory, "fixture.exe")
            with open(filename, "wb") as stream:
                stream.write(fixture_with_call())
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                analyze_file(filename)


if __name__ == "__main__":
    unittest.main()
