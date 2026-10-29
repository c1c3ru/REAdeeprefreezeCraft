import unittest
from tools.rea_runtime_buffer_lineage import validate, LineageError

A = "a" * 64
B = "b" * 64


def sample():
    return {"schema": "rea-015-buffer-lineage-v1", "events": [
        {"seq": 1, "pid": 42, "kind": "open", "handle": "0x40"},
        {"seq": 2, "pid": 42, "kind": "read", "handle": "0x40",
         "read_id": "r1", "buffer_pointer": "0x1000", "length": 96, "buffer_sha256": A},
        {"seq": 3, "pid": 42, "kind": "transform", "read_id": "r1",
         "input_pointer": "0x1000", "length": 96, "before_sha256": A, "after_sha256": B},
        {"seq": 4, "pid": 42, "kind": "close", "handle": "0x40"}]}


class LineageTests(unittest.TestCase):
    def test_consistent_direct_lineage(self):
        output = validate(sample())
        self.assertEqual(output["direct_matches"], 1)
        self.assertFalse(output["runtime_authenticated"])
        self.assertFalse(output["transformation_semantics_proven"])

    def test_other_address_does_not_prove_copy(self):
        obj = sample()
        obj["events"][2]["input_pointer"] = "0x2000"
        self.assertEqual(validate(obj)["direct_matches"], 0)

    def test_changed_before_hash_is_not_proven(self):
        obj = sample()
        obj["events"][2]["before_sha256"] = B
        self.assertEqual(validate(obj)["direct_matches"], 0)

    def test_orphan_transform_rejected(self):
        obj = sample()
        obj["events"][2]["read_id"] = "absent"
        with self.assertRaises(LineageError):
            validate(obj)

    def test_close_before_transform_rejected(self):
        obj = sample()
        obj["events"][2], obj["events"][3] = obj["events"][3], obj["events"][2]
        obj["events"][2]["seq"] = 3
        obj["events"][3]["seq"] = 4
        with self.assertRaises(LineageError):
            validate(obj)

    def test_duplicate_read_rejected(self):
        obj = sample()
        obj["events"].insert(2, dict(obj["events"][1], seq=3))
        for index, row in enumerate(obj["events"], 1):
            row["seq"] = index
        with self.assertRaises(LineageError):
            validate(obj)


if __name__ == "__main__":
    unittest.main()
