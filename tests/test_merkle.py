"""Tests for per-finding Merkle proofs (merkle.py), the ledger binding (custody.py) and the pipeline step."""
import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import custody  # noqa: E402
import merkle  # noqa: E402
import pipeline  # noqa: E402

def _put(path, text, mode="w"):
    with open(path, mode) as fh:
        fh.write(text)


def _dump(path, obj):
    with open(path, "w") as fh:
        json.dump(obj, fh)


LEDGER_INFO = {"case_id": "T", "ledger_seq": 7, "ledger_entry_hash": "ab" * 32}


def make_findings(n):
    return [dict(event_id=f"E{i:06d}", time_utc=f"2026-09-20T08:{i % 60:02d}:00Z", source="windows", host=f"H{i}",
                 event_type="auth_failure", user="administrator", src_ip=f"203.0.113.{i % 250}", target=None,
                 outcome="failure", detail=f"detail {i}", source_file="windows_security.xml", line_ref=i,
                 flags=["brute_force"], techniques=["T1110"], incident="INC-1" if i % 2 else None,
                 raw="not part of the leaf", severity="medium") for i in range(1, n + 1)]


class TreeAndProofs(unittest.TestCase):
    def test_every_leaf_verifies_for_sizes(self):
        for n in (1, 2, 3, 7, 38):
            with self.subTest(leaves=n):
                f = make_findings(n)
                tree = merkle.build_tree(f)
                self.assertEqual(tree["leaf_count"], n)
                for e in f:
                    p = merkle.make_proof(tree, f, e["event_id"], LEDGER_INFO)
                    ok, why = merkle.verify_proof(p, trusted_root=tree["root"])
                    self.assertTrue(ok, why)
                    self.assertTrue(merkle.verify_proof(p)[0])
                    json.dumps(p)  # proof is plain JSON

    def test_contract_hashes(self):
        f = make_findings(2)
        fields = {k: f[0].get(k) for k in merkle.LEAF_FIELDS}
        canon = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        lh0 = hashlib.sha256(b"\x00" + canon).hexdigest()
        self.assertEqual(merkle.leaf_hash(f[0]), lh0)
        tree = merkle.build_tree(f)
        l1 = tree["leaves"][1]["leaf_hash"]
        self.assertEqual(tree["root"], hashlib.sha256(b"\x01" + bytes.fromhex(lh0) + bytes.fromhex(l1)).hexdigest())
        self.assertEqual(merkle.build_tree(f[:1])["root"], lh0)  # one leaf: root is the leaf hash

    def test_fields_outside_the_contract_do_not_change_the_leaf(self):
        f = make_findings(1)[0]
        g = dict(f, raw="other", severity="high", epoch=1.0)
        self.assertEqual(merkle.leaf_hash(f), merkle.leaf_hash(g))

    def test_order_is_event_id_ascending_and_input_order_is_irrelevant(self):
        f = make_findings(7)
        a = merkle.build_tree(f)
        b = merkle.build_tree(list(reversed(f)))
        self.assertEqual(a, b)
        self.assertEqual([l["event_id"] for l in a["leaves"]], sorted(e["event_id"] for e in f))

    def test_empty_tree(self):
        t = merkle.build_tree([])
        self.assertEqual((t["leaf_count"], t["root"]), (0, hashlib.sha256(b"").hexdigest()))
        with self.assertRaises(KeyError):
            merkle.make_proof(t, [], "E000001", LEDGER_INFO)

    def test_duplicate_event_id_rejected(self):
        f = make_findings(2)
        f[1]["event_id"] = f[0]["event_id"]
        with self.assertRaises(ValueError):
            merkle.build_tree(f)

    def test_changed_finding_fails(self):
        f = make_findings(7)
        tree = merkle.build_tree(f)
        p = merkle.make_proof(tree, f, "E000003", LEDGER_INFO)
        for field, value in (("user", "root"), ("src_ip", "198.51.100.9"), ("flags", []), ("incident", "INC-9"), ("line_ref", 999)):
            with self.subTest(field=field):
                q = copy.deepcopy(p)
                q["finding"][field] = value
                ok, why = merkle.verify_proof(q, trusted_root=tree["root"])
                self.assertFalse(ok)
        # attacker also recomputes leaf_hash for the changed finding: path no longer reaches the root
        q = copy.deepcopy(p)
        q["finding"]["user"] = "root"
        q["leaf_hash"] = merkle.leaf_hash(q["finding"])
        self.assertFalse(merkle.verify_proof(q, trusted_root=tree["root"])[0])
        # make_proof refuses to prove a finding that changed after the tree was built
        f2 = copy.deepcopy(f)
        f2[2]["user"] = "root"
        with self.assertRaises(ValueError):
            merkle.make_proof(tree, f2, "E000003", LEDGER_INFO)

    def test_wrong_path_root_or_side_fails(self):
        f = make_findings(7)
        tree = merkle.build_tree(f)
        p = merkle.make_proof(tree, f, "E000003", LEDGER_INFO)
        self.assertGreater(len(p["path"]), 1)
        q = copy.deepcopy(p)
        q["path"][0]["hash"] = "00" * 32
        self.assertFalse(merkle.verify_proof(q, trusted_root=tree["root"])[0])
        q = copy.deepcopy(p)
        q["path"][0]["side"] = "left" if q["path"][0]["side"] == "right" else "right"
        self.assertFalse(merkle.verify_proof(q, trusted_root=tree["root"])[0])
        q = copy.deepcopy(p)
        q["path"] = q["path"][:-1]
        self.assertFalse(merkle.verify_proof(q, trusted_root=tree["root"])[0])
        q = copy.deepcopy(p)
        q["path"].reverse()
        self.assertFalse(merkle.verify_proof(q)[0])
        q = copy.deepcopy(p)
        q["root"] = "11" * 32
        self.assertFalse(merkle.verify_proof(q)[0])
        self.assertFalse(merkle.verify_proof(p, trusted_root="11" * 32)[0])
        q = copy.deepcopy(p)
        q["index"] = (p["index"] + 1) % p["leaf_count"]
        self.assertFalse(merkle.verify_proof(q, trusted_root=tree["root"])[0])
        q = copy.deepcopy(p)
        q["leaf_count"] = 2          # index 2 no longer exists
        self.assertFalse(merkle.verify_proof(q, trusted_root=tree["root"])[0])
        q = copy.deepcopy(p)
        q["leaf_count"] = 4          # a different tree shape: the path length no longer fits
        self.assertFalse(merkle.verify_proof(q, trusted_root=tree["root"])[0])
        # known limit: leaf_count is not hashed into the root. Changing it to another value with the same path shape
        # still verifies offline; the ledger-bound check compares it with the ledger entry (see LedgerBinding).
        q = copy.deepcopy(p)
        q["leaf_count"] = 8
        self.assertTrue(merkle.verify_proof(q, trusted_root=tree["root"])[0])

    def test_malformed_proofs_fail_cleanly(self):
        f = make_findings(3)
        p = merkle.make_proof(merkle.build_tree(f), f, "E000001", LEDGER_INFO)
        for bad in (None, [], {}, dict(p, version=2), dict(p, path="x"), dict(p, index="0"), dict(p, root=5),
                    dict(p, path=[{"hash": "zz", "side": "left"}]), dict(p, finding=dict(p["finding"], extra=1))):
            ok, why = merkle.verify_proof(bad)
            self.assertFalse(ok, why)

    def test_odd_node_promotion_blocks_duplicate_leaf_attack(self):
        # 3 findings: the last one is promoted. The classic attack lists the last leaf twice (n+1 leaves) and expects
        # the same root; with promotion (no duplication) that must produce a different root and the old proofs must not verify.
        f = make_findings(3)
        tree = merkle.build_tree(f)
        dup = f + [dict(f[-1], event_id="E000004")]            # same content, new id (ids must be unique)
        self.assertNotEqual(merkle.build_tree(dup)["root"], tree["root"])
        # same event_id twice is refused outright
        with self.assertRaises(ValueError):
            merkle.build_tree(f + [copy.deepcopy(f[-1])])
        # a forged proof that claims a 4th, duplicated leaf with the sibling of the promoted node does not reach the root
        p = merkle.make_proof(tree, f, "E000003", LEDGER_INFO)
        # leaf 3 of 3 is promoted at level 0, then joined with node(leaf1, leaf2): exactly one step, from the left
        forged = copy.deepcopy(p)
        forged["leaf_count"] = 4
        forged["index"] = 3
        forged["path"] = [{"hash": p["leaf_hash"], "side": "left"}] + p["path"]
        self.assertFalse(merkle.verify_proof(forged, trusted_root=tree["root"])[0])
        # the odd leaf's real proof is shorter than a full-tree proof would be
        self.assertEqual(len(p["path"]), 1)

    def test_promoted_leaf_proof_has_no_self_sibling(self):
        f = make_findings(7)
        tree = merkle.build_tree(f)
        p = merkle.make_proof(tree, f, "E000007", LEDGER_INFO)
        self.assertEqual(len(p["path"]), 2)   # promoted at level 0, then joins node(5,6) and node(1..4) from the left
        self.assertEqual([s["side"] for s in p["path"]], ["left", "left"])
        self.assertNotIn(p["leaf_hash"], [s["hash"] for s in p["path"]])

    def test_leaf_cannot_pass_as_inner_node(self):
        # second-preimage defence: an inner node (0x01 prefix) can never be accepted as a leaf (0x00 prefix)
        f = make_findings(2)
        tree = merkle.build_tree(f)
        fake = {k: None for k in merkle.LEAF_FIELDS}
        fake["event_id"] = "E000001"
        fake["detail"] = tree["leaves"][0]["leaf_hash"] + tree["leaves"][1]["leaf_hash"]
        self.assertNotEqual(merkle.leaf_hash(fake), tree["root"])


class LedgerBinding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.ledger_path = os.path.join(self.tmp, "custody_ledger.jsonl")

    def _case(self, key=None, n=5):
        ledger = custody.CustodyLedger(self.ledger_path, key=key)
        f = make_findings(n)
        tree = merkle.build_tree(f)
        p = os.path.join(self.tmp, "merkle_tree.json")
        with open(p, "w") as fh:
            json.dump(tree, fh)
        other = os.path.join(self.tmp, "normalized_events.json")
        with open(other, "w") as fh:
            json.dump(f, fh)
        ledger.record("normalize", other)
        e = ledger.record("merkle", p, details={"root": tree["root"], "leaf_count": tree["leaf_count"], "algorithm": tree["algorithm"]})
        return ledger, f, tree, e

    def _rewrite_ledger(self, edit, key=None):
        """Edit one ledger entry and re-chain every hash (what an attacker without the HMAC key can do)."""
        with open(self.ledger_path) as fh:
            entries = [json.loads(l) for l in fh if l.strip()]
        edit(entries)
        prev = custody.GENESIS
        for e in entries:
            e["prev_hash"] = prev
            e["entry_hash"] = custody._entry_hash(e)
            prev = e["entry_hash"]
        with open(self.ledger_path, "w") as fh:
            for e in entries:
                fh.write(json.dumps(e) + "\n")

    def test_intact_case_has_passing_merkle_check(self):
        ledger, f, tree, e = self._case()
        ok, checks = ledger.verify()
        self.assertTrue(ok, checks)
        m = [c for c in checks if c["type"] == "merkle"]
        self.assertEqual(len(m), 1)
        self.assertTrue(m[0]["ok"])
        self.assertTrue(any(c["type"] == "file" and c["item"] == "merkle_tree.json" and c["ok"] for c in checks))

    def test_case_without_merkle_entry_is_unchanged(self):
        ledger = custody.CustodyLedger(self.ledger_path)
        p = os.path.join(self.tmp, "x.txt")
        _put(p, "x")
        ledger.record("acquire", p)
        ok, checks = ledger.verify()
        self.assertTrue(ok)
        self.assertFalse([c for c in checks if c["type"] == "merkle"])

    def test_tree_file_root_tamper_caught(self):
        ledger, f, tree, e = self._case()
        t = copy.deepcopy(tree)
        t["root"] = "22" * 32
        _dump(os.path.join(self.tmp, "merkle_tree.json"), t)
        ok, checks = ledger.verify()
        self.assertFalse(ok)
        self.assertTrue(any(c["type"] == "merkle" and not c["ok"] for c in checks))
        self.assertTrue(any(c["type"] == "file" and c["item"] == "merkle_tree.json" and not c["ok"] for c in checks))

    def test_tree_leaf_swapped_with_consistent_root_still_caught(self):
        # attacker replaces a leaf and recomputes the root inside the tree file; ledger root no longer matches
        ledger, f, tree, e = self._case()
        f[0]["user"] = "evil"
        t = merkle.build_tree(f)
        _dump(os.path.join(self.tmp, "merkle_tree.json"), t)
        ok, checks = ledger.verify()
        self.assertFalse(ok)
        m = [c for c in checks if c["type"] == "merkle"][0]
        self.assertFalse(m["ok"])
        self.assertIn("ledger", m["note"])

    def test_leaves_edited_but_root_left_alone_caught(self):
        ledger, f, tree, e = self._case()
        t = copy.deepcopy(tree)
        t["leaves"][0]["leaf_hash"] = "33" * 32
        _dump(os.path.join(self.tmp, "merkle_tree.json"), t)
        ok, checks = ledger.verify()
        self.assertFalse(ok)
        self.assertIn("recomputed", [c for c in checks if c["type"] == "merkle"][0]["note"])

    def test_tree_file_deleted(self):
        ledger, f, tree, e = self._case()
        os.remove(os.path.join(self.tmp, "merkle_tree.json"))
        ok, checks = ledger.verify()
        self.assertFalse(ok)
        self.assertTrue(any(c["type"] == "merkle" and "missing" in c["note"] for c in checks))

    def test_root_edited_in_ledger_caught(self):
        ledger, f, tree, e = self._case()
        with open(self.ledger_path) as fh:
            lines = fh.read().splitlines()
        entry = json.loads(lines[-1])
        entry["details"]["root"] = "44" * 32
        lines[-1] = json.dumps(entry)
        _put(self.ledger_path, "\n".join(lines) + "\n")
        ok, checks = custody.CustodyLedger(self.ledger_path).verify()
        self.assertFalse(ok)
        self.assertTrue(any(c["type"] == "ledger" and not c["ok"] and "altered" in c["note"] for c in checks))

    def test_rechained_ledger_root_caught_by_hmac_and_by_anchor(self):
        key = b"unit-test-key"
        ledger, f, tree, e = self._case(key=key)
        anchor = ledger.entries[-1]["entry_hash"]

        def edit(entries):
            entries[-1]["details"]["root"] = "55" * 32
        self._rewrite_ledger(edit)
        # chain is internally consistent again, but the HMAC cannot be recomputed without the key
        ok, checks = custody.CustodyLedger(self.ledger_path, key=key).verify(key=key)
        self.assertFalse(ok)
        self.assertTrue(any(c["type"] == "ledger" and "HMAC" in c["note"] and not c["ok"] for c in checks))
        # a plain (unkeyed) chain is only caught by a noted anchor
        os.remove(self.ledger_path)
        ledger, f, tree, e = self._case(key=None)
        anchor = ledger.entries[-1]["entry_hash"]
        self._rewrite_ledger(edit)
        ok, checks = custody.CustodyLedger(self.ledger_path).verify(anchor=anchor)
        self.assertFalse(ok)
        self.assertTrue(any(c["type"] == "anchor" and not c["ok"] for c in checks))

    def test_proof_checked_against_ledger(self):
        key = b"unit-test-key"
        ledger, f, tree, e = self._case(key=key)
        info = dict(case_id="T", ledger_seq=e["seq"], ledger_entry_hash=e["entry_hash"])
        p = merkle.make_proof(tree, f, "E000002", info)
        self.assertEqual(merkle.verify_proof_against_ledger(p, self.ledger_path, key=key)[0], True)
        q = copy.deepcopy(p)
        q["finding"]["host"] = "other"
        self.assertFalse(merkle.verify_proof_against_ledger(q, self.ledger_path, key=key)[0])
        q = dict(p, ledger_entry_hash="66" * 32)
        self.assertFalse(merkle.verify_proof_against_ledger(q, self.ledger_path, key=key)[0])
        q = dict(p, leaf_count=p["leaf_count"] + 3)
        self.assertFalse(merkle.verify_proof_against_ledger(q, self.ledger_path, key=key)[0])


class PipelineIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.key = b"pipeline-test-key"
        cls.ctx = pipeline.run_case(os.path.join(ROOT, "sample_logs", "S1"), os.path.join(cls.tmp, "S1"), make_report=False, key=cls.key)
        cls.case = os.path.join(cls.tmp, "S1")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def test_s1_has_38_findings_and_verifies(self):
        self.assertEqual(self.ctx["corr"]["alert_events"], 38)
        with open(os.path.join(self.case, "merkle_tree.json")) as fh:
            tree = json.load(fh)
        self.assertEqual(tree["leaf_count"], 38)
        self.assertEqual(set(tree), {"algorithm", "leaf_count", "root", "leaves"})
        self.assertTrue(self.ctx["custody_ok"], [c for c in self.ctx["custody_checks"] if not c["ok"]])
        self.assertTrue(any(c["type"] == "merkle" and c["ok"] for c in self.ctx["custody_checks"]))
        entry = [e for e in self.ctx["ledger"].entries if e["action"] == "merkle"]
        self.assertEqual(len(entry), 1)
        self.assertEqual(entry[0]["target"], "merkle_tree.json")
        self.assertEqual(entry[0]["details"], {"root": tree["root"], "leaf_count": 38, "algorithm": tree["algorithm"]})
        self.assertIn("hmac", entry[0])

    def test_every_s1_finding_has_valid_offline_proof(self):
        findings = [e for e in self.ctx["events"] if e["flags"]]
        self.assertEqual(len(findings), 38)
        tree = self.ctx["merkle_tree"]
        for e in findings:
            p = merkle.make_proof(tree, findings, e["event_id"], self.ctx["merkle_ledger_info"])
            p = json.loads(json.dumps(p))   # offline: only the JSON text travels
            self.assertTrue(merkle.verify_proof(p, trusted_root=tree["root"])[0], e["event_id"])
        p = merkle.make_proof(tree, findings, findings[0]["event_id"], self.ctx["merkle_ledger_info"])
        self.assertTrue(merkle.verify_proof_against_ledger(p, os.path.join(self.case, "custody_ledger.jsonl"), key=self.key)[0])

    def test_normalized_events_tamper_still_caught(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        case = os.path.join(tmp, "c")
        shutil.copytree(self.case, case)
        p = os.path.join(case, "normalized_events.json")
        _put(p, " ", "a")
        ok, checks = custody.CustodyLedger(os.path.join(case, "custody_ledger.jsonl"), key=self.key).verify(key=self.key)
        self.assertFalse(ok)

    def test_case_without_findings_does_not_crash(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        src = os.path.join(tmp, "in")
        shutil.copytree(os.path.join(ROOT, "sample_logs", "S1"), src)
        # keep only a handful of benign lines so no rule fires
        auth = os.path.join(src, "auth.log")
        with open(auth) as fh:
            keep = [l for l in fh.read().splitlines() if "Accepted publickey" in l][:3]
        _put(auth, "\n".join(keep) + "\n")
        for name in os.listdir(src):
            if name not in ("auth.log", "case_config.json"):
                p = os.path.join(src, name)
                shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
        ctx = pipeline.run_case(src, os.path.join(tmp, "out"), make_report=False)
        self.assertEqual(ctx["corr"]["alert_events"], 0)
        t = ctx["merkle_tree"]
        self.assertEqual((t["leaf_count"], t["root"]), (0, merkle.EMPTY_ROOT))
        self.assertTrue(ctx["custody_ok"], [c for c in ctx["custody_checks"] if not c["ok"]])


if __name__ == "__main__":
    unittest.main()
