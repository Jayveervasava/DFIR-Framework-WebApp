"""Web application (webapp/app.py): login, case, upload, analysis, custody verification and tamper detection."""
import importlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

try:
    import flask  # noqa: F401
    HAVE_FLASK = True
except ImportError:
    HAVE_FLASK = False

try:
    import merkle  # noqa: F401
    HAVE_MERKLE = True
except ImportError:                      # merkle.py is written by another part of the project; its tests wait for it
    HAVE_MERKLE = False

AUTH_LOG = b"""Oct 18 10:00:01 web01 sshd[1201]: Failed password for root from 45.33.12.9 port 51234 ssh2
Oct 18 10:00:03 web01 sshd[1201]: Failed password for root from 45.33.12.9 port 51235 ssh2
Oct 18 10:00:05 web01 sshd[1201]: Failed password for root from 45.33.12.9 port 51236 ssh2
Oct 18 10:00:07 web01 sshd[1201]: Failed password for root from 45.33.12.9 port 51237 ssh2
Oct 18 10:00:09 web01 sshd[1201]: Failed password for root from 45.33.12.9 port 51238 ssh2
Oct 18 10:00:20 web01 sshd[1201]: Accepted password for admin from 45.33.12.9 port 51240 ssh2
Oct 18 10:01:00 web01 sudo:    admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/sbin/useradd backdoor
"""


@unittest.skipUnless(HAVE_FLASK, "flask not installed")
class WebAppTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        os.environ["DFIR_DATA_DIR"] = cls.tmp
        sys.path.insert(0, os.path.join(ROOT, "webapp"))
        import app as A
        cls.A = importlib.reload(A)
        cls.c = cls.A.app.test_client()
        cls.H = {"X-Requested-With": "cpdfir"}

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("DFIR_DATA_DIR", None)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _wait(self, cid):
        for _ in range(300):
            if not self.c.get(f"/api/cases/{cid}").json["job"]:
                return
            time.sleep(0.1)
        self.fail("job did not finish")

    def test_end_to_end(self):
        c, H = self.c, self.H
        self.assertEqual(c.get("/api/cases").status_code, 401)
        self.assertTrue(c.post("/api/setup", json={"username": "analyst", "password": "password123", "name": "Test"}).json["ok"])
        self.assertEqual(c.post("/api/cases", json={"title": "x"}).status_code, 400)          # CSRF header missing
        cid = c.post("/api/cases", json={"title": "web01"}, headers=H).json["id"]
        r = c.post(f"/api/cases/{cid}/evidence", data={"files": [(io.BytesIO(AUTH_LOG), "auth.log"), (io.BytesIO(b"\x00\x01"), "x.bin")]},
                   headers=H, content_type="multipart/form-data").json["report"]
        self.assertEqual([x["ok"] for x in r], [True, False])
        self.assertEqual(r[0]["kind"], "linux_auth")
        c.post(f"/api/cases/{cid}/jobs/analyze", json={}, headers=H)
        self._wait(cid)
        res = c.get(f"/api/cases/{cid}/results").json
        self.assertTrue(res["ready"])
        self.assertEqual(len(res["incidents"]), 1)
        self.assertIn("brute_force", [f["rule"] for f in res["fired"]])
        self.assertTrue(c.post(f"/api/cases/{cid}/verify", headers=H).json["ok"])
        self.assertTrue(c.post(f"/api/cases/{cid}/tamper", json={"action": "evidence"}, headers=H).json["ok"])
        v = c.post(f"/api/cases/{cid}/verify", headers=H).json
        self.assertFalse(v["ok"])
        self.assertTrue(any("auth.log" in x["item"] for x in v["failed"]))
        c.post(f"/api/cases/{cid}/tamper", json={"action": "restore"}, headers=H)
        self.assertTrue(c.post(f"/api/cases/{cid}/verify", headers=H).json["ok"])
        ev = c.get(f"/api/cases/{cid}/events?flagged=1&q=backdoor").json
        self.assertEqual(ev["total"], 1)
        one = c.get(f"/api/cases/{cid}/events/{ev['rows'][0]['id']}").json
        self.assertIn("useradd backdoor", one["excerpt"])
        self.assertEqual(c.get(f"/api/cases/{cid}/file/report").status_code, 200)

    def test_classify(self):
        d = tempfile.mkdtemp()
        try:
            def f(name, data, hint=None):
                p = os.path.join(d, name)
                with open(p, "wb") as fh:
                    fh.write(data)
                return self.A.classify(name, p, hint)
            self.assertEqual(f("Security.evtx", b"ElfFile\x00" + b"\x00" * 100), "windows_evtx")
            self.assertEqual(f("export.xml", b"<Event xmlns='x'><System/></Event>"), "windows_xml")
            self.assertEqual(f("secure", AUTH_LOG), "linux_auth")
            self.assertEqual(f("trail.json", b'{"Records":[{"eventName":"ConsoleLogin"}]}'), "cloudtrail")
            self.assertEqual(f("processes.json", b"{}"), "host_artifact")
            self.assertEqual(f("manifest.json", b"{}", "cloud"), "cloud_state")
            self.assertIsNone(f("notes.txt", b"hello world"))
        finally:
            shutil.rmtree(d)


# ====================================================================== backend additions: Merkle routes, demo cases, public mode
H = {"X-Requested-With": "cpdfir"}
ENV_KEYS = ("DFIR_PUBLIC_MODE", "DFIR_DATA_DIR", "DFIR_SEED_DEMO", "DFIR_RETENTION_HOURS", "DFIR_GUEST", "DATABASE_URL")


def load_app(tmp, public=True, seed=False):
    """A fresh copy of the console (own data folder, own module state); returns (module, restore_environment)."""
    saved = {k: os.environ.get(k) for k in ENV_KEYS}
    os.environ.update(DFIR_DATA_DIR=tmp, DFIR_SEED_DEMO="1" if seed else "0", DFIR_RETENTION_HOURS="0")
    os.environ["DFIR_PUBLIC_MODE"] = "1" if public else "0"
    os.environ.pop("DATABASE_URL", None)
    os.environ.pop("DFIR_GUEST", None)
    spec = importlib.util.spec_from_file_location("app", os.path.join(ROOT, "webapp", "app.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, os.path.join(ROOT, "webapp"))
    spec.loader.exec_module(mod)
    mod.app.config["TESTING"] = True

    def restore():
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return mod, restore


def wait_idle(mod, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        if not any(j.status == "running" for j in list(mod.JOBS.values())):
            return
        time.sleep(0.1)
    raise AssertionError("jobs did not finish")


def wait_demos(mod, timeout=120):
    """Wait until every demo case is analysed with today's stamp and the worker has finished."""
    end = time.time() + timeout
    while time.time() < end:
        ok = True
        for key in mod.DEMOS:
            found = mod._demo_index().get(key)
            ok = ok and found is not None and mod._demo_task(found) is None
        if ok:
            wait_idle(mod)
            return
        time.sleep(0.2)
    raise AssertionError("demo cases were not analysed in time")


def add_merkle_if_missing(mod, cid):
    """Until the analysis step of the framework builds the tree itself: build it from the case's findings and record it in the
    custody ledger exactly as the contract says (merkle_tree.json + ledger entry action 'merkle')."""
    d = os.path.join(mod.CASES, cid, "case")
    tp = os.path.join(d, "merkle_tree.json")
    if os.path.exists(tp):
        return
    import merkle as mk
    with open(os.path.join(d, "normalized_events.json"), encoding="utf-8") as f:
        findings = [e for e in json.load(f) if e.get("flags")]
    tree = mk.build_tree(findings)
    with open(tp, "w", encoding="utf-8") as f:
        json.dump(tree, f)
    led = mod.CustodyLedger(os.path.join(d, "custody_ledger.jsonl"), key=mod.CUSTODY_KEY)
    e = led.record("merkle", tp, stage="Merkle", details={"root": tree["root"], "leaf_count": tree["leaf_count"], "algorithm": tree["algorithm"]})
    mod._set_anchor(cid, e["entry_hash"], "test")


class BackendBase(unittest.TestCase):
    public = True
    seed = False

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.mod, restore = load_app(self.tmp, public=self.public, seed=self.seed)
        self.addCleanup(restore)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.app = self.mod.app

    def guest(self):
        c = self.app.test_client()
        self.assertEqual(c.post("/api/guest", json={}, headers=H).status_code, 200)
        return c

    def analysed_case(self, c, scenario="S1"):
        cid = c.post("/api/cases", json={"title": "t"}, headers=H).get_json()["id"]
        r = c.post(f"/api/cases/{cid}/jobs/sample", json={"scenario": scenario, "analyze": True}, headers=H)
        self.assertEqual(r.status_code, 200, r.get_json())
        wait_idle(self.mod)
        self.assertTrue(c.get(f"/api/cases/{cid}/results").get_json()["ready"])
        return cid

    def flagged(self, cid):
        with open(os.path.join(self.mod.CASES, cid, "case", "normalized_events.json"), encoding="utf-8") as f:
            evs = json.load(f)
        return [e for e in evs if e.get("flags")], [e for e in evs if not e.get("flags")]


@unittest.skipUnless(HAVE_FLASK, "flask not installed")
class MerkleRoutes(BackendBase):
    def test_wrong_ids_are_clean_404(self):
        c = self.guest()
        cid = c.post("/api/cases", json={"title": "empty"}, headers=H).get_json()["id"]
        no_tree = 404 if HAVE_MERKLE else 501                                   # a real case that has no tree (or no Merkle layer)
        for url, want in (("/api/cases/NOPE/merkle", 404), ("/api/cases/NOPE/findings/E1/proof", 404),
                          ("/api/cases/..%2F..%2Fx/merkle", 404), (f"/api/cases/{cid}/merkle", no_tree),
                          (f"/api/cases/{cid}/findings/NOPE/proof", no_tree)):
            r = c.get(url)
            self.assertEqual(r.status_code, want, url)
            self.assertNotIn(b"Traceback", r.data)
            self.assertTrue(r.is_json and r.get_json()["error"], url)
        r = c.post("/api/verify-proof", json={"proof": {}, "case_id": "NOPE"}, headers=H)
        self.assertEqual(r.status_code, 404)
        self.assertNotIn(b"Traceback", r.data)

    def test_visitors_cannot_use_each_others_cases(self):
        a, b = self.guest(), self.guest()
        cid = a.post("/api/cases", json={"title": "private"}, headers=H).get_json()["id"]
        self.assertEqual(b.get(f"/api/cases/{cid}/merkle").status_code, 404)
        self.assertEqual(b.get(f"/api/cases/{cid}/findings/E1/proof").status_code, 404)
        self.assertEqual(b.post("/api/verify-proof", json={"proof": {}, "case_id": cid}, headers=H).status_code, 404)
        self.assertEqual(self.app.test_client().get(f"/api/cases/{cid}/merkle").status_code, 401)      # not signed in

    def test_verify_proof_input_checks(self):
        c = self.guest()
        self.assertEqual(c.post("/api/verify-proof", json={}, headers=H).status_code, 400)
        self.assertEqual(c.post("/api/verify-proof", data="not json", headers=H, content_type="text/plain").status_code, 400)
        self.assertEqual(c.post("/api/verify-proof", json={"proof": {}, "case_id": 7}, headers=H).status_code, 400)
        self.assertEqual(c.post("/api/verify-proof", json={"proof": {}}).status_code, 400)             # CSRF header missing

    @unittest.skipUnless(HAVE_MERKLE, "merkle.py not available yet")
    def test_merkle_proof_round_trip(self):
        c = self.guest()
        cid = self.analysed_case(c)
        add_merkle_if_missing(self.mod, cid)
        flagged, plain = self.flagged(cid)
        m = c.get(f"/api/cases/{cid}/merkle")
        self.assertEqual(m.status_code, 200)
        m = m.get_json()
        self.assertTrue(m["verified"], m.get("problems"))
        self.assertEqual(m["leaf_count"], len(flagged))
        self.assertTrue(m["root"] and m["ledger_seq"])
        eid = flagged[len(flagged) // 2]["event_id"]
        r = c.get(f"/api/cases/{cid}/findings/{eid}/proof")
        self.assertEqual(r.status_code, 200)
        cd = r.headers["Content-Disposition"]
        self.assertTrue(cd.startswith("attachment") and f"proof_{cid}_{eid}.json" in cd, cd)
        proof = json.loads(r.data)
        for k in ("version", "case_id", "event_id", "leaf_hash", "index", "leaf_count", "path", "root", "ledger_seq",
                  "ledger_entry_hash", "finding"):
            self.assertIn(k, proof)
        self.assertEqual((proof["case_id"], proof["event_id"], proof["root"]), (cid, eid, m["root"]))
        v = c.post("/api/verify-proof", json={"proof": proof, "case_id": cid}, headers=H).get_json()
        self.assertEqual((v["valid"], v["leaf_matches_finding"], v["root_matches_ledger"]), (True, True, True), v)
        v = c.post("/api/verify-proof", json={"proof": proof}, headers=H).get_json()                    # offline check, no case
        self.assertEqual((v["valid"], v["leaf_matches_finding"], v["root_matches_ledger"]), (True, None, None), v)
        # another visitor gets nothing from this analysed case: not the tree, not a proof, not a check against it
        other = self.guest()
        self.assertEqual(other.get(f"/api/cases/{cid}/merkle").status_code, 404)
        self.assertEqual(other.get(f"/api/cases/{cid}/findings/{eid}/proof").status_code, 404)
        self.assertEqual(other.post("/api/verify-proof", json={"proof": proof, "case_id": cid}, headers=H).status_code, 404)
        # an event without flags has no proof
        self.assertEqual(c.get(f"/api/cases/{cid}/findings/{plain[0]['event_id']}/proof").status_code, 404)
        self.assertEqual(c.get(f"/api/cases/{cid}/findings/NO-SUCH-EVENT/proof").status_code, 404)

    @unittest.skipUnless(HAVE_MERKLE, "merkle.py not available yet")
    def test_altered_proofs_are_rejected(self):
        c = self.guest()
        cid = self.analysed_case(c)
        add_merkle_if_missing(self.mod, cid)
        eid = self.flagged(cid)[0][0]["event_id"]
        proof = json.loads(c.get(f"/api/cases/{cid}/findings/{eid}/proof").data)

        def check(p, **kw):
            return c.post("/api/verify-proof", json=dict({"proof": p}, **kw), headers=H).get_json()
        p = json.loads(json.dumps(proof))
        p["finding"]["detail"] = "something else"
        self.assertFalse(check(p, case_id=cid)["valid"])
        p = json.loads(json.dumps(proof))
        p["root"] = "0" * 64
        v = check(p, case_id=cid)
        self.assertFalse(v["valid"])
        self.assertFalse(v["root_matches_ledger"])
        p = json.loads(json.dumps(proof))
        p["case_id"] = "CASE-1999-0001"
        self.assertFalse(check(p, case_id=cid)["valid"])
        v = check({"version": 1, "garbage": True}, case_id=cid)                                         # malformed: clean answer
        self.assertEqual((v["valid"], v["leaf_matches_finding"]), (False, False))

    @unittest.skipUnless(HAVE_MERKLE, "merkle.py not available yet")
    def test_changed_finding_is_detected(self):
        c = self.guest()
        cid = self.analysed_case(c)
        add_merkle_if_missing(self.mod, cid)
        eid = self.flagged(cid)[0][0]["event_id"]
        proof = json.loads(c.get(f"/api/cases/{cid}/findings/{eid}/proof").data)
        p = os.path.join(self.mod.CASES, cid, "case", "normalized_events.json")
        with open(p, encoding="utf-8") as f:
            evs = json.load(f)
        for e in evs:
            if e["event_id"] == eid:
                e["detail"] = "edited after analysis"
        with open(p, "w", encoding="utf-8") as f:
            json.dump(evs, f)
        os.utime(p, (time.time() + 5, time.time() + 5))                                                 # defeat the mtime cache
        m = c.get(f"/api/cases/{cid}/merkle").get_json()
        self.assertFalse(m["verified"])
        self.assertTrue(m["problems"])
        v = c.post("/api/verify-proof", json={"proof": proof, "case_id": cid}, headers=H).get_json()
        self.assertFalse(v["leaf_matches_finding"])
        self.assertEqual(c.get(f"/api/cases/{cid}/findings/{eid}/proof").status_code, 409)             # no proof for a damaged case


@unittest.skipUnless(HAVE_FLASK, "flask not installed")
class PublicModeFlags(BackendBase):
    def test_aws_collection_is_closed_in_public_mode(self):
        c = self.guest()
        self.assertFalse(c.get("/api/session").get_json()["aws_collect_enabled"])
        cid = c.post("/api/cases", json={"title": "aws"}, headers=H).get_json()["id"]
        r = c.post(f"/api/cases/{cid}/jobs/aws", json={"access_key": "AKIAEXAMPLEKEY123456", "secret_key": "x", "region": "us-east-1"}, headers=H)
        self.assertEqual(r.status_code, 403)
        self.assertIn("locally", r.get_json()["error"])
        self.assertIsNone(c.get(f"/api/cases/{cid}").get_json()["job"])                                  # no job was started
        self.assertEqual(r.get_json().get("run_locally"), True)
        with self.assertRaises(RuntimeError):                                                            # the job itself refuses too
            self.mod._job_aws(self.mod.Job(cid, "aws", "guest"), cid, {}, access_key="AKIAEXAMPLEKEY123456", secret_key="x")

    def test_can_reanalyse_flag(self):
        c = self.guest()
        self.assertFalse(c.get("/api/session").get_json()["can_reanalyse"])
        self.assertFalse(self.app.test_client().get("/api/session").get_json()["can_reanalyse"])        # not signed in
        # the shared demo case: read-only for a guest, also per case
        m = self.mod
        cid = "CASE-SHARED-01"
        os.makedirs(os.path.join(m.CASES, cid, "uploads"))
        m.save_meta({"id": cid, "title": "demo", "created": m._now(), "created_by": "system", "owner": "system", "shared": True,
                     "status": "new", "config": {k: m.fw_config.DEFAULT_CASE[k] for k in m.CFG_KEYS},
                     "evidence": [{"id": "x", "kind": "linux_auth", "name": "auth.log"}]})
        self.assertFalse(c.get(f"/api/cases/{cid}").get_json()["can_reanalyse"])
        self.assertEqual(c.post(f"/api/cases/{cid}/jobs/analyze", json={}, headers=H).status_code, 403)
        own = self.analysed_case(c)
        self.assertTrue(c.get(f"/api/cases/{own}").get_json()["can_reanalyse"])                         # a guest's own case can be analysed again

    def test_private_install_keeps_aws_and_reanalyse(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        mod, restore = load_app(tmp, public=False)
        self.addCleanup(restore)
        c = mod.app.test_client()
        self.assertTrue(c.post("/api/setup", json={"username": "analyst", "password": "password123", "name": "T"}).get_json()["ok"])
        s = c.get("/api/session").get_json()
        self.assertTrue(s["aws_collect_enabled"])
        self.assertTrue(s["can_reanalyse"])


@unittest.skipUnless(HAVE_FLASK, "flask not installed")
class DemoCases(BackendBase):
    seed = True

    def setUp(self):
        super().setUp()
        wait_demos(self.mod)

    def demo_ids(self):
        return self.mod._demo_index()

    def test_both_demo_cases_are_there_shared_and_read_only(self):
        ids = self.demo_ids()
        self.assertEqual(set(ids), {"s1_aws", "s1_pure"})
        self.assertEqual(ids["s1_pure"], "S1_pure")
        g = self.guest()
        listed = {x["id"]: x for x in g.get("/api/cases").get_json()}
        for cid in ids.values():
            self.assertIn(cid, listed)
            self.assertTrue(listed[cid]["shared"])
            self.assertFalse(listed[cid]["writable"])
            self.assertFalse(listed[cid]["can_reanalyse"])
            self.assertEqual(g.post(f"/api/cases/{cid}/jobs/analyze", json={}, headers=H).status_code, 403)
            self.assertTrue(g.get(f"/api/cases/{cid}/results").get_json()["ready"])

    def test_pure_demo_has_no_account_state(self):
        ids = self.demo_ids()

        def kinds(cid):
            return {e["kind"] for e in self.mod._read_json(os.path.join(self.mod.CASES, cid, "case.json"))["evidence"]}
        self.assertNotIn("cloud_state", kinds(ids["s1_pure"]))
        self.assertIn("cloud_state", kinds(ids["s1_aws"]))
        flagged, plain = self.flagged(ids["s1_pure"])
        run = self.mod._read_json(os.path.join(self.mod.CASES, "S1_pure", "case.json"))["last_run"]
        self.assertEqual(run["events"], len(flagged) + len(plain))
        self.assertEqual(run["events"], 244)                                   # scenario S1 as generated by generate_data.py
        self.assertEqual(run["alerts"], len(flagged))
        self.assertFalse([e for e in flagged + plain if e["event_type"] in self.mod.CLOUD_STATE_TYPES])
        self.assertGreater(len(self.flagged(ids["s1_aws"])[0]), len(flagged))                            # the other demo has the posture findings too

    def test_analysis_stamp_is_stored_with_the_case(self):
        import heldout
        for cid in self.demo_ids().values():
            m = self.mod._read_json(os.path.join(self.mod.CASES, cid, "case.json"))
            self.assertEqual(m["analysis_stamp"]["rules_fingerprint"], heldout.rules_fingerprint())
            self.assertEqual(m["analysis_stamp"]["rules"], len(self.mod.FLAGS))

    def test_demo_is_analysed_again_when_the_rule_set_changed(self):
        ids = self.demo_ids()
        old_dir = os.path.join(self.mod.CASES, ids["s1_pure"])
        keep_dir = os.path.join(self.mod.CASES, ids["s1_aws"])
        for d in (old_dir, keep_dir):
            with open(os.path.join(d, "case", "OLD_ANALYSIS_MARKER"), "w") as f:       # disappears only if the case is analysed again
                f.write("x")
        meta_p = os.path.join(old_dir, "case.json")
        m = self.mod._read_json(meta_p)
        before = [e["sha256"] for e in m["evidence"]]
        m["analysis_stamp"]["rules_fingerprint"] = "0" * 64                              # as if analysed with an older rule set
        m["analysis_stamp"]["rules"] = 57
        self.mod._write_json(meta_p, m)
        self.assertEqual(self.mod._demo_task("S1_pure")[0], "reanalyse")
        self.assertIsNone(self.mod._demo_task(ids["s1_aws"]))
        # restart of the console on the same data folder
        mod2, restore = load_app(self.tmp, public=True, seed=True)
        self.addCleanup(restore)
        wait_demos(mod2)
        m2 = mod2._read_json(meta_p)
        self.assertEqual(m2["analysis_stamp"]["rules_fingerprint"], mod2.rules_fingerprint())
        self.assertEqual(m2["analysis_stamp"]["rules"], len(mod2.FLAGS))
        self.assertEqual([e["sha256"] for e in m2["evidence"]], before)                  # the evidence was not touched
        self.assertFalse(os.path.exists(os.path.join(old_dir, "case", "OLD_ANALYSIS_MARKER")))
        self.assertTrue(os.path.exists(os.path.join(keep_dir, "case", "OLD_ANALYSIS_MARKER")))     # the up-to-date demo was left alone
        g = mod2.app.test_client()
        g.post("/api/guest", json={}, headers=H)
        self.assertTrue(g.get("/api/cases/S1_pure/results").get_json()["ready"])
        self.assertTrue(g.post("/api/cases/S1_pure/verify", headers=H).get_json()["ok"])

    def test_demo_of_an_older_version_is_adopted_not_duplicated(self):
        ids = self.demo_ids()
        aws, case_ids = ids["s1_aws"], lambda: sorted(x for x in os.listdir(self.mod.CASES))
        meta_p = os.path.join(self.mod.CASES, aws, "case.json")
        m = self.mod._read_json(meta_p)
        m.pop("demo"), m.pop("analysis_stamp")                                           # what the live demo looks like today
        self.mod._write_json(meta_p, m)
        shutil.rmtree(os.path.join(self.mod.CASES, "S1_pure"))
        mod2, restore = load_app(self.tmp, public=True, seed=True)
        self.addCleanup(restore)
        wait_demos(mod2)
        self.assertEqual(sorted(os.listdir(mod2.CASES)), sorted([aws, "S1_pure"]))
        self.assertEqual(mod2._demo_index(), {"s1_aws": aws, "s1_pure": "S1_pure"})
        self.assertEqual(mod2._read_json(meta_p)["analysis_stamp"]["rules_fingerprint"], mod2.rules_fingerprint())

    def test_failed_reanalysis_puts_the_old_results_back(self):
        cid = "S1_pure"
        d = os.path.join(self.mod.CASES, cid, "case")
        with open(os.path.join(d, "OLD_ANALYSIS_MARKER"), "w") as f:
            f.write("x")
        stamp = self.mod._read_json(os.path.join(self.mod.CASES, cid, "case.json"))["analysis_stamp"]
        real = self.mod.pipeline.run_case

        def broken(inp, out, *a, **k):
            shutil.rmtree(out)                                                              # run_case cleans the folder first ...
            raise RuntimeError("boom")                                                      # ... and then the run dies
        self.mod.pipeline.run_case = broken
        try:
            with self.assertRaises(RuntimeError):
                self.mod._reanalyse_keeping_old(self.mod.Job(cid, "analyze", "system"), cid, {"name": "Demo Analyst"})
        finally:
            self.mod.pipeline.run_case = real
        self.assertTrue(os.path.exists(os.path.join(d, "OLD_ANALYSIS_MARKER")))
        self.assertTrue(os.path.exists(os.path.join(d, "incidents.json")))
        self.assertEqual(self.mod._read_json(os.path.join(self.mod.CASES, cid, "case.json"))["analysis_stamp"], stamp)
        self.assertFalse(os.path.exists(os.path.join(self.mod.TMP, f"{cid}.previous-analysis")))

    @unittest.skipUnless(HAVE_MERKLE, "merkle.py not available yet")
    def test_guest_can_read_and_check_proofs_of_the_demo(self):
        add_merkle_if_missing(self.mod, "S1_pure")
        g = self.guest()
        m = g.get("/api/cases/S1_pure/merkle").get_json()
        self.assertTrue(m["verified"], m.get("problems"))
        eid = self.flagged("S1_pure")[0][0]["event_id"]
        r = g.get(f"/api/cases/S1_pure/findings/{eid}/proof")
        self.assertEqual(r.status_code, 200)
        v = g.post("/api/verify-proof", json={"proof": json.loads(r.data), "case_id": "S1_pure"}, headers=H).get_json()
        self.assertTrue(v["valid"] and v["leaf_matches_finding"] and v["root_matches_ledger"], v)


@unittest.skipUnless(HAVE_FLASK, "flask not installed")
class MirrorHold(unittest.TestCase):
    """persist.Mirror.hold(): no upload or delete while a case is being rebuilt (no database needed for this check)."""

    def test_sync_waits_while_held(self):
        sys.path.insert(0, os.path.join(ROOT, "webapp"))
        import persist
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        with open(os.path.join(tmp, "a.txt"), "w") as f:
            f.write("new")
        mir = persist.Mirror.__new__(persist.Mirror)
        mir.root, mir.state, mir.holds, mir.lock, mir.dirty = tmp, {"gone.txt": (1, 1)}, 0, threading.Lock(), threading.Event()
        calls = []

        class Conn:
            def __enter__(s):
                return s

            def __exit__(s, *a):
                return False

            def execute(s, sql, *a):
                calls.append(sql.split()[0])
        mir._conn = lambda: Conn()
        with mir.hold():
            self.assertEqual(mir.sync(), 0)
            self.assertEqual(calls, [])                                                    # nothing uploaded, nothing deleted
            self.assertEqual(mir.state, {"gone.txt": (1, 1)})                              # and the changes are still pending
        self.assertTrue(mir.dirty.is_set())                                                # leaving the hold asks for a sync
        self.assertEqual(mir.sync(), 2)                                                    # a.txt uploaded, gone.txt deleted
        self.assertEqual(calls, ["INSERT", "DELETE"])


if __name__ == "__main__":
    unittest.main()
