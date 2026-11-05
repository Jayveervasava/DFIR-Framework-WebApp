"""Build Table 8 (CP-DFIR vs Chainsaw vs Hayabusa on the same 117 held-out in-scope samples).

Reads  results/table8/chainsaw_per_sample.csv, results/table8/hayabusa_per_sample.csv  (written by run_chainsaw.py /
run_hayabusa.py on the laptop) and the CP-DFIR frozen v1.1 rows in results/heldout_frozen_v1.1.json.
Writes results/table8.csv and results/table8.md.  A tool whose per-sample file does not exist is printed as
"UNTESTED, run on laptop" - no number is invented for it.

  python scripts/table8.py             build the table
  python scripts/table8.py --selftest  check the parsers/matching on tiny made-up fixtures (does NOT test the real tools)
"""
import argparse
import csv
import json
import math
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as C  # noqa: E402


def wilson(k, n, z=1.96):
    if not n:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def cell(k, n):
    lo, hi = wilson(k, n)
    return f"{k}/{n} ({100 * k / n:.1f}%, 95% CI {100 * lo:.0f}-{100 * hi:.0f}%)"


def cpdfir_row(rows, frozen):
    ins = [r for r in frozen["rows"] if r["scope"] == "in"]
    a, e, p = sum(r["alerted"] for r in ins), sum(r["exact"] for r in ins), sum(r["parent_match"] for r in ins)
    assert (len(ins), a, e, p) == (frozen["in_scope"], frozen["in_alerted"], frozen["in_exact"], frozen["in_parent"]), "frozen json is inconsistent"
    return dict(tool="CP-DFIR (frozen v1.1)", version=f"rules fingerprint {frozen['rules_fingerprint']}", n=len(ins), alerted=a,
                alerted_any=a, parent=p, exact=e, errors=0, status="measured (results/heldout_frozen_v1.1.json)")


def tool_row(name, csv_path, meta_path, expected_files):
    if not os.path.exists(csv_path):
        return dict(tool=name, version="-", n=len(expected_files), alerted=None, alerted_any=None, parent=None, exact=None, errors=None,
                    status="UNTESTED, run on laptop")
    rows = list(csv.DictReader(open(csv_path, encoding="utf-8-sig")))
    got = {r["file"] for r in rows}
    if got != set(expected_files):
        raise SystemExit(f"{csv_path}: covers {len(got)} files, expected exactly the {len(expected_files)} in-scope samples "
                         f"(missing {len(set(expected_files) - got)}, extra {len(got - set(expected_files))}). Re-run the script without --limit.")
    meta = json.load(open(meta_path)) if os.path.exists(meta_path) else {}
    ver = meta.get("version", "?")
    rules = meta.get("sigma_commit") or meta.get("rules_commit") or ""
    errs = sum(1 for r in rows if r["status"].startswith(("error", "timeout", "unparsable")))
    ml = meta.get("min_level", "?")
    return dict(tool=name, version=f"{ver}; rules {rules[:10] or '?'}; alert = level >= {ml}", n=len(rows),
                alerted=sum(int(r["alerted"]) for r in rows), alerted_any=sum(int(r["alerted_any_level"]) for r in rows),
                parent=sum(int(r["parent_match"]) for r in rows), exact=sum(int(r["exact"]) for r in rows), errors=errs,
                status="measured" + (f" - {errs} samples errored and count as no alert" if errs else ""))


def build(out_dir=C.OUT_DIR, out_base=None):
    out_base = out_base or os.path.join(C.ROOT, "results")
    rows, frozen = C.load_inscope()
    files = [r["file"] for r in rows]
    table = [cpdfir_row(rows, frozen),
             tool_row("Chainsaw", os.path.join(out_dir, "chainsaw_per_sample.csv"), os.path.join(out_dir, "chainsaw_meta.json"), files),
             tool_row("Hayabusa", os.path.join(out_dir, "hayabusa_per_sample.csv"), os.path.join(out_dir, "hayabusa_meta.json"), files)]
    with open(os.path.join(out_base, "table8.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["tool", "version_rules", "in_scope_samples", "alert", "alert_any_level", "correct_technique_parent_level", "correct_technique_exact", "errored", "status"])
        for t in table:
            w.writerow([t["tool"], t["version"], t["n"]] + [("" if t[k] is None else t[k]) for k in ("alerted", "alerted_any", "parent", "exact", "errors")] + [t["status"]])
    md = ["| Tool | Alert (of 117) | Correct technique, parent level (of 117) | Correct technique, exact (of 117) | Status |", "|---|---|---|---|---|"]
    for t in table:
        if t["alerted"] is None:
            md.append(f"| {t['tool']} | - | - | - | **{t['status']}** |")
        else:
            md.append(f"| {t['tool']} | {cell(t['alerted'], t['n'])} | {cell(t['parent'], t['n'])} | {cell(t['exact'], t['n'])} | {t['status']} |")
    md += ["", "Versions / rule sets: " + "; ".join(f"{t['tool']}: {t['version']}" for t in table), "",
           "How to read this table (keep these caveats in the paper):",
           "- Same 117 samples for every tool: the held-out samples whose labelled technique CP-DFIR has a rule for (frozen v1.1 scope). "
           "This scope is defined by CP-DFIR's rules, so it favours CP-DFIR's coverage; Chainsaw/Hayabusa cover more techniques than these 117 test.",
           "- The sample files come from the Hayabusa sample collection; Hayabusa and Sigma rules may have been written with these files in view, "
           "so their numbers are not guaranteed to be held-out for them.",
           "- 'Alert' = at least one detection at the stated minimum level; 'correct technique' = an ATT&CK id in the rule tags matches the label "
           "(exact) or its parent technique, with the same equivalence list as heldout.py. Sigma/Hayabusa tags are the rule authors' mapping, CP-DFIR's is the author's own.",
           "- 95% CI = Wilson interval over samples; samples are not independent (many come from the same technique folders)."]
    open(os.path.join(out_base, "table8.md"), "w", encoding="utf-8").write("\n".join(md) + "\n")
    print("\n".join(md))
    return table


def selftest():
    import _common as c
    assert c.techs_from_text("attack.t1059.001, attack.execution, attack.T1027") == {"T1059.001", "T1027"}
    assert c.techs_from_text("T1059.001 ¦ T1027") == {"T1059.001", "T1027"}
    assert c.techs_from_text("attack.g0032 foo t12345") == set()
    assert c.judge("T1027", {"T1059"}) == (False, True)                    # EQUIV: T1027 ~ T1059.001 -> parent match, not exact
    assert c.judge("T1059.001", {"T1059.001"}) == (True, True)
    assert c.judge("T1059.001", {"T1059.003"}) == (False, True)            # same parent
    assert c.judge("T1003", {"T1021.002"}) == (False, False)
    js = json.dumps([{"name": "Rule A", "level": "high", "tags": ["attack.t1003.001"], "document": {"x": "T9999"}},
                     {"name": "Rule B", "level": "informational", "tags": ["attack.t1136.001"]},
                     {"name": "Rule C", "level": "low", "document": {"x": "T9999"}}])
    d = c.parse_chainsaw_json(js)
    assert [x["techs"] for x in d] == [{"T1003.001"}, {"T1136.001"}, set()], d
    assert c.parse_chainsaw_json("") == []
    assert len(c.parse_chainsaw_json("\n".join(json.dumps(x) for x in json.loads(js)))) == 3     # JSON lines
    with tempfile.TemporaryDirectory() as t:
        p = os.path.join(t, "h.csv")
        open(p, "w", encoding="utf-8").write("Timestamp,Level,RuleTitle,MitreTags\n2020,high,Rule A,T1003.001 ¦ T1027\n2020,info,Rule B,T1136.001\n")
        h = c.parse_hayabusa_csv(p)
        assert h[0]["techs"] == {"T1003.001", "T1027"} and h[1]["level"] == "info"
        r = c.finish_row(dict(file="f", label="T1003"), "ok", h, "low")
        assert (r["alerted"], r["alerted_any_level"], r["n_detections"], r["n_detections_any_level"], r["exact"], r["parent_match"]) == (1, 1, 1, 2, 0, 1), r
        r = c.finish_row(dict(file="f", label="T1136.001"), "ok", h[1:], "low")        # only an informational hit -> no alert at min level low
        assert (r["alerted"], r["alerted_any_level"], r["exact"]) == (0, 1, 0), r
        r = c.finish_row(dict(file="f", label="T1136.001"), "ok", [], "low")
        assert r["alerted"] == 0 and r["alerted_any_level"] == 0
    rows, fr = c.load_inscope()
    assert len(rows) == 117 and cpdfir_row(rows, fr)["alerted"] == 36
    print("selftest OK (parsers/matching on made-up fixtures; the real tools were NOT run)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    selftest() if a.selftest else build()
