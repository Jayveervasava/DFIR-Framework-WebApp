"""Shared helpers for the Table 8 scripts (Chainsaw / Hayabusa on the held-out in-scope samples).

Matching rule = exactly the one heldout.py uses for CP-DFIR, so the three tools are scored the same way:
  exact        a reported technique equals the label (or one of its EQUIV equivalents)
  parent_match a reported technique has the same parent technique as the label (or its equivalents)
"""
import csv
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import heldout  # noqa: E402  (EQUIV, parent: same definitions as the CP-DFIR held-out run)

FROZEN = os.path.join(ROOT, "results", "heldout_frozen_v1.1.json")
OUT_DIR = os.path.join(ROOT, "results", "table8")
LEVELS = {"informational": 0, "info": 0, "low": 1, "medium": 2, "med": 2, "high": 3, "critical": 4, "crit": 4}
_TECH = re.compile(r"(?<![A-Za-z0-9])[Tt](\d{4})(?:\.(\d{3}))?(?!\d)")
FIELDS = ["file", "label", "status", "n_detections", "n_detections_any_level", "alerted", "alerted_any_level",
          "reported_techniques", "exact", "parent_match", "top_rules"]


def load_inscope(path=FROZEN):
    """The in-scope held-out samples of the frozen v1.1 run (117), as stored in results/heldout_frozen_v1.1.json."""
    d = json.load(open(path, encoding="utf-8"))
    rows = [dict(file=r["file"], label=r["label"], corpus=r["corpus"]) for r in d["rows"] if r["scope"] == "in"]
    if len(rows) != d["in_scope"]:
        raise SystemExit(f"{path}: {len(rows)} in-scope rows but in_scope={d['in_scope']}")
    return rows, d


def techs_from_text(s):
    return {f"T{a}" + (f".{b}" if b else "") for a, b in _TECH.findall(s or "")}


def level_rank(x):
    return LEVELS.get(str(x or "").strip().lower())          # None = level missing/unknown


def judge(label, techs):
    ok_set = heldout.EQUIV.get(label, {label})
    exact = bool(set(techs) & ok_set)
    par = bool({heldout.parent(t) for t in techs} & {heldout.parent(x) for x in ok_set})
    return exact, par


def summarise_detections(dets, min_level):
    """dets: list of dict(level, title, techs). Returns the numeric part of a per-sample row."""
    mr = LEVELS[min_level]
    kept = [d for d in dets if (level_rank(d["level"]) is not None and level_rank(d["level"]) >= mr)]
    techs = sorted({t for d in kept for t in d["techs"]})
    titles = []
    for d in kept:
        if d["title"] and d["title"] not in titles:
            titles.append(d["title"])
    return dict(n_detections=len(kept), n_detections_any_level=len(dets), alerted=int(bool(kept)),
                alerted_any_level=int(bool(dets)), reported_techniques="|".join(techs), top_rules=" | ".join(titles[:3]),
                _techs=techs)


def finish_row(sample, status, dets, min_level):
    r = summarise_detections(dets, min_level)
    exact, par = judge(sample["label"], r.pop("_techs"))
    r.update(file=sample["file"], label=sample["label"], status=status, exact=int(exact), parent_match=int(par))
    return r


def parse_chainsaw_json(text):
    """Chainsaw `hunt --json` output: a JSON array (or JSON lines) of detections. Technique ids come from the rule tags
    (attack.t1059.001). ASSUMED FORMAT - not checked against a real Chainsaw run."""
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        data = [json.loads(l) for l in text.splitlines() if l.strip()]
    if isinstance(data, dict):
        data = [data]
    out = []
    for d in data:
        if not isinstance(d, dict):
            continue
        tags = d.get("tags") or (d.get("rule") or {}).get("tags") or []
        techs = techs_from_text(" ".join(str(t) for t in tags))
        if not tags:                                         # fallback: scan everything except the raw event(s)
            rest = {k: v for k, v in d.items() if k not in ("document", "documents")}
            techs = techs_from_text(json.dumps(rest))
        out.append(dict(level=d.get("level") or (d.get("rule") or {}).get("level"),
                        title=d.get("name") or (d.get("rule") or {}).get("title") or "", techs=techs))
    return out


def parse_hayabusa_csv(path):
    """Hayabusa csv-timeline output with `-p verbose`: columns Level, RuleTitle, MitreTags (e.g. 'T1059.001 ¦ T1027').
    ASSUMED FORMAT - not checked against a real Hayabusa run."""
    out = []
    with open(path, encoding="utf-8-sig", newline="") as f:
        rd = csv.DictReader(f)
        need = {"Level", "RuleTitle", "MitreTags"}
        if not need <= set(rd.fieldnames or []):
            raise ValueError(f"{path}: expected columns {sorted(need)}, found {rd.fieldnames}")
        for r in rd:
            out.append(dict(level=r["Level"], title=r["RuleTitle"], techs=techs_from_text(r["MitreTags"])))
    return out


def write_per_sample(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in FIELDS})


def sample_path(samples_dir, rel):
    return os.path.join(samples_dir, *rel.split("/"))


def raw_name(rel):
    import hashlib
    return hashlib.sha1(rel.encode()).hexdigest()[:12]


def check_samples(rows, samples_dir):
    missing = [r["file"] for r in rows if not os.path.exists(sample_path(samples_dir, r["file"]))]
    if missing:
        raise SystemExit(f"{len(missing)} of {len(rows)} samples are missing under {samples_dir} (first: {missing[0]}).\n"
                         "Download them first:  python -c \"import heldout; heldout.fetch('.')\"   (needs internet, fetches the pinned Hayabusa sample commit)")
