"""False-alarm measurement on logs YOU assert are benign (paper Sections 6.3 and 7.3).

No labelled real benign log set ships with the repository and none could be downloaded in the sandbox, so
*no false-positive rate has been measured so far*. This script measures it once you point it at a benign set.

It runs the CURRENT detection rules (fingerprint printed and stored) on every file and reports
  * events with at least one alert / supported events      (event-level rate, with Wilson 95% interval)
  * share of files with at least one alert                  (file-level rate)
  * alerts per 1,000 supported events and which rules fired (so the false positives can be read one by one)
Every alert on benign data counts as a false positive. The word "rate" is only printed when --assert-benign is given
AND the data come from several independent sources (--n-sources >= 2); a one-host result is printed as a single data point.

Examples
  python scripts/benign_fp.py --dir real_data/benign_evtx --assert-benign --n-sources 12 --source "NextronSystems/evtx-baseline @<commit>"
  python scripts/benign_fp.py --dir D:\\logs\\linux --linux --assert-benign --n-sources 5 --source "my 5 clean servers"
  python scripts/benign_fp.py --dir real_data/heldout/DeepBlueCLI     (no --assert-benign: output says 'alerts per 1000, not a FP rate')
Where to get benign logs: see scripts/README.md ("Benign data").
"""
import argparse
import collections
import json
import math
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as C  # noqa: E402,F401  (puts the repo root on sys.path)

import config  # noqa: E402
import correlate  # noqa: E402
import heldout  # noqa: E402
import normalize  # noqa: E402


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(100 * max(0.0, c - h), 3), round(100 * min(1.0, c + h), 3)]


def find_files(root, linux):
    exts = (".log", ".txt") if linux else (".evtx", ".xml")
    out = []
    for dp, _, fs in os.walk(root):
        out += [os.path.join(dp, f) for f in fs if f.lower().endswith(exts)]
    return sorted(out)


def measure(files, linux, tz="+00:00", year=2024, log=print):
    cfg = config.load_case_config(None)
    rows = []
    for i, p in enumerate(files, 1):
        try:
            ev, st = normalize.parse_linux(p, tz, year) if linux else normalize.parse_windows(p)
        except Exception as e:                                           # noqa: BLE001  (e.g. python-evtx cannot decode the file)
            rows.append(dict(file=p, error=str(e)[:200], records=0, supported=0, alerted_events=0, flags={}))
            continue
        for k, e in enumerate(ev, 1):
            e["event_id"] = f"E{k}"
        if ev:
            correlate.correlate(ev, cfg)
        flags = collections.Counter(f for e in ev for f in e["flags"])
        rows.append(dict(file=p, error=None, records=st["records_seen"], supported=st["normalized"],
                         alerted_events=sum(1 for e in ev if e["flags"]), flags=dict(flags)))
        if i % 25 == 0:
            log(f"  {i}/{len(files)}")
    return rows


def summarise(rows, a):
    ok = [r for r in rows if not r["error"]]
    sup = sum(r["supported"] for r in ok)
    alev = sum(r["alerted_events"] for r in ok)
    nal = sum(sum(r["flags"].values()) for r in ok)
    files_alert = sum(1 for r in ok if r["alerted_events"])
    rules = collections.Counter()
    for r in ok:
        rules.update(r["flags"])
    is_rate = bool(a.assert_benign and a.n_sources >= 2)
    return dict(
        source=a.source, asserted_benign=bool(a.assert_benign), n_sources=a.n_sources, is_rate=is_rate,
        rules_fingerprint=heldout.rules_fingerprint()[:16], files=len(rows), files_unreadable=len(rows) - len(ok),
        records=sum(r["records"] for r in ok), supported_events=sup, events_with_alert=alev, alerts=nal,
        event_level_fp_pct=round(100 * alev / sup, 4) if sup else None, event_level_ci95_pct=wilson(alev, sup),
        files_with_alert=files_alert, file_level_fp_pct=round(100 * files_alert / len(ok), 2) if ok else None,
        file_level_ci95_pct=wilson(files_alert, len(ok)), alerts_per_1000_events=round(1000 * nal / sup, 2) if sup else None,
        by_rule=dict(rules.most_common()), per_file=rows,
        caveats=["Event-level interval treats events as independent; events on one host are correlated, so it is too narrow.",
                 "Result is valid only for the data set used (OS, roles, volume); it is not a general false-positive rate.",
                 "Clean-install baselines contain little user/admin activity; enterprise noise is likely higher."])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--linux", action="store_true", help="the files are Linux auth.log style text logs (default: Windows .evtx/.xml)")
    ap.add_argument("--assert-benign", action="store_true", help="I confirm these logs contain no attack activity (needed to call alerts false positives)")
    ap.add_argument("--n-sources", type=int, default=1, help="number of independent hosts/systems the files come from")
    ap.add_argument("--source", default="", help="provenance (dataset name + commit/URL) - stored with the result")
    ap.add_argument("--tz", default="+00:00", help="Linux log timezone offset")
    ap.add_argument("--year", type=int, default=2024, help="Linux log year (syslog lines carry none)")
    ap.add_argument("--out", default=os.path.join(C.ROOT, "results", "benign_fp.json"))
    a = ap.parse_args()
    files = find_files(a.dir, a.linux)
    if not files:
        raise SystemExit(f"No {'text' if a.linux else '.evtx/.xml'} files under {a.dir}")
    t0 = time.time()
    s = summarise(measure(files, a.linux, a.tz, a.year), a)
    s["seconds"] = round(time.time() - t0, 1)
    json.dump(s, open(a.out, "w", encoding="utf-8"), indent=1)
    kind = "false-positive rate" if s["is_rate"] else "alerts (NOT a false-positive rate: " + (
        "data not asserted benign" if not a.assert_benign else "only one source = single data point") + ")"
    print(f"{s['files']} files ({s['files_unreadable']} unreadable), {s['supported_events']:,} supported events, rules {s['rules_fingerprint']}")
    print(f"{kind}: {s['events_with_alert']} alerted events = {s['event_level_fp_pct']}% of supported events (95% CI {s['event_level_ci95_pct']}); "
          f"{s['files_with_alert']}/{s['files'] - s['files_unreadable']} files with an alert; {s['alerts_per_1000_events']} alerts per 1,000 events")
    print("by rule:", s["by_rule"])
    print("written", a.out)


if __name__ == "__main__":
    main()
