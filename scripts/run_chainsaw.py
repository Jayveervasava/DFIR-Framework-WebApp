"""Run Chainsaw on the 117 in-scope held-out samples, one file at a time.  *** UNTESTED: run on the laptop ***

Needs: chainsaw binary + its mappings/ folder, a clone of SigmaHQ/sigma (see scripts/README.md), and the held-out samples
(download: python -c "import heldout; heldout.fetch('.')" -> real_data/heldout/).  Nothing here was run against a real Chainsaw.

  python scripts/run_chainsaw.py --chainsaw C:\\tools\\chainsaw\\chainsaw.exe --sigma C:\\tools\\sigma --mapping C:\\tools\\chainsaw\\mappings\\sigma-event-logs-all.yml
  add  --rules C:\\tools\\chainsaw\\rules  to also use Chainsaw's own rules;  --limit 3 --dry-run to try first.
"""
import argparse
import datetime
import json
import os
import platform
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as C  # noqa: E402


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", **kw)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--chainsaw", default="chainsaw")
    ap.add_argument("--sigma", required=True, help="folder with the SigmaHQ rules (git clone https://github.com/SigmaHQ/sigma)")
    ap.add_argument("--mapping", required=True, help="Chainsaw mapping file, e.g. mappings/sigma-event-logs-all.yml")
    ap.add_argument("--rules", help="optional: Chainsaw's own rules folder (-r)")
    ap.add_argument("--samples", default=os.path.join(C.ROOT, "real_data", "heldout"))
    ap.add_argument("--out", default=C.OUT_DIR)
    ap.add_argument("--min-level", default="low", choices=["informational", "low", "medium", "high", "critical"],
                    help="a detection counts as an alert at this level or above (default low); lower levels are still reported separately")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--limit", type=int, help="only the first N samples (trial run)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    rows, _ = C.load_inscope()
    rows = rows[:a.limit] if a.limit else rows
    if not a.dry_run:
        C.check_samples(rows, a.samples)
    raw_dir = os.path.join(a.out, "raw", "chainsaw")
    os.makedirs(raw_dir, exist_ok=True)

    def cmd_for(sample_file, raw):
        c = [a.chainsaw, "hunt", sample_file, "-s", a.sigma, "--mapping", a.mapping]
        if a.rules:
            c += ["-r", a.rules]
        return c + ["--json", "-o", raw, "--skip-errors", "-q"]

    out, n_rc = [], 0
    for i, s in enumerate(rows, 1):
        sf = os.path.abspath(C.sample_path(a.samples, s["file"]))
        raw = os.path.abspath(os.path.join(raw_dir, C.raw_name(s["file"]) + ".json"))
        cmd = cmd_for(sf, raw)
        if a.dry_run:
            print(" ".join(f'"{x}"' if " " in x else x for x in cmd))
            continue
        if os.path.exists(raw):
            os.remove(raw)
        try:
            p = _run(cmd, timeout=a.timeout)
            if p.returncode != 0:
                n_rc += 1
                status = f"error rc={p.returncode}: {((p.stderr or p.stdout).strip().splitlines() or [''])[-1]}"[:200]
                dets = []
            else:
                status = "ok"
                dets = C.parse_chainsaw_json(open(raw, encoding="utf-8", errors="replace").read()) if os.path.exists(raw) else []
        except subprocess.TimeoutExpired:
            status, dets, n_rc = "timeout", [], n_rc + 1
        except ValueError as e:
            status, dets, n_rc = f"unparsable output: {e}"[:200], [], n_rc + 1
        out.append(C.finish_row(s, status, dets, a.min_level))
        print(f"[{i}/{len(rows)}] {status[:40]:40s} alerts={out[-1]['n_detections']:3d} {s['file'][-60:]}")
        if i == 3 and n_rc == 3:
            raise SystemExit("First 3 samples all failed - check the paths/flags (see the last error above). Aborting.")
    if a.dry_run:
        return
    C.write_per_sample(os.path.join(a.out, "chainsaw_per_sample.csv"), out)
    ver = ""
    try:
        ver = _run([a.chainsaw, "--version"], timeout=30).stdout.strip()
    except Exception as e:                                   # noqa: BLE001
        ver = f"unknown ({e})"
    try:
        sigma_commit = _run(["git", "-C", a.sigma, "rev-parse", "HEAD"], timeout=30).stdout.strip()
    except Exception:                                        # noqa: BLE001
        sigma_commit = ""
    meta = dict(tool="Chainsaw", version=ver, sigma_commit=sigma_commit, mapping=a.mapping, chainsaw_rules=a.rules or None,
                min_level=a.min_level, command_template=" ".join(cmd_for("<sample.evtx>", "<out.json>")), samples=len(out),
                errors=n_rc, run_at=datetime.datetime.now(datetime.timezone.utc).isoformat(), platform=platform.platform())
    json.dump(meta, open(os.path.join(a.out, "chainsaw_meta.json"), "w"), indent=1)
    if sum(r["n_detections_any_level"] for r in out) == 0:
        print("WARNING: zero detections on all samples - this is suspicious (wrong --sigma/--mapping?). Do not use these numbers before checking.")
    print(f"Done: {len(out)} samples, {n_rc} errors. Next: python scripts/table8.py")


if __name__ == "__main__":
    main()
