"""Run Hayabusa (csv-timeline) on the 117 in-scope held-out samples, one file at a time.  *** UNTESTED: run on the laptop ***

Needs: hayabusa binary with its rules/ folder (hayabusa update-rules), and the held-out samples (download: python -c "import heldout; heldout.fetch('.')").
Hayabusa looks for its rules/config relative to its own folder, so the script runs it with that folder as working directory.
Nothing here was run against a real Hayabusa.

  python scripts/run_hayabusa.py --hayabusa C:\\tools\\hayabusa\\hayabusa-win-x64.exe
  --limit 3 --dry-run to try first;  --extra "--enable-noisy-rules" etc. are passed through (and recorded).
"""
import argparse
import datetime
import json
import os
import platform
import shlex
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as C  # noqa: E402


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", **kw)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hayabusa", required=True, help="path of the hayabusa executable")
    ap.add_argument("--cwd", help="working directory for hayabusa (default: the folder of the executable)")
    ap.add_argument("--samples", default=os.path.join(C.ROOT, "real_data", "heldout"))
    ap.add_argument("--out", default=C.OUT_DIR)
    ap.add_argument("--min-level", default="low", choices=["informational", "low", "medium", "high", "critical"])
    ap.add_argument("--extra", default="", help="extra arguments passed to csv-timeline (recorded in the metadata)")
    ap.add_argument("--tool-version", default="", help="set if --version cannot be read automatically")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    exe = os.path.abspath(a.hayabusa)
    cwd = a.cwd or os.path.dirname(exe)
    rows, _ = C.load_inscope()
    rows = rows[:a.limit] if a.limit else rows
    if not a.dry_run:
        C.check_samples(rows, a.samples)
    raw_dir = os.path.abspath(os.path.join(a.out, "raw", "hayabusa"))
    os.makedirs(raw_dir, exist_ok=True)

    def cmd_for(sample_file, raw):
        return [exe, "csv-timeline", "-f", sample_file, "-o", raw, "-p", "verbose", "-w", "-q", "-C"] + shlex.split(a.extra)

    out, n_err = [], 0
    for i, s in enumerate(rows, 1):
        sf = os.path.abspath(C.sample_path(a.samples, s["file"]))
        raw = os.path.join(raw_dir, C.raw_name(s["file"]) + ".csv")
        cmd = cmd_for(sf, raw)
        if a.dry_run:
            print(" ".join(f'"{x}"' if " " in x else x for x in cmd))
            continue
        if os.path.exists(raw):
            os.remove(raw)
        try:
            p = _run(cmd, cwd=cwd, timeout=a.timeout)
            if p.returncode != 0:
                n_err += 1
                status, dets = f"error rc={p.returncode}: {((p.stderr or p.stdout).strip().splitlines() or [''])[-1]}"[:200], []
            elif os.path.exists(raw):
                status, dets = "ok", C.parse_hayabusa_csv(raw)
            else:
                status, dets = "ok (no output file: no detections)", []     # Hayabusa writes no file when nothing is detected (assumed)
        except subprocess.TimeoutExpired:
            status, dets, n_err = "timeout", [], n_err + 1
        except ValueError as e:
            status, dets, n_err = f"unparsable output: {e}"[:200], [], n_err + 1
        out.append(C.finish_row(s, status, dets, a.min_level))
        print(f"[{i}/{len(rows)}] {status[:40]:40s} alerts={out[-1]['n_detections']:3d} {s['file'][-60:]}")
        if i == 3 and n_err == 3:
            raise SystemExit("First 3 samples all failed - check the paths/flags (see the last error above). Aborting.")
    if a.dry_run:
        return
    C.write_per_sample(os.path.join(a.out, "hayabusa_per_sample.csv"), out)
    ver = a.tool_version
    if not ver:
        for flag in ("--version", "-V", "help"):
            try:
                t = _run([exe, flag], cwd=cwd, timeout=30)
                line = next((l.strip() for l in (t.stdout + t.stderr).splitlines() if "v" in l.lower() and any(c.isdigit() for c in l)), "")
                if line:
                    ver = line
                    break
            except Exception:                                # noqa: BLE001
                pass
    rules_ver = ""
    try:
        rules_ver = _run(["git", "-C", os.path.join(cwd, "rules"), "rev-parse", "HEAD"], timeout=30).stdout.strip()
    except Exception:                                        # noqa: BLE001
        pass
    meta = dict(tool="Hayabusa", version=ver or "unknown (pass --tool-version)", rules_commit=rules_ver, min_level=a.min_level,
                command_template=" ".join(cmd_for("<sample.evtx>", "<out.csv>")), samples=len(out), errors=n_err,
                run_at=datetime.datetime.now(datetime.timezone.utc).isoformat(), platform=platform.platform())
    json.dump(meta, open(os.path.join(a.out, "hayabusa_meta.json"), "w"), indent=1)
    if sum(r["n_detections_any_level"] for r in out) == 0:
        print("WARNING: zero detections on all samples - suspicious (rules missing? run 'hayabusa update-rules'). Do not use these numbers before checking.")
    print(f"Done: {len(out)} samples, {n_err} errors. Next: python scripts/table8.py")


if __name__ == "__main__":
    main()
