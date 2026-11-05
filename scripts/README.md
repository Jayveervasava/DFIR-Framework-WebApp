# scripts/ - Table 8 (Chainsaw / Hayabusa) and benign false-alarm measurement

Status: **nothing in this folder that calls an external tool has been run.** The sandbox these scripts were written in had no
internet, no Chainsaw, no Hayabusa and no EVTX files. The parsers were checked only on made-up fixtures
(`python scripts/table8.py --selftest`). Treat every command below as **UNTESTED, run on laptop** until you have run it once.
Try `--limit 3` first, then the full run. `--dry-run` only prints the commands.

## Table 8: same 117 samples for every tool

The 117 samples are the in-scope rows of `results/heldout_frozen_v1.1.json` (frozen rules, fingerprint 804638ca9a700716).

### 1. Samples (needs internet, about 40 MB)
```
python -c "import heldout; heldout.fetch('.')"        -> real_data/heldout/
```

### 2. Chainsaw
Install (Windows or Linux):
1. Download the latest release zip from https://github.com/WithSecureLabs/chainsaw/releases and unpack it. It contains the binary and `mappings/` (and `rules/`).
2. `git clone https://github.com/SigmaHQ/sigma` (write down the commit: `git -C sigma rev-parse HEAD`; the script records it).
```
python scripts/run_chainsaw.py --chainsaw C:\tools\chainsaw\chainsaw.exe --sigma C:\tools\sigma ^
       --mapping C:\tools\chainsaw\mappings\sigma-event-logs-all.yml --limit 3
python scripts/run_chainsaw.py ... (same without --limit)      add  --rules C:\tools\chainsaw\rules  to include Chainsaw's own rules
```
Per sample it runs `chainsaw hunt <file> -s <sigma> --mapping <map> --json -o <raw.json> --skip-errors -q`.
Technique ids are read from the rule tags (`attack.t1059.001`). The JSON layout is assumed, not checked: if `--limit 3` shows
`alerts=0` everywhere, open one file in `results/table8/raw/chainsaw/` and fix `parse_chainsaw_json` in `scripts/_common.py`.

### 3. Hayabusa
Install: download the release zip from https://github.com/Yamato-Security/hayabusa/releases, unpack, then run `hayabusa update-rules` once in that folder (needs internet).
```
python scripts/run_hayabusa.py --hayabusa C:\tools\hayabusa\hayabusa-win-x64.exe --limit 3
python scripts/run_hayabusa.py --hayabusa C:\tools\hayabusa\hayabusa-win-x64.exe
```
Per sample it runs `hayabusa csv-timeline -f <file> -o <raw.csv> -p verbose -w -q -C` with the Hayabusa folder as working directory.
Technique ids come from the `MitreTags` column. Flag names and column names are from memory of Hayabusa 2.x and were not checked;
use `--extra "..."` for version-specific flags, `--tool-version` if the version cannot be read.

### 4. Build the table
```
python scripts/table8.py
```
Output `results/table8.csv` and `results/table8.md`. A tool with no per-sample file is printed as **UNTESTED, run on laptop**.

Per-sample file (`results/table8/<tool>_per_sample.csv`), one row per one of the 117 samples:

| column | meaning |
|---|---|
| file, label | sample path under real_data/heldout, labelled ATT&CK technique |
| status | `ok`, or `error rc=...`, `timeout`, `unparsable output` (these count as no alert and are listed in the table) |
| n_detections / n_detections_any_level | detections at/above `--min-level` (default `low`) / at any level incl. informational |
| alerted / alerted_any_level | 1 if at least one such detection |
| reported_techniques | ATT&CK ids from the tags of detections at/above min-level |
| exact / parent_match | 1 if a reported id equals the label (or an equivalent) / shares its parent technique; same rule as `heldout.py` |
| top_rules | up to 3 rule titles |

Table columns: tool, alert n/117, correct technique parent-level n/117, correct technique exact n/117 (each with a Wilson 95% interval),
plus the CP-DFIR frozen v1.1 row read from the stored result (36 alert, 26 parent-level, 24 exact).

Fairness notes (also printed under the table): the 117 are defined by CP-DFIR's rule coverage; the sample files come from the Hayabusa
sample collection, so Hayabusa/Sigma rules may have been written with them in view; technique tags are the rule authors' own mapping;
Chainsaw/Hayabusa also raise many alerts that are not the labelled technique, and this table does not count those either way.

## Benign data (false alarms, paper Sections 6.3 and 7.3)

**No false-positive rate has been measured.** The repository has no labelled real benign logs: the three "many-events" background logs
are not labelled benign, LogHub OpenSSH/Linux contain real attacks, and the live-host result (3 alerts on one VM) is one data point.

What is needed: real logs that are known to be free of attack activity, from several independent systems.
Candidates I know of but could not check from the sandbox (verify license, content and size yourself):
- NextronSystems/evtx-baseline on GitHub: Windows event logs of clean OS installs (made for testing Sigma false positives). Clean installs have little user/admin activity, so this gives a lower bound only.
- Security logs exported from several clean VMs / lab hosts you control (`python main.py collect-live --out DIR`, Administrator), with a short note of what was done on them.
- For Linux: `auth.log` files from servers you operate and know to be clean.

Then:
```
python scripts/benign_fp.py --dir real_data/benign_evtx --assert-benign --n-sources <number of distinct hosts> --source "<dataset>@<commit>"
python scripts/benign_fp.py --dir D:\logs\linux --linux --assert-benign --n-sources 5 --tz +00:00 --year 2025 --source "my 5 servers"
```
It reports alerted events / supported events with a Wilson 95% interval, files with an alert, alerts per 1,000 events and the rules that fired
(read every one: each is a false positive or a missing label). It prints the word "rate" only with `--assert-benign` and `--n-sources >= 2`;
otherwise it says the result is not a false-positive rate. It uses the **current** rules (v1.3, fingerprint printed), not the frozen v1.1 rules.
Output `results/benign_fp.json`.
