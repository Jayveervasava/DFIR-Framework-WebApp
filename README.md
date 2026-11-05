# CP-DFIR: Cross-Platform DFIR Framework

[![tests](https://github.com/jayveerv/DFIR-Framework-WebApp/actions/workflows/tests.yml/badge.svg)](https://github.com/jayveerv/DFIR-Framework-WebApp/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23973650.svg)](https://doi.org/10.5281/zenodo.23973650)
![version](https://img.shields.io/badge/version-1.3-blue.svg)

**A Scalable Cross-Platform DFIR Framework for Automated Evidence Collection, Correlation, and Cloud Forensic Investigation**

Author: Jayveer Vasava (M.Tech Cyber Security, Parul University)

CP-DFIR collects evidence from Windows, Linux and AWS, converts it to one common schema, correlates events from the different
platforms into a single attack timeline mapped to MITRE ATT&CK, and records every step in a tamper-evident chain of custody.
It runs as an analyst console in the browser (similar in spirit to Velociraptor or Timesketch) and from the command line (`main.py`).

**Live demo:** <https://cp-dfir-console.onrender.com/>

Click **Try demo** (no password) to open a read-only demo case, or create your own case, upload evidence (or a collector zip) and
press Analyse. You get the investigation graph, timeline, MITRE ATT&CK matrix, cloud posture, chain of custody (verify and tamper
check), a printable report (dark or light), a pseudonymised export, and seven framework-evaluation pages.

The hosted instance is free-tier, so the first visit can take up to a minute to wake up. Privacy rules on the hosted instance: each
visitor sees only their own cases, visitor cases are deleted after 24 hours, and the shared demo case is read-only. For real
evidence, run CP-DFIR on your own computer so the data never leaves it.

> **Status and honesty note.** The simulated-data results are weak evidence: the data and the rules were both written in this
> project. The held-out result on unseen real samples is the honest baseline (see [Results on real public data](#4-results-on-real-public-data)
> and [Limitations](#5-what-is-not-measured-limitations)).

---

## Contents

1. [What is new in v1.3](#what-is-new-in-v13)
2. [Quick start](#quick-start)
3. [Reproduce the paper](#reproduce-the-paper)
4. [The web console](#the-web-console)
5. [Framework layers](#2-framework-layers)
6. [Results on simulated data](#3-results-on-simulated-data)
7. [Live host evidence collection](#3b-live-host-evidence-collection-hostcollectpy)
8. [Cloud account state](#3c-cloud-account-state-cloudstatepy)
9. [Results on real public data](#4-results-on-real-public-data)
10. [Limitations](#5-what-is-not-measured-limitations)
11. [Analysing your own logs](#6-analysing-your-own-logs)
12. [Future work](#7-future-work)
13. [How to cite](#how-to-cite)
14. [License](#license)

---

## What is new in v1.3

| Feature | What it does | File |
|---|---|---|
| Windows account manipulation | Events 4728/4756 (privileged group), 4738/4742 (UAC flags: no pre-auth, no password, reversible encryption, DES, delegation; SPN), 4781 (rename), 5136 (SPN / delegation / UAC), 4723/4724 (password reset) give 4 new T1098 rules | `normalize.py`, `correlate.py` |
| Defence tampering | Defender events 5001/5007/5010/5012, `Set-MpPreference` / `Add-MpPreference` exclusions, `sc config WinDefend`, Sysmon driver unload, PowerShell 4103/800 give `defender_tampering` (T1562.001) | `normalize.py`, `correlate.py` |
| Kerberos brute force | Events 4768/4771 failures now count as authentication failures, and the brute-force rule counts them | `normalize.py` |
| Service baseline | Drivers and services under System32 or Program Files no longer alert; services launched through cmd, PowerShell, `%COMSPEC%` or from outside those folders still do | `correlate.py` |
| Live progress | The analysis job shows stage, progress bar and elapsed time; a warning appears for cases larger than 20 MB | `pipeline.py`, `webapp/` |
| Merkle per-finding proofs | Every analysis builds a SHA-256 Merkle tree of the findings (`merkle_tree.json`) and records its root in the HMAC-signed custody ledger. Each alert has **Download proof**; the **Verify proof** page (`#/verify-proof`) checks a proof offline or against a case's ledger. Tamper-evident, not tamper-proof (see Limitations) | `merkle.py`, `pipeline.py`, `custody.py`, `webapp/` |
| Sixth tampering test | Reordered ledger entries are now part of the tampering evaluation (30 attempts: 6 attack types x 5 scenarios) | `evaluate.py` |

**Held-out note.** The frozen v1.1 result (30.8% of in-scope samples alerted) is the real held-out number. The v1.3 rules were
written after looking at the gaps in that collection, so their re-run is shown only as post-hoc
(`results/heldout_frozen_v1.1.json` versus `results/heldout_results.json`).

<details>
<summary>What was new in v1.1</summary>

| Feature | What it does | File |
|---|---|---|
| Evidence collectors | Windows (PowerShell, nothing to install) and Linux (Python 3 standard library) collectors gather host state, processes, sockets, accounts, persistence, recent executables and security logs into one zip with `cpdfir_manifest.json` (SHA-256 of every file) | `collectors/` |
| Integrity since collection | On zip upload every file hash is checked against the manifest; changed, missing or extra files are reported immediately | `webapp/app.py` |
| Case privacy | Per-visitor cases, read-only shared demo case, automatic deletion of guest cases (retention), SSH only to public hosts | `webapp/app.py` |
| Pseudonymised export | Usernames, IPs, hosts, emails and AWS account / key IDs become keyed tokens (per-case secret); the ledger is never altered | `anonymize.py` |
| Professional report | Executive summary with suggested next steps, case details and scope, findings, integrity, method and limits, appendix; dark and light themes; A4 print with page numbers | `report.py` |
| Durable storage | If `DATABASE_URL` (PostgreSQL) is set, the data folder is mirrored to the database and restored on restart (with a SHA-256 check); keys live only in environment variables | `webapp/persist.py` |
| Held-out validation | Frozen rules run once on 320 new real samples, separate from the development set | `heldout.py` |

</details>

---

## Quick start

Requirements: Python 3.12 or newer (the hosted demo uses 3.13).

```bash
git clone https://github.com/jayveerv/DFIR-Framework-WebApp.git
cd DFIR-Framework-WebApp
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**Run the web console**

```bash
python webapp/app.py               # opens http://127.0.0.1:5000
```

On Windows you can double-click `run_webapp.bat`; on Linux or macOS use `./run_webapp.sh`. The first time, create your analyst
account (the name appears in reports and in the custody ledger as the investigator).

**Run the CLI demo**

```bash
python main.py demo                # simulated S1 attack, report opens in the browser
python main.py tamper-demo         # shows tampering being detected
```

**Run the tests**

```bash
pip install -r requirements-dev.txt pytest
python -m pytest tests -v
```

Tests that need `moto` and `freezegun` (the AWS emulator tests) are skipped if those packages are missing.

**Deploy to Render (free)**

New, then Blueprint, choose this repository, and set `DFIR_ADMIN_PASSWORD` and `DATABASE_URL` (a free Neon or Supabase PostgreSQL).
Render generates `DFIR_CUSTODY_KEY` and `DFIR_SESSION_KEY` itself. Auto-deploy is off, so redeploy by hand after each push.

---

## Reproduce the paper

All numbers and figures come from the real outputs in `results/` and `cases/`; nothing is typed in by hand.

| What | Command | Output |
|---|---|---|
| Simulated scenarios S1 to S5, ablation, tamper tests (6 attack types x 5 scenarios = 30 attempts, plus untouched controls), scalability (full run, about 1 minute) | `python main.py evaluate` | `results/evaluation.json`, `results/metrics_summary.csv`, `results/scalability.csv`, `results/evaluation_report.html` |
| Same, but scalability only up to 10,000 records | `python main.py evaluate --quick` | same files |
| Real public data: EVTX-ATTACK-SAMPLES, LogHub, Stratus Red Team, plus the held-out set (downloads about 44 MB on the first run, needs internet) | `python main.py real-eval` | `results/real_data_results.json`, `results/real_data_report.html`, `results/heldout_results.json` |
| Tamper-detection demo | `python main.py tamper-demo` | console output |
| Dashboard with all figures (the development vs held-out detection bars are in the Real-World Validation section) | `python make_dashboard.py` | `results/dashboard.html` |
| Table 8, step 1: download the held-out samples (needs internet) | `python -c "import heldout; heldout.fetch('.')"` | `real_data/heldout/` |
| Table 8, step 2: Chainsaw on the 117 in-scope held-out samples (**UNTESTED, run on laptop**; needs the Chainsaw binary and a Sigma clone, see `scripts/README.md`) | `python scripts/run_chainsaw.py --chainsaw PATH --sigma DIR --mapping FILE` | `results/table8/chainsaw_per_sample.csv`, `chainsaw_meta.json` |
| Table 8, step 3: Hayabusa on the same 117 samples (**UNTESTED, run on laptop**) | `python scripts/run_hayabusa.py --hayabusa PATH` | `results/table8/hayabusa_per_sample.csv`, `hayabusa_meta.json` |
| Table 8, step 4: build the table (CP-DFIR frozen v1.1 row + both tools; a tool without results is shown as UNTESTED) | `python scripts/table8.py` | `results/table8.csv`, `results/table8.md` |
| Check the Table 8 parsers on made-up fixtures (does not run the real tools) | `python scripts/table8.py --selftest` | console output |
| False alarms on benign logs (**not measured yet**: needs a labelled real benign log set, see `scripts/README.md`) | `python scripts/benign_fp.py --dir DIR --assert-benign --n-sources N --source "NAME@COMMIT"` | `results/benign_fp.json` |
| Unit and integration tests | `python -m pytest tests -v` | console output |

The frozen held-out result that the paper reports is `results/heldout_frozen_v1.1.json` (rule fingerprint `804638ca9a700716`).
Downloaded datasets are not stored in the repository; they are fetched into `real_data/` on first use.
Timings in the scalability table depend on the machine; the shipped `results/scalability.csv` was produced on the author's computer.

Not yet measured, and therefore not in the paper's numbers: Chainsaw and Hayabusa on the 117 samples, and the false-positive rate on real benign logs (the single-host result in Section 3b is one data point, not a rate).

---

## The web console

The framework also runs as a working web application: upload or collect evidence, press Analyse, and the same framework
(`pipeline.run_case`) runs and shows live results.

| Page | What it does |
|---|---|
| **Cases** | Create a new case (empty, or with simulated scenario S1 to S5 / S1_cloud) and list all cases |
| **Evidence** | Drag and drop upload (`.evtx`, wevtutil `.xml`, `auth.log` / `secure`, `cloudtrail.json`, host or cloud JSON, `.zip`); the file type is detected automatically. Originals are kept read-only with a SHA-256 |
| Collectors | **Live triage** (this computer), **AWS** (read-only keys, never saved), **Linux over SSH**, **Windows Security log export**, simulated scenarios |
| **Overview** | KPIs, time per pipeline stage, incidents, alerts by platform, top attacker IPs, rules fired |
| **Investigation** | Entity graph (drag and zoom), cross-platform timeline, attack story, kill chain, events of an incident |
| **MITRE ATT&CK** | Matrix of the techniques seen in this case |
| **Cloud posture** | AWS account mistakes (MFA off, public bucket, open ports, and more) |
| **Evidence explorer** | All normalised events with search, filter and paging; a row click shows the full record, the **original log line** and provenance |
| **Chain of custody** | **Verify now**, HMAC-signed ledger blocks, anchor hash (kept outside the case folder), the **Merkle root of the findings** (verified against the ledger), and a **tampering demo** (change a file, see TAMPERING DETECTED, restore) |
| **Download / Verify proof** | Every alert has a **Download proof** button (a small JSON file: the finding, its Merkle path and the root). The **Verify proof** page (`#/verify-proof`) checks a pasted or uploaded proof and says VALID or INVALID; with a case ID the root is also checked against that case's custody ledger |
| **Report and export** | HTML report, `timeline.csv`, events and incidents JSON, ledger, full case bundle (`.zip`) |
| **Activity log** | Who did what: uploads (with hash), collectors, analysis, verification, exports |
| Framework evaluation | 7 native pages: overview, accuracy, integrity, cloud, scalability, real-world validation, ATT&CK coverage (from `results/*.json`) |
| System and self-test | Environment, the unit tests in one click, password change |
| Users and audit | (admin) add or remove analysts, global audit log (logins, failed logins), delete cases |

**Forensic design**

- Evidence originals are stored read-only in `webapp_data/cases/<ID>/uploads/`; analysis runs on a copy (the acquisition step hashes again).
- The custody ledger is **HMAC-signed**; the key is in `webapp_data/custody.key`, outside the case folders. The anchor hash of each analysis is in `webapp_data/anchors.json`.
- You can also verify from the command line: `python main.py verify --case webapp_data/cases/<ID>/case --custody-key-file webapp_data/custody.key --anchor <hash>`
- Login uses hashed passwords and a 5-minute lock after 8 failed attempts; every API call checks a CSRF header; by default the server listens only on `127.0.0.1`.
- **Backup:** keep the `webapp_data/` folder (cases, `custody.key`, `anchors.json`) together.

**Public mode.** To host it online: `python webapp/app.py --host 0.0.0.0 --port 8080 --no-browser` with `DFIR_PUBLIC_MODE=1`. In public mode live
triage, SSH and Windows export are disabled, because they would collect the server's data rather than yours, and the AWS
collector does not accept access keys (run CP-DFIR locally for that). Two read-only demo cases are kept analysed with the current
rule set: the S1 scenario alone (`S1_pure`: 244 events, 38 flagged) and S1 plus an AWS account state (268 events, 51 flagged).

Files: `webapp/app.py` (Flask backend, uses the framework unchanged), `webapp/static/` (UI), `run_webapp.bat`, `run_webapp.sh`.

### Static dashboard

`python make_dashboard.py` builds `results/dashboard.html`, a self-contained dark SOC-style viewer (no internet needed) with these
sections: Mission Control, Evidence Collection, Cross-Platform Correlation, Attack Investigation, Cloud Forensics, Chain of Custody,
MITRE ATT&CK Coverage, Scalability, Real-World Validation and Evidence Explorer. The button at the top switches to the light theme;
open a section directly with, for example, `dashboard.html#mitre`. Screenshots are in `screenshots/`.

---

## Command line (Windows menu and CLI)

On Windows, `run.bat` installs the required packages on first run (internet needed) and shows this menu:

| Menu | What it does |
|---|---|
| 1 | Demo: simulated attack, report opens in the browser |
| 2 | Full evaluation on simulated scenarios (about 1 minute) |
| 3 | Validation on **real public data** (about 44 MB download the first time, about 3 minutes) |
| 4 | Tampering demo |
| 5 | **Analyse your own logs** |
| 6 | Export this laptop's Windows Security log (**run as Administrator**) |
| 7 | Pull AWS CloudTrail events **and account state** (IAM, access keys, S3, security groups); needs AWS credentials |
| 8 | Unit tests |
| 9 | **Triage**: collect live evidence from this laptop (processes, sockets, accounts, persistence, files, logs), analyse it and build a report |

Command line: `python main.py triage | collect-host | demo | evaluate | real-eval | tamper-demo | analyze --input DIR | collect-live | collect-aws | collect-linux | verify --case DIR | selftest`

---

## 2. Framework layers

| Layer | File | Job |
|---|---|---|
| Acquisition | `collect.py`, `hostcollect.py`, `cloudstate.py` | Copies logs into `evidence/` (hash before and after). Live host collector (section 3b), Windows `wevtutil` (XML / .evtx), AWS boto3 `LookupEvents`, Linux local or SSH |
| Normalisation | `normalize.py` | All formats into one schema; all times in UTC |
| Correlation | `correlate.py` | 62 rule types, all mapped to MITRE ATT&CK (Windows 21, Linux 2, login / brute force 2, AWS CloudTrail 11, live host 15, AWS account posture 11) plus a NetworkX entity graph. Every connected component that contains an activity alert becomes an incident (posture findings alone do not create incidents) |
| Chain of custody | `custody.py`, `merkle.py` | SHA-256 of every action in a hash-chained ledger with **optional HMAC** (signed with a secret key). Detects a changed file, a changed entry, a deleted entry, reordered entries, a removed last entry, and a fully rewritten chain (with HMAC). **Merkle per-finding proofs:** every finding (flagged event) is a leaf of a SHA-256 Merkle tree; the tree is written to `merkle_tree.json` and its root is recorded in the ledger, so one finding can be handed over and checked on its own |
| Reporting | `report.py` | Self-contained HTML report (no internet or JavaScript needed) |
| Evaluation | `evaluate.py`, `generate_data.py` | Simulated scenarios with ground truth, tampering tests, scalability |
| Real-data validation | `realdata.py` | Tests on **real** public logs (section 4) |
| Tests | `tests/` | 105 tests: real processes and sockets (Linux), AWS collectors (botocore Stubber validated against the AWS service model), SSH collector (fake runner), parsers, rules, custody, hosted-console privacy, collector package integrity, pseudonymisation, held-out labels, Merkle trees and proofs (including tampered and malformed proofs) |

**Supported inputs**

- **Windows:** wevtutil XML export or binary `.evtx`. Security (4624, 4625, 4634, 4672, 4688, 4698, 4720, 4732, 5145, 1102), System (7045, 104), **Sysmon (1, 3, 10, 13)**, PowerShell 4104
- **Linux:** `auth.log` / `secure`: sshd Failed and Accepted, sudo COMMAND, useradd; PAM-only logs (older RedHat); traditional and ISO timestamps; "message repeated N times"
- **AWS:** CloudTrail JSON (`Records`, a list, JSON Lines, concatenated objects, enriched exports such as Datadog)

**How cross-platform links are made** (the report shows the graph): the same attacker IP; a credential file read on Linux plus the
`credential_inventory` entry (`case_config.json`) that maps it to an AWS key; and `CreateAccessKey` linking an old key to a new key.

**Configurable policy:** `privileged_source_allowlist` (in `case_config.json`): administrator logons are expected only from these IPs; others are flagged.

---

## 3. Results on simulated data

Full detail is in `results/evaluation_report.html`.

| Measure | Result |
|---|---|
| Evidence completeness | 100% (5 scenarios) |
| Correlation, core S1 to S4 | Precision 100%, Recall 100%, **F1 = 1.000** |
| Correlation, hard case S5 | Precision 90.0%, Recall 69.2%, **F1 = 0.783** |
| S5 with admin-source policy | Precision 92.9%, Recall 100%, **F1 = 0.963**; benign S4 with policy: 0 false alerts |
| Unified versus siloed | S1: best silo finds 42.1% of the attack chain, unified 100%. S2: 64.0% versus 100% |
| Integrity | 30 of 30 tampering attacks detected (6 attack types x 5 scenarios, including reordered entries and a forged chain caught by HMAC); 5 of 5 untouched cases verified. A forged chain is **not** caught without HMAC or an anchor (listed as a known limitation) |
| Scalability | 1,067 records in 0.06 s, up to 104,634 records in 7.7 s. Throughput falls from about 16,800 to about 13,600 records/s, so scaling is near-linear. The attack is still found (F1 1.000) |

**These numbers are weak evidence**: both the data and the rules were created in this project. That is why section 4 matters.

---

## 3b. Live host evidence collection (`hostcollect.py`)

`python main.py triage` (menu 9) collects live evidence from this computer in order of volatility (RFC 3227), read-only:

| Artifact | What |
|---|---|
| `system.json` | Host, OS, boot time, logged-in users, whether you are an administrator |
| `connections.json` | Network sockets and the owning process |
| `processes.json` | Process list: executable path, command line, user, parent, **executable SHA-256**, deleted binary |
| `accounts.json` | Local accounts, admin groups, sudoers (Linux) or `net user` and Administrators (Windows) |
| `persistence.json` | cron, systemd, rc.local, ld.so.preload, authorized_keys (Linux); Run keys, startup folder, scheduled tasks, services (Windows); LaunchAgents (macOS) |
| `files.json` | Temp and download files of the last 7 days: ELF / PE / script magic, SHA-256, **timestomp** check (ctime) |
| `Security.evtx` / `auth.log` | Security logs (Windows needs Administrator) |
| `manifest.json` | Hash of every artifact, the commands that ran, errors, and **what could not be collected** |

Every file goes into the custody ledger. Analysis then runs the log rules plus 15 host rules (process running from a temp folder,
deleted or memfd binary, reverse shell, cron / systemd / authorized_keys persistence, duplicate UID 0, executable in temp,
timestomp, and others). A host process or socket is **linked to the same incident as an attacker IP from auth.log or CloudTrail**.

**Real test (Linux, on the test machine).** The tests create real processes (a binary running from `/tmp`, a deleted binary, a
memfd process, a timestomped binary, a real TCP connection from bash) and check that the collector sees them and the rule fires.
Running on a real system found 5 bugs, now fixed: journalctl's "-- No entries --" became a fake auth.log; the collector counted its
own files as recent files; `psutil` strips the `(deleted)` marker of a deleted binary; the recent-file check used only `mtime`
(so timestomping escaped it); and a cap of 500 files could cut off an old-mtime dropped binary.

**False positives on a real benign host.** One real benign Linux host (this test VM): 62 processes, 57 accounts, 15 persistence
entries, 978 recent files gave **3 alerts**, all benign: a chromedriver binary in `/tmp` (a test tool, *executable_in_temp*), a
small executable in `/tmp` (*executable_in_temp*), and the sandbox's own telemetry agent running from memfd (*fileless_memfd_process*).
That is **3 false positives** on a single host, so it is one data point and not a false-positive rate.

---

## 3c. Cloud account state (`cloudstate.py`)

`python main.py collect-aws --days 7 --region ap-south-1 [--all-regions]` collects CloudTrail events and the **account state**
(use `--no-state` to skip it). It is read-only. CloudTrail shows what happened; the state shows what the attacker could do, what was
switched off and what was open.

| Artifact | What |
|---|---|
| `trails.json` | CloudTrail trails: logging on or off, multi-region, log-file validation |
| `iam_account.json` | Root account MFA |
| `iam_users.json` | Users, MFA, **administrator rights** (AdministratorAccess, or a customer-managed policy whose document allows `Action *` on `Resource *`, directly or through a group), access keys (age, last use) |
| `iam_roles.json` | Roles and **who can assume them** (another account, "anyone") |
| `s3_buckets.json` | Public-access block, public bucket policy (evaluated by the tool if `IsPublic` is missing) |
| `security_groups.json` | Ports open to the Internet (one region, or `--all-regions`) |
| `manifest.json` | Hash of every artifact, API operations used, **denied or failed calls** |

A denied call is recorded as "unknown", not "missing" (an account whose IAM could not be read is not called "no MFA"). **11 posture
rules:** no trail or trail logging off, trail log-file validation off, root MFA missing, admin without MFA, stale access key
(over 90 days), role trusts anyone, role trusts another account (allowlist via `cloud_trusted_accounts`), public bucket,
incomplete public-access block, and SSH / RDP / all ports open to the world. **Posture findings alone do not create an incident**;
if an attacker used a key, that key's account record (user, stale or not) joins the incident.

**Three kinds of testing:**

1. **Labelled fixture** (JSON, written by the author): 13 of 13 findings, 0 false positives, and 0 findings on a clean account.
2. **botocore Stubber** (responses validated against the AWS service model): collector call order and error handling, AccessDenied.
3. **moto AWS emulator with the real boto3 code path** (`tests/test_cloud_emulated.py`): a seeded account with 14 misconfigurations
   and harmless look-alikes (custom-policy admin, admin through a group with MFA, inactive and fresh keys, conditional and service role
   trust, a fully blocked bucket, port 443, an internal rule). **14 of 14 found, 0 false positives**; with `--all-regions` 15 of 15.
   The collector used **only List / Get / Describe** operations (a test checks this). Pagination was tested with 230 users. With an abused
   key, only 1 of 5 key records joined the incident.

**This is an emulator, not a real AWS account.** It tests boto3's request and response handling and this code, not AWS's real
behaviour. The collector has never been run against a real account. Permissions needed (all read-only): `sts:GetCallerIdentity`,
`cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `iam:GetAccountSummary`, `iam:ListUsers`, `iam:ListRoles`,
`iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`, `iam:ListMFADevices`, `iam:ListAttachedUserPolicies`, `iam:ListGroupsForUser`,
`iam:ListAttachedGroupPolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `s3:ListAllMyBuckets`, `s3:GetBucketPublicAccessBlock`,
`s3:GetBucketPolicyStatus`, `s3:GetBucketPolicy`, `ec2:DescribeSecurityGroups` (and `ec2:DescribeRegions`).
For the emulator tests install `moto` and `freezegun` (`requirements-dev.txt`).

---

## 4. Results on real public data

Full detail is in `results/real_data_report.html`. The data is downloaded from GitHub and is not part of this repository.

| Data | What | Result |
|---|---|---|
| **Windows** EVTX-ATTACK-SAMPLES | 278 real attack captures, 37,364 records | **0 parse errors.** 232 samples (83.5%) contain supported events (12.2% before the parser work). Of 26 labelled samples, **25 detected**; on 5 deliberately hard or unsupported cases, **1 of 5** (Kerberos password spray 4771, caught by the brute-force rule since v1.3 counts 4768/4771 failures) |
| **Linux** LogHub OpenSSH_2k | A real Internet-facing SSH server, 2,000 lines | 520 events (26%); failures **527 = 527** against an independent regex count; brute-force IPs **11 = 11** against an independent naive detector (same set) |
| Linux LogHub Linux_2k | Older RedHat format | 489 events (24.4%); brute-force IPs 39 = 39 |
| **AWS** Stratus Red Team CloudTrail | 4 real attack samples (15 events) | **4 of 4 detected** (earlier version: 1 of 4 and a crash on one file) |

**Bugs found with real data and fixed:** binary `.evtx` could not be read; the real time format (`2019-03-19 23:35:07+00:00`) failed;
the CloudTrail source IP was in a different place (enriched export); one real CloudTrail file was invalid JSON (no comma between
records) and crashed the parser; syslog "message repeated 5 times" was counted as one failure (brute-force IPs went from 9 to 11);
the older RedHat `sshd(pam_unix)` format parsed at 0%.

### 4b. Held-out validation (frozen rules, new samples)

The labelled results above are a development set (the rules were written while looking at those samples). So the rules were
**frozen** (fingerprint `804638ca9a700716`) and run **once** on **320 new real samples** that were never seen when writing the rules:
the Hayabusa sample collection (fixed commit), which is EVTX-to-MITRE-Attack, DeepBlueCLI (SANS) and Yamato Security. One file that
was byte-identical to the development set was removed.

| | Samples | Alert raised | Correct technique |
|---|---|---|---|
| In scope (a rule for the technique exists) | 117 | 36 (30.8%) | **26 (22.2%)** |
| DeepBlueCLI (classic attacks) | 14 in scope | 13 | 8 |
| EVTX-to-MITRE-Attack | 102 in scope | 22 | 17 |

**What this means:** the 25 of 26 on the development set does not carry over to new data. Classic captures (PsExec, Mimikatz,
PowerShell, log clearing) are caught well. Most EVTX-to-MITRE-Attack samples use Security events the framework did not parse at that time
(4738 / 4724 / 5136 account changes, 4656 / 4663 object access). These gaps were not tuned against this set (otherwise it would become
a development set too); closing them needs new parsers and rules and then another unseen set. 15 files (1,681 records) cannot be
decoded because of a `python-evtx` 0.8 NullTypeNode bug; they are counted, not hidden. Run: `python main.py real-eval` (the held-out run is part of it).

**Still missed (marked MISS in the report):** rdrleakdiag LSASS dump (the sample has no LSASS-access event; the command line triggers
*credential_dump_tool* but the label asks for *lsass_access*, so it counts as a MISS), renamed regsvr32, msxsl, Security 4656/4663
object-access LSASS, and TeamViewer memory dump.

---

## 5. What is NOT measured (limitations)

1. **False-positive rate on real benign traffic** was not measured: no labelled real benign log was available.
2. **Correlation on a real multi-platform incident** was not measured: no public dataset contains real Windows, Linux and AWS logs of one incident. Cross-platform correlation was evaluated only on **simulated** scenarios.
3. The detection rules were written **after looking at real samples**, so the labelled EVTX-ATTACK-SAMPLES results are a development set. Section 4b therefore tests the frozen rules on **320 unseen samples**, where the correct technique is found in **22.2%** of in-scope samples. That is the honest baseline.
4. Sample labels were taken from file names (the author's reading), not from official per-rule labels of the dataset.
5. **Where the live collectors were really tested:** the host collector was tested on a **real Linux system**. **The Windows and macOS paths (registry Run keys, schtasks, services, wevtutil, LaunchAgents) were not run on a Windows or macOS machine during this project**: the parsers were tested on fixtures of the documented output formats, not on real output. The AWS collector was tested with a botocore stub, and the SSH collector with a fake runner (no real sshd or AWS account). The PowerShell collector (`collectors/cpdfir-collect-windows.ps1`) was syntax-checked with the PowerShell 7.4 parser (0 errors) but has not been run on real Windows. **Running menu 9 on a Windows laptop is the most important check.**
6. Detection is rule-based: attacks outside the rules are not found.
7. Linux session attribution is a heuristic (the latest login of the same user). In S5 this causes one false positive.
8. Linking a credential file to an AWS key needs the analyst's `credential_inventory`.
9. The custody ledger **detects tampering; it does not prevent it.** Removing the last entries is caught only if the anchor hash is noted separately, and a full rewrite of the chain only if the ledger is HMAC-signed (`--custody-key-file` or `DFIR_CUSTODY_KEY`) and the key is not in the attacker's hands. If the attacker has the key or full write access to the ledger, there is no guarantee. On the public demo the anchor is stored on the same server.
10. The host collector takes no memory dump or disk image, only artifacts. The timestomp check uses ctime on Linux and is absent on Windows. Live collection itself changes the system slightly (a new process, files read).
11. Speed was measured in a single process up to 100,000 records.
12. **Merkle per-finding proofs are tamper-evident, not tamper-proof.** (a) `leaf_count` is not hashed into the root: the offline
    check alone (`verify_proof` without a case) still passes when the count is changed to another value with the same path shape
    (for example 7 to 8); the check against the custody ledger (`verify_proof_against_ledger`, or the Verify proof page with a case
    ID) catches it. (b) A leaf covers only 15 fields (`event_id, time_utc, source, host, event_type, user, src_ip, target, outcome,
    detail, source_file, line_ref, flags, techniques, incident`); a change to `severity`, `raw` or other fields is not caught by a
    proof (the file hash of `normalized_events.json` in the ledger still covers them). (c) A proof shows that a finding is in the
    tree; it does not show that the findings are complete (a finding dropped before the tree was built is not detected). (d) The root
    is trusted only through the HMAC-signed ledger: an attacker who has the key, or write access to the whole ledger, tree file and
    anchor, defeats it. Without a trusted root a proof is only self-consistent.

---

## 6. Analysing your own logs

Put these files in one folder: `windows_security.xml` or `*.evtx`, `auth.log`, `cloudtrail.json`, and (optional) `case_config.json`:

```json
{
  "case_id": "CASE-001",
  "investigator": "Your Name",
  "linux_timezone_offset": "+05:30",
  "linux_log_year": 2026,
  "internal_ranges": ["198.51.100.0/24"],
  "credential_inventory": { "web01:/home/ubuntu/.aws/credentials": "AKIA................" },
  "privileged_source_allowlist": ["10.0.5.10/32"]
}
```

Run `python main.py analyze --input "folder"` (or menu 5). The report is written to `cases/<case_id>/report.html`.
Verify with `python main.py verify --case cases/DEMO --anchor <hash>`.

**AWS live:** `pip install boto3`, set up AWS credentials (`aws configure`, or a read-only IAM user with `cloudtrail:LookupEvents`), then
`python main.py collect-aws --days 7 --region ap-south-1`. Only management events are returned (the last 90 days).
**Linux:** `python main.py collect-linux --host SERVER --user ubuntu --key key.pem` (key-based SSH), or without `--host` to copy local files.
**Windows:** menu 6 (as Administrator), or `wevtutil qe Security /c:5000 /rd:false /f:xml > windows_security.xml`.

---

## 7. Future work

Measure the false-positive rate on real benign logs; live tests on a real AWS account, Windows and Linux; Sysmon 11 / 7 and Kerberos
events; anomaly-based detection; Azure and GCP; Docker and Kubernetes; a blockchain-based custody ledger.

---

## How to cite

If you use CP-DFIR, please cite the software archive on Zenodo: v1.3 is [10.5281/zenodo.23973650](https://doi.org/10.5281/zenodo.23973650).
To cite all versions (this DOI always resolves to the latest release), use [10.5281/zenodo.23973649](https://doi.org/10.5281/zenodo.23973649).

```bibtex
@software{vasava_cpdfir_2026,
  author  = {Vasava, Jayveer},
  title   = {CP-DFIR: Cross-Platform DFIR Framework},
  version = {1.3},
  year    = {2026},
  doi     = {10.5281/zenodo.23973650},
  url     = {https://github.com/jayveerv/DFIR-Framework-WebApp}
}
```

A `CITATION.cff` file is included so GitHub shows a "Cite this repository" button.

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 Jayveer Vasava.

The sample captures downloaded by `real-eval` (EVTX-ATTACK-SAMPLES, Hayabusa samples, LogHub, Stratus Red Team) keep their own licenses and are not part of this repository.
