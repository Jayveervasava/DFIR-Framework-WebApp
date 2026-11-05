# MERGE REPORT: v1.3 merge (Claude 1 + 2 + 3 + 4)

Branch: `merge-v1.3` (base: `main` @ `26938b2`). Date: 5 Nov 2026.

## 1. Kya joda (har ek ka alag commit)

| Commit | Kya | Files |
|---|---|---|
| step1 | MIT LICENSE, CITATION.cff, CI (`.github/workflows/tests.yml`), English README aur `.bat` messages, Python 3.13 (`render.yaml`), VERSION 1.3 | 9 |
| Claude 1 | Merkle per-finding proofs: `merkle.py` (naya), `pipeline.py`, `custody.py`, `tests/test_merkle.py` (25 tests) | 4 |
| Claude 2 | Backend: `/merkle`, `/proof`, `/verify-proof` routes, demo auto re-analyse, `S1_pure` demo, public mode me AWS key collection band, `persist.Mirror.hold()`, 17 tests | 3 |
| Claude 3 | Frontend: Download proof, Verify proof page, Merkle card, demo-first login, graph fit, timeline zoom, bada text, mobile header, light theme, print | 2 |
| Claude 4 | Reorder tamper attack (30 attempts), Figure 6, `scripts/` (Table 8, benign FP), README "Reproduce the paper", `results/` (6 files) | 16 |

- Overlap: koi code file do zips me nahi thi. Sirf `CHANGES.md` sabme thi, isliye `docs/CHANGES_claude1.md` ... `CHANGES_claude4.md` naam se rakhi gayi.
- Claude 4 ki README me sirf "Reproduce the paper" section alag tha (12 lines). Baaki README step1 jaisa hi tha, koi conflict nahi.
- `dev_stub_merkle.py` repo me **nahi** dala.
- GitHub `main` (`26938b2`) aur `DFIR-Framework-WebApp-main.zip` bilkul same the. Step1 zip unke upar 9 files aage tha.

## 2. Fixes (brief wale 6 + jo test me mile)

| # | Fix | Natija |
|---|---|---|
| 1 | `app.js`: Re-analyse button ab per-case `can_reanalyse` padhta hai, na mile to session flag | Guest apna case re-analyse kar sakta hai, shared demo nahi |
| 2 | README: tamper 25/25 se **30/30 (6 types)**, hard cases 0/5 se **1/5** (Kerberos spray "still missed" se hataya), tests 62 se **104**. Merkle ki lines layers table, v1.3 table aur console table me. Public mode me AWS + demo cases. Limitation #12 (Merkle) | Commit `b484a84` |
| 3 | Asli `merkle.py` ke saath contract check | Sab match: `ledger_info` keys (`seq`/`ledger_seq`, `entry_hash`/`ledger_entry_hash`), `build_tree` ka shape, algorithm `sha256-merkle-v1`, empty tree root = SHA-256(b""), proof me exactly 15 fields. Test helper `add_merkle_if_missing` ab no-op hai, kyunki pipeline khud tree banata hai (E2E me check kiya) |
| 4 | `custody._entry_hash` aur `custody._mac` Claude 1 ke `custody.py` me abhi bhi hain | OK, fallback ki zaroorat nahi padti |
| 5 | Demo stamp | Stamp-rahit demo aur `merkle: false` stamp wala demo, dono re-analyse hote hain aur tree ban jata hai (E2E me test kiya) |
| 6 | `results/evaluation.json` ko chhua nahi | Consistent hai: 5 scenarios x 6 detect-expected = **30/30**, controls 5/5, `metrics_summary.csv` 7/7 per scenario. `main` se farak sirf 5 reorder entries + `note` ka hai. Timings, scalability, cloud_emulated purane laptop run ke hi hain |
| **A** | **Naya bug (E2E me mila):** `/api/verify-proof` case_id ke saath bhi `leaf_count` badla hua proof VALID batata tha | Ab ledger ke `leaf_count` se match karta hai, aur test bhi joda (`8b2381d`) |
| **B** | **Naya bug (browser me mila):** finding badalne par bhi "Leaf matches the finding" **yes** dikhta tha | Ab proof ke andar ki finding ko dobara hash karta hai, aur test bhi joda (`0ddec2c`) |
| **C** | Phone par Evidence page 850 px chauda tha (grid `1fr`) | `minmax(0,1fr)`, aur grid items ko `min-width:0` |
| **D** | Phone par graph ka legend 10 px bahar jata tha | Ab wrap hota hai |
| **E** | Verify proof page: galat JSON daalne par purana result reh jata tha; Case ID ka placeholder galat tha | Result box reset hota hai; placeholder ab "empty = check the proof on its own" |

## 3. Tests

| Run | Result |
|---|---|
| `python3 -m unittest discover -s tests` (boto3 ke bina, jaise brief me) | 104 chale: 100 pass, 4 error (sirf boto3 missing) |
| boto3 + moto + freezegun install karke (CI jaisa) | **104 me se 104 pass, 0 error, 0 skip** |
| `python3 -m pytest tests -q` | 104 passed, 10 subtests passed |
| `node --check webapp/static/app.js` | OK |

Count: 62 (base) + 25 (Claude 1) + 17 (Claude 2) = **104**. Maine 2 purani tests me assertions joda, nayi test function nahi joda.

## 4. End-to-end (Flask test client, asli `merkle.py`): 44/44 pass

Login (guest), version 1.3, rules **62**, `S1_pure` **244 events / 38 flagged / 1 incident**, demo S1+AWS **268 / 51 / 1**.
Pipeline ne khud `merkle_tree.json` aur ledger entry (stage `Merkle`, seq 7) likhi. `GET /merkle`: verified true, 38 leaves.
Proof download: 200, `attachment; filename=proof_S1_pure_E000109.json`, 15 fields, `verify_proof_against_ledger` OK.
`verify-proof`: VALID (case ke saath aur bina). Finding badli → INVALID. `leaf_count` badla → bina case ke VALID (documented limit), case_id ke saath INVALID. Root badla → INVALID.
Malformed proof → `valid:false` (500 nahi). Galat body → 400. Dusre visitor ke case par merkle / proof / verify-proof → **404**. Unflagged event → 404. Case A ka proof case B ke saath → INVALID.
Public mode me AWS collect → **403** + `run_locally`. Guest shared demo ko re-analyse nahi kar sakta, apna case kar sakta hai. Tree file tamper karne par verified false aur proof **409**.
Demo stamp: stamp-rahit aur `merkle:false`, dono re-analyse hote hain.

Mutation check (copy par, har ek me test fail hona chahiye tha, aur hua):
verify-proof ka privacy check hataya → FAIL ✅, leaf_count binding hataya → FAIL ✅, public AWS block hataya → FAIL ✅.

## 5. Browser check (Playwright Chromium, headless)

Har page (login + 19 pages) 4 combinations me: laptop 1440x900 + iPhone 13, dark + light. DOM check: horizontal scroll, overlap, text < 10.5 px, JS errors.
Fixes C, D ke baad sab saaf: **0 JS errors, 0 overflow, 0 header overlap**.
Browser me poora flow chalaya: Download proof button dabaya → file download hui (event window nahi khula) → Verify proof page par VALID → finding badli to INVALID ("Leaf matches: NO") → galat JSON par saaf error.
Screenshots: `CP-DFIR-screenshots.zip` (repo me nahi; chat me alag diya).

## 6. Jo test nahi hua / dhyan rakhna

- **PostgreSQL mirror (`persist.Mirror.hold`)** asli DB par test nahi hua (sirf fake connection se).
- **Render par deploy** nahi kiya. Pehli deploy par demo ek baar re-analyse hoga (kuch second "not ready").
- Asli phone ya Safari par test nahi hua; Chromium me iPhone 13 emulation hi tha.
- `evaluation.json` abhi bhi do runs ka merge hai (`note` key me likha hai). Laptop par `python main.py evaluate` ek baar chalana.
- Chainsaw/Hayabusa (Table 8) aur benign FP ke scripts **UNTESTED** hain (Claude 4). Pehle `--limit 3` se chalana.
- Commit `c066f21`..`20f3372` ke messages me Co-Authored-By trailer subject line me chipak gaya (cosmetic).

## 7. Aapke kaam

1. GitHub par PR merge karo (Actions green check dekh ke).
2. Render redeploy karo (auto-deploy off hai). Python 3.13 fail ho to `render.yaml` me 3.12. Phir System page par 62 rules / v1.3 check karo.
3. UptimeRobot (har 10 min).
4. Zenodo: release v1.3 → DOI → README + `CITATION.cff` me `XXXXXXX` badlo.
5. Light-theme screenshots final karo (paper Figures 2-5, 7).
6. Laptop par: `python main.py evaluate` (boto3 + moto) ek baar; Chainsaw/Hayabusa `--limit 3` se; Figure 6 ka caption dekhna.
