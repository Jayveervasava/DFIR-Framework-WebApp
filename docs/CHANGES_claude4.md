# CHANGES - Claude 4 (paper numbers: tamper 30, Table 8, benign FP, Figure 6)

## Anumaan check (task 1) - tera anumaan SAHI tha
`evaluate.tamper_tests()` har scenario pe 7 checks chalata hai: 1 control (untouched), 5 attacks jinse detection expected hai
(evidence 1-bit flip, ledger entry edit, entry delete, truncate, forged chain with HMAC key), aur 1 documented limitation
("same forgery WITHOUT key or anchor", `expect_detect=False`). Report/dashboard sirf `expect_detect=True` ginte hain:
5 attacks x 5 scenarios = **25**. Maine 6th attack **"reorder"** (ledger me entry 2 aur 3 swap, content wahi) add kiya:
6 x 5 = **30**. Control aur limitation ab bhi bahar hain (5/5 controls verify hote hain).

## Asli numbers (python3 main.py evaluate, full run)
- **Tamper detected: 30/30** (6 attack types, har type 5/5 scenarios S1-S5 me). Controls: 5/5 verify (no false alarm).
  Known limitation (forgery without key/anchor) abhi bhi detect nahi hoti - yeh badla nahi.
- Reorder detect kaise hota hai: `custody.verify` ka sequence-gap + prev_hash-link check (HMAC pe depend nahi karta). custody.py badla nahi.
- Tests: `python3 -m unittest discover -s tests` -> 62 tests, 4 error (boto3 missing, normal), 6 skipped = baseline wahi. Existing
  `test_all_tampering_attacks_are_detected` ab reorder bhi cover karta hai aur pass hai. (Koi test "count == 30" assert nahi karta; tests/ mera nahi hai.)
- `python3 main.py tamper-demo` chala, output theek.

## IMPORTANT: evaluation.json ek single run nahi hai
Sandbox me boto3/moto nahi tha, to full run me `cloud_emulated` = `{"available": false}` aa gaya aur scalability/timings sandbox machine
(Python 3.12, Linux) ke the. Dono paper ke numbers (Table 7 scalability, cloud emulated 14/14) bigaad dete. Isliye:
- `results/evaluation.json` = tera purana laptop-run, bas har scenario ki `tamper` list naye run (6 attacks) se badli. Baaki sab (timings, scalability,
  cloud_emulated, accuracy) purane laptop run ka, **badla nahi**. File me `"note"` key hai jo yeh likhti hai.
- `results/scalability.csv` purana hi hai. `metrics_summary.csv` me sirf tamper columns badle (6/6 attacks + control = 7/7 per scenario).
- `evaluation_report.html` aur `dashboard.html` isi merged data se bane.
- Sandbox run me accuracy numbers (F1, completeness, incidents) purane run se **same** aaye (sirf timings alag).
- **Laptop pe ek baar `python main.py evaluate` (boto3+moto ke saath) chala dena** taaki sab ek hi run se aa jaye; tamper 30/30 wahan bhi aana chahiye.
- `cases/` ko `main.py evaluate` regenerate karta hai (naye hashes). Maine unhe zip me NAHI dala (tumhare nahi); dashboard original cases se bana hai.

## Badli files
`evaluate.py` (reorder test + docstring), `make_dashboard.py` (Figure 6), `README.md` (sirf "Reproduce the paper"),
`results/{evaluation.json, evaluation_report.html, metrics_summary.csv, dashboard.html}`, naya `scripts/`, `results/table8.{csv,md}`, yeh `CHANGES.md`.
heldout.py aur realdata.py **nahi badle** (zarurat nahi padi).

## Table 8 (task 2) - scripts taiyaar, Chainsaw/Hayabusa **UNTESTED, run on laptop**
`scripts/run_chainsaw.py`, `scripts/run_hayabusa.py`, `scripts/table8.py`, `scripts/_common.py`, install steps + output format: `scripts/README.md`.
- 117 samples = `results/heldout_frozen_v1.1.json` ke `scope=="in"` rows (check: 117).
- Scoring wahi rule jo heldout.py me (exact / parent match, EQUIV list) - `_common.judge` heldout.EQUIV/parent import karta hai.
- CP-DFIR frozen v1.1 row asli JSON se: **alert 36/117 (30.8%), sahi technique parent-level 26/117 (22.2%), exact 24/117 (20.5%)**, fingerprint 804638ca9a700716.
- Chainsaw/Hayabusa ke liye `results/table8.md` abhi "UNTESTED, run on laptop" dikhata hai - koi number nahi likha.
- Jo test hua: sirf parsers/matching made-up fixtures pe (`python scripts/table8.py --selftest`) aur `--dry-run` (commands print). Kisi asli tool ka output
  nahi dekha. **Chainsaw JSON layout aur Hayabusa ke flags/column names (`-p verbose`, `MitreTags`, `-w -q -C`) meri yaad se hain, verify nahi hue.**
  Pehle `--limit 3` chalana; sab zero aaye to `_common.parse_*` theek karna.
- Paper me yeh caveats table ke saath likhna: (1) 117 ka scope CP-DFIR ke rules se tay hua; (2) samples Hayabusa ke apne sample repo se hain, to Hayabusa/Sigma
  rules ne shayad inhe dekha ho; (3) tags rule-authors ki mapping hain; (4) 95% Wilson CI, samples independent nahi.

## Benign false-positive (task 3) - **rate measure NAHI hua**
Repo me ya sandbox me koi labelled real benign log nahi mila (internet band): "many-events" background logs labelled benign nahi hain, LogHub me real attacks hain,
live-host (3 alerts, ek VM) ek data point hai. Paper me "FP rate not measured" hi rehna chahiye.
`scripts/benign_fp.py` ready hai: event-level aur file-level rate + Wilson CI + per-rule breakdown, "rate" shabd sirf `--assert-benign` aur `--n-sources >= 2` pe.
Current (v1.3) rules use karta hai, frozen v1.1 nahi (fingerprint output me). Sandbox me sirf simulated S4 pe smoke test hua (script chalta hai; wo result nahi hai).
Chahiye: kai alag hosts ke clean real logs (candidate: NextronSystems/evtx-baseline - yaad se, verify karna; clean installs hain to sirf lower bound) ya apne clean VMs/servers.

## Figure 6 (task 4)
`make_dashboard.py`: Real-World Validation section me grouped horizontal bar chart "Figure 6": development labelled (25/26), development hard cases,
held-out all in-scope (alert 36/117, correct technique 26/117) aur per corpus (DeepBlueCLI 13/14 & 8/14, EVTX-to-MITRE 22/102 & 17/102, Yamato 1/1 & 1/1);
data `results/heldout_frozen_v1.1.json` + `real_data_results.json` se. **Maine maana ki Figure 6 yahi hai - tumne content nahi bataya; alag ho to batao.**
Node se JS syntax aur chart-function asli data pe chali (numbers sahi nikle); browser me visually dekha NAHI (sandbox me renderer nahi). Ek baar dashboard.html khol ke dekh lena.

## README (task 5)
"Reproduce the paper" section me rows: Figure 6, Table 8 steps 1-4, selftest, benign_fp; "UNTESTED"/"not measured yet" saaf likha. Baaki README mere section ke bahar - nahi chhua.

## Paper me kahan numbers badlenge
- **Abstract, Section 6.5, Table 7, Conclusion:** tamper "25/25 (5 attack types x 5 scenarios)" -> **"30/30 (6 attack types x 5 scenarios)"**, aur attack list me "entries reordered" jodna. Controls 5/5 wahi.
  Forged-chain-without-key limitation wahi rahegi.
- **Table 8 (naya):** CP-DFIR frozen v1.1 36 / 26 (24 exact) of 117; Chainsaw/Hayabusa laptop run ke baad.
- **Sections 6.3 / 7.3:** FP rate abhi bhi "not measured"; Table 8 ya benign_fp.json se koi FP number tab tak mat likho jab tak benign run na ho.
- **Figure 6:** naya bar chart (dashboard se).
- Scalability (Table 7 ka timing hissa), F1, completeness, cloud numbers: **koi badlav nahi**.

## Dhyan do - mere hisse ke bahar (maine nahi chhua)
1. `README.md` line ~246 (Section 3) abhi "25 of 25 ... 5 attack types x 5 scenarios" kehta hai -> 30 of 30 / 6 types (README ka owner kare).
2. **README (Sec. 4) kehta hai hard cases "0 of 5", par shipped `results/real_data_results.json` me hard 1/5 hit hai (`kerberos_pwd_spray_4771`).** Dashboard JSON se padhta hai
   (to 1/5 dikhayega). Paper/README me se ek ko sahi karo - realdata.py dobara chala ke dekho kaun sa stale hai.
3. `python main.py real-eval` heldout_results.json (v1.3 post-hoc, 68/117 alert) overwrite karta hai; paper me frozen v1.1 (36/117) hi use karna.
4. Agar baaki accounts bhi `CHANGES.md` bana rahe hain to naam badal ke merge karna.
