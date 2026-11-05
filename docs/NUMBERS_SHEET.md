# CP-DFIR v1.3: numbers sheet (paper ke liye)

Har number neeche likhi file ya run se hai, koi bhi haath se nahi likha. Wording hamesha **"tamper-evident"**, kabhi "tamper-proof" nahi.

| Kya | Number | Source |
|---|---|---|
| Detection rules | **62** | `/api/system/info` (merged branch), README layers table |
| Tamper tests | **30 / 30 detected** (6 attack types x 5 scenarios: evidence bit-flip, entry edit, entry delete, truncate, forged chain with HMAC, **reorder**). Controls 5/5 verify. Forgery without key/anchor: not detected (documented limit) | `results/evaluation.json` (`scenarios[].tamper`), `metrics_summary.csv` |
| Development set (EVTX-ATTACK-SAMPLES, labelled) | **25 / 26** | `results/real_data_results.json` |
| Hard cases | **1 / 5** (Kerberos password spray 4771 via brute_force). Missed: renamed regsvr32, msxsl, hashdump 4656/4663 LSASS, TeamViewer dumper | `results/real_data_results.json` (`hard: true`) |
| Held-out, frozen v1.1 (fingerprint `804638ca9a700716`) | 320 samples; in-scope **117**; alert **36 (30.8%)**; correct technique (parent) **26 (22.2%)**; exact 24 (20.5%) | `results/heldout_frozen_v1.1.json` |
| `S1_pure` demo case | **244 events, 38 flagged**, 1 incident | E2E run, merged branch (web app) |
| Demo S1 + AWS state | **268 events, 51 flagged**, 1 incident | E2E run, merged branch (web app) |
| Merkle step cost | median **9.2 ms** (8.2-9.8 ms) for 104,634 records / 88,584 events / 38 findings. Machine: Claude 1 ka sandbox. End-to-end difference run-to-run noise ke andar hai. **Percentage overhead mat likhna** | `docs/CHANGES_claude1.md` |
| Merkle tree (S1) | 38 leaves, ledger entry #7 (stage `Merkle`), algorithm `sha256-merkle-v1` | E2E run |
| Scalability | 104,634 records in **7.713 s**; throughput 16,772 → 13,565 records/s (README me rounded: 16,800 → 13,600); F1 1.000 at every size | `results/scalability.csv` (purana laptop run, Python 3.13.16) |
| Cloud emulated | 14/14 (single region), 15/15 (all regions), 0 FP | `results/evaluation.json` → `cloud_emulated` |
| Tests (CP-DFIR) | **105** (62 + 25 Merkle + 17 web + 1 collector named-pipe regression). boto3/moto ke saath: 105/105 pass | `pytest tests` on `main` |
| Zenodo DOI | v1.3: **10.5281/zenodo.23973650**; all versions (concept): 10.5281/zenodo.23973649. Release `v1.3` = commit `e9aa892` | zenodo.org/records/23973650 |
| Showcase test count (Claude 7) | 105 + 55 + 41 = **201** | Brief ka formula |

## Dhyan
- `evaluation.json` do runs ka merge hai (tamper lists naye run se, baaki purane laptop run se). Laptop par `python main.py evaluate` ek baar chalao. Usse timings, 7.7 s aur 16,800 → 13,600 badal sakte hain; paper me wahi naye numbers daalna.
- Table 8 me Chainsaw/Hayabusa ke numbers abhi **nahi** hain (UNTESTED). Benign FP rate **not measured**.
- `heldout_results.json` (v1.3 post-hoc, 68/117) paper ke main result me use mat karna; frozen v1.1 (36/117) hi asli held-out hai.
