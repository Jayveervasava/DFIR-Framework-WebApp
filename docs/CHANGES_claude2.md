# CHANGES — Claude 2 (webapp backend)

Badli hui files: `webapp/app.py`, `webapp/persist.py`, `tests/test_webapp.py`, `CHANGES.md`. Baaki kuch nahi chhua
(merkle.py / custody.py / pipeline.py / webapp/static/ untouched).

## Contract
Shared contract ka koi hissa **badla nahi**. Lekin contract ne 3 cheezein define nahi ki thi, mujhe assume karni padi.
Claude 1 / Claude 3 confirm karein:

1. `make_proof(tree, findings, event_id, ledger_info)`: `ledger_info` ek dict hai jisme maine ye keys daali hain:
   `case_id, seq, entry_hash, ledger_seq, ledger_entry_hash, root, leaf_count, algorithm`
   (seq / entry_hash = "merkle" ledger entry ka). Backend `proof["case_id"]` ko hamesha case id se overwrite karta hai.
2. `build_tree()` ka return `{"root","leaf_count","leaves":[{"event_id","leaf_hash"}], ...}` hona chahiye (merkle_tree.json jaisa).
   Backend tree ko case ke findings se dobara banata hai, leaves ke order me (order se farak nahi padta), aur root compare karta hai.
3. pipeline ko `case/merkle_tree.json` likhna hai aur ledger me `action="merkle"`, `target=merkle_tree.json`,
   `details={root, leaf_count, algorithm}` record karna hai (file ka sha256 CustodyLedger.record khud rakhta hai).
   Entry ki integrity check ke liye `custody._entry_hash` aur `custody._mac` (private helpers) use hote hain; na mile to
   `CustodyLedger.verify` pe fallback.

Contract me additive extras (Claude 3 ignore kar sakta hai): `GET /merkle` me `algorithm`, `problems[]`;
`/api/verify-proof` me `case_problems` (sirf jab non-empty); `/api/cases` aur `/api/cases/<id>` me per-case `can_reanalyse`;
AWS 403 me `run_locally: true`.

## Kya badla
1. **Teen routes** (sab `login_required`, case privacy `case_dir()` se, yaani dusre visitor ka case = 404):
   - `GET /api/cases/<id>/merkle` -> `{root, leaf_count, ledger_seq, verified}`. `verified` = tree file, ledger entry (hash + HMAC + file sha256),
     case ke flagged events aur dobara banaya root, sab ek-dusre se match.
   - `GET /api/cases/<id>/findings/<event_id>/proof` -> proof JSON, `Content-Disposition: attachment; filename=proof_<case>_<event>.json`.
     Proof jaari karne se pehle server khud verify karta hai. Case ki integrity toot gayi ho to 409 (proof nahi milta).
   - `POST /api/verify-proof` `{proof, case_id?}` -> `{valid, reason, leaf_matches_finding, root_matches_ledger}`.
     `case_id` ke bina sirf proof khud check hota hai (baaki do fields `null`). `case_id` ke saath ledger ka root trusted_root banta hai.
   - Status codes: galat/na-dikhne-wala case, galat event, unflagged event, ya tree-less case = 404 JSON (stack trace nahi);
     body galat = 400; 2 MB se bada = 413; merkle.py build me nahi = 501; malformed proof = `valid:false` (500 nahi).
   - Ab `/api/...` ke har 404 ka jawab JSON hai (pehle HTML tha).
2. **Demo auto re-analyse**: har analysis ke saath `case.json` me `analysis_stamp = {rules_fingerprint, rules, merkle}` store hota hai
   (`rules_fingerprint` = `heldout.rules_fingerprint()`). Startup (public mode / `DFIR_SEED_DEMO=1`) par demo case ka stamp aaj ke stamp se
   alag ho to stored evidence se dobara analyse. Purana (stamp-rahit) live demo bhi isi se pakda jayega (57 -> 62 rules).
   Evidence ko haath nahi lagta. Purane results pehle `tmp/` me copy hote hain; run fail ho to wapas rakhe jaate hain.
   `persist.py`: naya `Mirror.hold()` — re-analyse ke dauran DB sync ruka rehta hai, DB me purani poori copy rehti hai
   (beech me restart ho to adhoora case restore nahi hota); khatam hote hi ek normal sync.
3. **S1_pure demo**: alag case id `S1_pure`, sirf scenario S1 (AWS account state nahi). Purana demo (S1 + AWS state) wahi id/title,
   bas ab `demo: "s1_aws"` key se pehchana jata hai. Dono `shared`, guests ko read-only.
4. **Public mode me AWS key collection band**: route 403 + "Run CP-DFIR locally ..." message, `_job_aws` bhi refuse karta hai.
   `/api/session` me `aws_collect_enabled` (public me false).
5. `/api/session` me `can_reanalyse` (guest / logged-out = false, analyst/admin = true).
6. `tests/test_webapp.py`: 17 nayi tests (neeche).

## Asli numbers (web app ke andar chalake, sandbox me)
- Rules: 62.
- `S1_pure`: **244 events, 38 flagged**, 1 incident (evidence: windows_xml, linux_auth, cloudtrail).
- Demo S1 + AWS state: 268 events, 51 flagged, 1 incident.
- Dono demo ek saath seed + analyse: ~0.3 s (sandbox).
- Dhyan: `pipeline.run_case` ko seedha `DEFAULT_CASE` dekar chalaoge to `case_config.json` ignore hota hai aur S1 ke 74 flagged aate hain.
  Wo galat comparison hai, README me mat likhna.

## Test kaise kiya
```
python3 -m unittest discover -s tests                         # merkle.py ke bina
PYTHONPATH=/path/to/dev_stub python3 -m unittest discover -s tests   # dev stub ke saath
```
- Baseline: 62 tests, 4 error (boto3), 6 skip. Ab: **79 tests, wahi 4 boto3 error, koi nayi fail nahi.**
  Stub ke saath skip = 6 (baseline jitne); stub ke bina 10 (4 Merkle tests merkle.py ka intezaar karte hain).
- Mutation check (copy par): AWS block hata ke, fingerprint check hata ke, guest `can_reanalyse` true karke, verify-proof ka
  privacy check hata ke — chaaron me tests fail hue.
- Merkle tests `merkle.py` hote hi chalte hain. Jab tak pipeline khud tree nahi banata, test helper `add_merkle_if_missing`
  contract ke mutabiq tree + ledger entry bana deta hai; pipeline bana de to helper kuch nahi karta.

## Kya nahi ho saka / dhyan dene wali baatein
- **Asli merkle.py ke saath test nahi hua** (abhi mila nahi). Stub `dev_stub/merkle.py` alag file hai, zip ke andar nahi, repo me commit mat karna.
- **PostgreSQL mirror asli DB par test nahi hua** (psycopg / DB sandbox me nahi). `hold()` ka logic fake connection se test hai.
- Render par live deploy test nahi hua.
- Pehli deploy par live demo ek baar dobara analyse hoga; us dauran (Render par kuch second) us case ke results "not ready" dikhenge.
  Naye ledger ka anchor `anchors.json` me history ke saath jud jata hai.
- Jab merkle.py + pipeline integration aayega, stamp ka `merkle` flag badlega, to demo cases ek baar apne aap dobara analyse honge.
  Agar pipeline tree nahi banata, to routes 404 "no Merkle tree yet" denge.
- Demo cases ab har startup par ensure hote hain: admin ne demo delete kiya to restart par wapas ban jayega (pehle bhi khali CASES me yehi hota tha).
- **Brief se farak**: "server guests ka Re-analyse block karta hai" sirf shared demo case par sach hai; guest apne case par analyse
  kar sakta hai. Isliye session flag spec ke hisaab se guest ke liye false hai, par Claude 3 ko button dikhane ke liye
  per-case `can_reanalyse` (`/api/cases`, `/api/cases/<id>`) padhna chahiye.
- `cases/S1_pure/` repo me nahi joda: zaroorat nahi, console `webapp_data/cases/S1_pure` startup par khud banata hai.
- `CHANGES.md` ka naam sab Claude accounts ka same hoga: merge conflict se bachne ke liye rename kar lena (jaise `CHANGES_claude2.md`).
