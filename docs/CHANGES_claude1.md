# CHANGES – Claude 1: Merkle per-finding proofs (core)

## Contract: koi signature nahi badla
`build_tree`, `make_proof`, `verify_proof` ke signatures, leaf fields, canonical JSON, leaf/node hash, odd-node promotion, leaf order, `merkle_tree.json` keys, ledger entry aur proof JSON sab contract jaisa hai.

Contract ne jo cheezein khuli chhodi thi, unke liye maine ye choose kiya (Claude 2 aur 3 ko pata hona chahiye):

| Baat | Jo choose kiya |
|---|---|
| `tree["algorithm"]` string | `"sha256-merkle-v1"` |
| 0 findings | `merkle_tree.json` phir bhi likha jata hai: `leaf_count 0`, `root = SHA-256(b"")` = `e3b0c442...b855`; ledger me `merkle` entry bhi jati hai. Crash nahi hota. `make_proof` empty tree par `KeyError` deta hai |
| `ledger_info` (make_proof ka 4th argument) | dict with `case_id`, `ledger_seq` (ya `seq`), `ledger_entry_hash` (ya `entry_hash`). Pura ledger entry + `case_id` bhi chalega |
| `case_id` jo pipeline deta hai | case folder ka naam (`os.path.basename(case_dir)`), e.g. `S1`. `cfg["case_id"]` nahi |
| Ledger entry ka `stage` | `"Merkle"` (`action="merkle"`, `target=merkle_tree.json`, `details={root, leaf_count, algorithm}` contract ke hisaab se) |
| Leaf order | plain string sort on `event_id`. Ids `E%06d` hain, to 999,999 events tak numeric order ke barabar hai |
| Duplicate `event_id` | `build_tree` `ValueError` deta hai |
| Leaf me missing field | `event.get(field)` → `null` (e.g. unlinked finding ka `incident` = `null`) |
| `proof["finding"]` | **exactly** 15 leaf fields chahiye (`incident: null` bhi likhna hai). `verify_proof` extra ya kam keys reject karta hai |

Jo naya joda (contract me nahi tha, kuch toda nahi):
- `merkle.verify_proof_against_ledger(proof, ledger_path, key=None)`: ledger chain (aur key ho to HMAC) verify karke proof ko ledger entry ke root se check karta hai. Case folder nahi, sirf ledger file chahiye.
- `merkle.leaf_hash(event)`, `merkle.canonical_json`, `merkle.leaf_fields`, `merkle.EMPTY_ROOT` (helpers).
- `run_case()` ke `ctx` me extra keys: `merkle_tree`, `merkle_ledger_info` (seedha `make_proof` ko de sakte ho), `merkle_seconds`.
- `custody.verify` ke `checks` me naya `type: "merkle"` (report ki custody table me apne aap dikhega).

## Kya badla
| File | Badlav |
|---|---|
| `merkle.py` (naya) | Algorithms 1-3 + ledger-bound helper. Sirf standard library |
| `pipeline.py` | `_write_outputs()` me `export` ke baad: findings (`e["flags"]` non-empty) se tree, `merkle_tree.json`, `ledger.record("merkle", ...)`. `ctx` me 3 extra keys. `timings` me **koi naya key nahi** (report.py har key ko stage-table me chhapta hai, isliye alag `merkle_seconds`). Merkle ka time `output_and_custody` ke andar aata hai |
| `custody.py` | `verify()` me naya check (`_merkle_checks`): latest `merkle` entry ke liye (a) tree file ka root == ledger `details.root`, (b) root leaves se dobara compute karke wahi match, (c) `leaf_count` match. `merkle_tree.json` ka file-hash check pehle se latest-file check me aata hai. Jis ledger me `merkle` entry nahi (purane cases), unme koi naya check nahi lagta, wo pehle jaise verify hote hain (S1, S3, cloud_clean try kiye) |
| `tests/test_merkle.py` (naya) | 25 tests |

Koi aur file nahi badli (`diff -rq` se confirm kiya).

## Kaise test kiya (commands)
```
python3 -m unittest tests.test_merkle                 # 25 tests, OK
python3 -W error::ResourceWarning -m unittest tests.test_merkle   # OK, koi unclosed file nahi
python3 -m unittest discover -s tests                 # 87 tests = 62 purane + 25 naye; errors=4 (boto3 nahi hai), skipped=6 – baseline jaisa
```
Merkle se pehle (original zip) aur baad me 62 purane tests ka natija same: 4 error sab `ModuleNotFoundError: boto3`.

`tests/test_merkle.py` ye cover karta hai:
- 1, 2, 3, 7, 38 leaves: har leaf ka proof verify (trusted root ke saath aur bina).
- Contract hash check (leaf/node/ek-leaf root haath se compute karke match), order independence, empty tree, duplicate id.
- Finding badli (5 fields, aur attacker `leaf_hash` bhi dobara compute kare) → fail. `make_proof` badli hui finding par refuse.
- Galat path hash, side flip, path chhota/ulta, galat root, galat trusted root, galat index/leaf_count → fail. Malformed proofs (9 tarah) clean `False`, crash nahi.
- Duplicate-leaf attack (3 leaves, last duplicate) → root alag aata hai, same `event_id` do baar refuse, forged 4-leaf proof fail.
- Leaf ko inner node ki tarah chalane ki koshish (0x00/0x01 prefix) fail.
- Ledger: tree file root badla, leaf badla + root dobara compute kiya, leaves badle root nahi, tree file delete, ledger me `details.root` edit, ledger re-chain (HMAC se pakda, plain chain anchor se pakda).
- Pipeline S1: 38 findings, `custody_ok`, ledger entry ka format, har finding ka proof JSON round-trip ke baad verify, `verify_proof_against_ledger`, `normalized_events.json` tamper ab bhi pakda jata hai, 0-findings case crash nahi karta.

## Speed (asli runs, is sandbox ki machine par)
Case: `generate_data.build_scaled(dir, 100000)` = **104,634 records**, 88,584 events, 38 findings (wahi size jo `results/scalability.csv` ki aakhri row hai). `pipeline.run_case(..., make_report=False, key=...)`, original zip vs naya code, 5 baar alternate (orig, new, orig, new...), alag processes me. "proc" = evaluate.py wala total (acquisition + normalization + correlation + output_and_custody + custody_verification).

| Naap | Result |
|---|---|
| Merkle step khud (`ctx["merkle_seconds"]`: build_tree + file likhna + ledger.record) | median **9.2 ms** (8.2 – 9.8 ms) = proc ka ~0.2% |
| `custody.verify` ka time, original vs naya | 64.5 ms vs 64.4 ms (median) |
| End-to-end proc, original | median 4.205 s (4.123 – 4.309) |
| End-to-end proc, naya | median 4.324 s (4.254 – 4.528) |
| Paired difference (new − orig) | +0.062, +0.241, +0.128, +0.254, −0.055 s; median +0.128 s |

Dhyan se padhna: end-to-end diff (+0.128 s) seedha Merkle ka cost **nahi** hai. Wo run-to-run noise ke andar hai (sirf original ki 5 runs hi 0.19 s failti hain, aur ek paired diff negative hai) aur seedha naapa hua Merkle step sirf ~9 ms hai. Paper me Merkle ka extra cost "~9 ms (measured step), end-to-end difference within run-to-run noise (±0.1-0.2 s)" likho, "3%" mat likho.

Synthetic worst case (pipeline run nahi, sirf `merkle.py`): is case ke saare 88,584 events ko findings maan kar `build_tree` = median **0.564 s** (5 runs: 0.558 – 0.635 s). Ek proof banana 0.063 s (path 17 hashes, ye `levels` dobara banata hai), `verify_proof` 0.1 ms. Ye "agar har event finding hota" ka upper bound hai, asli S1-type cases me findings bahut kam hain.

Absolute numbers is sandbox ke hain. `results/scalability.csv` me 7.713 s tumhari apni machine ka hai (yahan original code 4.2 s leta hai), dono ko mat milana. `results/scalability.csv` maine regenerate nahi kiya (wo meri file nahi). Apni machine par `python main.py evaluate` chalao to Merkle ka time wahan ki table me khud aa jayega (`custody` column me, kyunki wo `output_and_custody` me hai).

## Jo nahi ho saka / limits
- `report.py`, `webapp/`, `main.py`, README ko Merkle ke baare me update nahi kiya (meri files nahi). Report ki custody table me naya `merkle` row apne aap dikhegi, bas.
- Proof banane ke liye CLI nahi hai, sirf Python API.
- `results/` aur `cases/` me purane saved cases regenerate nahi kiye, unme `merkle_tree.json` nahi hai.
- `leaf_count` aur `index` root me hash nahi hote. Offline `verify_proof` me `leaf_count` ko same path-shape wali doosri value (e.g. 7 → 8) par badalne se proof pass rehta hai (test me documented). `verify_proof_against_ledger` leaf_count ko ledger entry se match karwata hai, isliye wahan ye pakda jata hai. Inclusion ki guarantee par isse asar nahi padta.
- Leaf me sirf 15 contract fields hain. `severity`, `raw`, `epoch`, `session_id`, `key_id`, `logon_type`, `extra` leaf me **nahi** hain, to unko badalna Merkle proof se nahi pakda jayega (par poori `normalized_events.json` ka file hash ledger me hai).
- `verify_proof` bina `trusted_root` ke sirf itna batata hai ki proof apne hi root se consistent hai. Koi bhi nakli findings ka valid tree bana sakta hai, isliye trusted root ledger se (HMAC-verified) lena zaroori hai.
- Boto3 wale 4 tests yahan chal nahi sakte (baseline).

---

# Paper ke liye section: Per-finding Merkle proofs

Notation: `H` = SHA-256, `||` = concatenation, `canon(f)` = `json.dumps(f, sort_keys=True, separators=(",", ":"), ensure_ascii=True)` ke ASCII bytes.

## Algorithm 1: Build
```
Input : F = set of findings (events with non-empty flags)
Output: tree T = (root, leaf_count, leaves)
1  require event_id unique in F
2  sort F by event_id ascending
3  for each f in F:  L_i <- H(0x00 || canon(f restricted to the 15 leaf fields))
4  if |F| = 0: root <- H("")  and return
5  level <- [L_1 ... L_n]
6  while |level| > 1:
7      next <- [ H(0x01 || level[2j] || level[2j+1]) for j = 0 .. floor(|level|/2)-1 ]
8      if |level| is odd: append level[last] to next        # promotion, never duplication
9      level <- next
10 root <- level[0]
11 return T = (root, n, [(event_id_i, L_i)])
```

## Algorithm 2: Prove
```
Input : T, F, event_id e, ledger_info (case_id, seq, entry_hash)
Output: proof P
1  i <- index of e in T.leaves;  f <- finding with event_id e
2  fail if H(0x00 || canon(f)) != T.leaves[i].leaf_hash
3  build all levels of T;  path <- []
4  for each level except the root level:
5      if i is odd:                 append (level[i-1], "left")
6      else if i+1 < |level|:       append (level[i+1], "right")
7      # else: promoted node, no sibling at this level, nothing appended
8      i <- floor(i/2)
9  return P = {version 1, case_id, e, leaf_hash, index, leaf_count, path, root, ledger_seq, ledger_entry_hash, finding f}
```

## Algorithm 3: Verify (offline)
```
Input : proof P, optional trusted_root R*
Output: (ok, reason)
1  check P well-formed (version, hex hashes, 0 <= index < leaf_count, finding has exactly the 15 fields,
   finding.event_id = P.event_id)
2  h <- H(0x00 || canon(P.finding));  reject if h != P.leaf_hash
3  expected_sides <- sides implied by (index, leaf_count)   # same walk as Prove, no hashing
4  reject if |P.path| != |expected_sides| or any side differs
5  for each (s, side) in P.path:
6      h <- H(0x01 || s || h) if side = "left" else H(0x01 || h || s)
7  reject if h != P.root
8  if R* given: accept only if P.root = R*      # otherwise result only means "self-consistent"
9  accept
```

## Algorithm 4: Ledger-bind
```
Input : tree T, ledger L (hash-chained, HMAC key K)
1  write T to merkle_tree.json
2  L.record("merkle", target = merkle_tree.json,
           details = {root: T.root, leaf_count: T.leaf_count, algorithm: T.algorithm})
   # entry: sha256 = SHA-256(merkle_tree.json), prev_hash = hash of previous entry,
   #        entry_hash = H(entry body), hmac = HMAC-SHA256(K, entry_hash)
3  Verify(L, K):  chain + HMAC for all entries, file hash of merkle_tree.json,
                  root recomputed from the file's leaves == entry.details.root, leaf counts equal
4  Proof check against ledger: take entry P.ledger_seq, require action = "merkle",
                  entry_hash = P.ledger_entry_hash, leaf_count equal, then Verify-proof with R* = entry.details.root
```

## Threat model
**Maqsad.** Ye mechanism **tamper-evident** hai (badlav pakda jata hai), **tamper-proof nahi** (badlav roka nahi jata).

**Jo pakadta hai** (attacker ke paas HMAC key nahi hai aur ledger ki root-signed entry badal nahi sakta):
- Kisi finding ki kisi committed field ka badalna, proof me ya case me: leaf hash badal jata hai, path root tak nahi pahunchta.
- Proof ke path ka hash, side, length ya order badalna, galat root dena.
- `merkle_tree.json` badalna (root ya leaves): file hash aur ledger root se mismatch.
- Ledger me `details.root` edit karna: `entry_hash` toot jata hai; chain dobara bana de to HMAC invalid (key ke bina), aur plain chain ho to noted anchor se mismatch.
- Duplicate-leaf (CVE-2012-2459 type) attack: odd node duplicate nahi hota, promote hota hai, aur `event_id` unique hona zaroori hai.
- Leaf ko inner node ki tarah (ya ulta) pass karna: 0x00 / 0x01 domain separation.

**Jo nahi pakadta / guarantee nahi deta:**
- Root ki security ledger ke HMAC par tiki hai. Attacker ke paas HMAC key ho, ya poora ledger-write access ho (ledger + tree file + anchor sab badal de), to koi guarantee nahi. Bina key ke plain hash chain me bhi poora rewrite sirf us anchor se pakda jata hai jo case folder ke bahar noted ho.
- Completeness nahi: Merkle sirf deta hai ki *ye finding us tree me thi*. Ye nahi batata ki koi finding tree banne se pehle (normalization/correlation me) chhoot gayi ya daba di gayi, ya detection rules ne sahi findings nikali.
- Tree banne se pehle ka data (acquisition, parsing, rules) trusted maana gaya hai. Merkle post-correlation integrity deta hai, source-log authenticity nahi.
- Leaf me sirf 15 fields hain; baaki fields (`severity`, `raw`, ...) per-finding proof se protected nahi hain.
- `verify_proof` bina trusted root ke authenticity nahi, sirf self-consistency batata hai; `leaf_count` root se bound nahi.
- Time ka proof nahi (ledger timestamps attacker-controlled system clock par hain).

**Paper ke liye wording:** "tamper-evident per-finding integrity", kabhi "tamper-proof".
