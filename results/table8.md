| Tool | Alert (of 117) | Correct technique, parent level (of 117) | Correct technique, exact (of 117) | Status |
|---|---|---|---|---|
| CP-DFIR (frozen v1.1) | 36/117 (30.8%, 95% CI 23-40%) | 26/117 (22.2%, 95% CI 16-31%) | 24/117 (20.5%, 95% CI 14-29%) | measured (results/heldout_frozen_v1.1.json) |
| Chainsaw | 53/117 (45.3%, 95% CI 37-54%) | 43/117 (36.8%, 95% CI 29-46%) | 40/117 (34.2%, 95% CI 26-43%) | measured |
| Hayabusa | 76/117 (65.0%, 95% CI 56-73%) | 48/117 (41.0%, 95% CI 33-50%) | 44/117 (37.6%, 95% CI 29-47%) | measured |

Versions / rule sets: CP-DFIR (frozen v1.1): rules fingerprint 804638ca9a700716; Chainsaw: chainsaw 2.12.0; rules d7c9da10c1; alert = level >= low; Hayabusa: Hayabusa v3.6.0 - Nezamezuki Release; rules 58f8f145c6; alert = level >= low

How to read this table (keep these caveats in the paper):
- Same 117 samples for every tool: the held-out samples whose labelled technique CP-DFIR has a rule for (frozen v1.1 scope). This scope is defined by CP-DFIR's rules, so it favours CP-DFIR's coverage; Chainsaw/Hayabusa cover more techniques than these 117 test.
- The sample files come from the Hayabusa sample collection; Hayabusa and Sigma rules may have been written with these files in view, so their numbers are not guaranteed to be held-out for them.
- 'Alert' = at least one detection at the stated minimum level; 'correct technique' = an ATT&CK id in the rule tags matches the label (exact) or its parent technique, with the same equivalence list as heldout.py. Sigma/Hayabusa tags are the rule authors' mapping, CP-DFIR's is the author's own.
- 95% CI = Wilson interval over samples; samples are not independent (many come from the same technique folders).
