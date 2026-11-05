# CHANGES — Claude 3 (frontend + UI)

Badli hui files: `webapp/static/app.js`, `webapp/static/app.css`, `CHANGES.md`.
`webapp/static/index.html` aur `webapp/app.py` **nahi** chhue.

## Kya badla (kaam ke number ke hisaab se)
1. **Download proof**: har flagged alert row me "Download proof" (Investigation, unlinked alerts, Explorer) aur event detail window me. Link: `/api/cases/<case>/findings/<event>/proof` (download). Chain-of-custody page pe naya "Merkle root of findings" card (`GET .../merkle`: root, leaf_count, ledger_seq, verified). Agar route na mile to card chupchap "not available" dikhata hai, page nahi tootta.
2. **Verify proof page** `#/verify-proof` + nav link: paste ya .json upload, optional Case ID, `POST /api/verify-proof`. Bada VALID / INVALID + reason + 2 checks (leaf matches finding, root matches ledger). Galat JSON ya server error alag red box me ("Could not verify"), INVALID se alag.
3. **Login**: "Try demo" pehla aur sabse bada button, analyst sign-in uske neeche. Version `/api/session` se (login page, uske footer, nav foot, aur har page ke neeche naya footer). Hard-code nahi.
4. `aws_collect_enabled === false` → AWS collector form chhupa, uski jagah "run CP-DFIR locally" pointer (GitHub link). Cloud page ke empty state ka text bhi badla. `can_reanalyse === false` → Re-analyse buttons (Overview, Evidence, "results out of date" box) chhupe. Flag `undefined` = purana behaviour.
5. Custody page pe note: "On the hosted demo the anchor is stored on the same server. For real evidence, run CP-DFIR locally."
6. **Entity graph**: viewBox ab nodes + headings + edge labels ka bounding box + padding hai, to load par sab kuch fit dikhta hai. Reset (⟲) = fit-to-view. Phone par (graph container < 640 px) layout vertical: groups upar-neeche, node 236 px chaude.
7. **Timeline**: axis sirf attack window (flagged events ka min–max + 5%) pe zoom. Posture/cloud-state records (12:00) axis pe nahi aate: neeche alag dashed strip "AWS account state · snapshot · not on time axis" (collected time ke saath). Window ke bahar ke related events edge pe hollow ring, legend me count.
8. **Bada text**: tables 12.8→14 px, header 12, mono 13, tags 12, ATT&CK cells 13 (columns 136 px), timeline labels 13–14.5 (SVG 1200→1000 wide, phone par scroll).
9. **Mobile**: header me logo/badge overlap fix (items `flex:none`, badge right me, ≤560 px par brand text aur badge ka time-text chhupta hai); graph full width; zoom buttons graph ke **neeche** (ab har screen par neeche, kabhi node nahi dhakte).
10. **Light theme print-ready**: muted/accents ke dark values (contrast ≥ ~4.5:1), primary button/chip white text, unobserved ATT&CK cells opacity 1, `@media print` (nav/header/buttons chhupe, tables ka max-height/scroll hata, animations band, cards na tootein).

## Kaise test kiya
- `node --check webapp/static/app.js` → OK
- `python3 -m unittest discover -s tests` → 62 tests, 4 error (boto3), baseline jaisa
- Node fake-DOM smoke test (browser nahi): timeline (axis 08:26–09:48Z, 12:00 snapshot alag strip, koi marker viewBox ke bahar nahi), graph (laptop + phone dono viewBox fit), evTable me proof sirf flagged rows par, login me demo pehle + v1.3 + guest na ho to demo button nahi, VALID/INVALID render.
- CSS braces balanced.

## Nahi ho saka / dhyan rakho
- Real browser nahi: koi pixel-level check nahi hua. CSS blind likhi hai.
- Backend routes (`merkle`, `proof`, `verify-proof`) abhi repo me nahi hain; sirf contract ke hisaab se likha. Integration test Claude 2 ke merge ke baad.
- `can_reanalyse=false` par sirf *Re-analyse* chhupa; pehli baar "Analyse" (jab koi run hi nahi) dikhta rehta hai. Alag chahiye to batao.
- Custody note hamesha dikhta hai (local par bhi); chaho to sirf `public_mode` par kar sakte hain.
- Cloud posture page ki apni table me proof button nahi; row kholo → event window me hai.
- Graph me touch-drag/pinch nahi (page scroll na ruke isliye); phone par +/−/⟲ buttons. Graph layout load par tay hota hai: rotate/resize par dobara fit karne ke liye page reload.
- Phone layout me ip→key jaise door ke edges beech wale node ke peeche se guzar sakte hain.

## Screenshot me check karna hai (har page: laptop + phone)
Dono themes (dark + light) me; light paper figures ke liye.
- [ ] Login: Try demo sabse bada/pehla, sign-in neeche, v1.3 dikh raha; phone par bhi
- [ ] Header phone par: logo, custody badge, theme, avatar overlap nahi; badge kata nahi
- [ ] Cases: card/KPI text, footer v1.3
- [ ] Evidence: hosted me AWS collector gayab + local-pointer; baki collectors theek; Re-analyse hidden (flag false)
- [ ] Overview: tables ka bada text, incident table phone par scroll
- [ ] Investigation: graph load par poora fit (laptop 1/2/3 columns; phone vertical), kuch kata nahi; zoom buttons neeche; +/−/⟲ kaam karein
- [ ] Investigation timeline: attack window zoomed, 12:00 records alag strip me, tick labels padhne layak; phone par horizontal scroll
- [ ] Investigation tables: "Download proof" column + button click par event window na khule; event window me proof button
- [ ] MITRE ATT&CK: bade cells, observed highlighted, light me low-contrast nahi
- [ ] Cloud posture: tables, empty state text (aws off)
- [ ] Evidence explorer: filters + table phone par
- [ ] Chain of custody: hosted-demo note, Merkle card (root, leaves, ledger #, verified), ledger blocks
- [ ] Verify proof: khali page, VALID result, INVALID result, galat JSON error; phone par
- [ ] Report, Activity log, Evaluation (7 pages, khaas Figures 2–5, 7), System, Users: text size aur kuch clipped nahi
- [ ] Light theme print preview (Ctrl+P): nav/header gayab, tables poori, kuch cut nahi
