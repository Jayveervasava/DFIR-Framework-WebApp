"""Per-finding Merkle proofs (tamper-evident, standard library only).

Every finding (a normalized event with a non-empty ``flags`` list) becomes one leaf of a binary
SHA-256 Merkle tree. The tree root is written to the HMAC-signed custody ledger, so a single finding can
later be proven to belong to the case with a short proof (about log2(n) hashes) that is checked offline,
without the rest of the case.

Shared contract (do not change without telling the other modules):
  leaf fields   event_id, time_utc, source, host, event_type, user, src_ip, target, outcome, detail,
                source_file, line_ref, flags, techniques, incident
  canonical     json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
  leaf hash     SHA-256(0x00 || canonical JSON bytes)
  node hash     SHA-256(0x01 || left || right)
  odd node      promoted to the next level unchanged (never duplicated)
  leaf order    event_id ascending
  empty tree    root = SHA-256(b"") (leaf_count 0)

Public API:
  build_tree(findings)                                  -> tree dict
  make_proof(tree, findings, event_id, ledger_info)     -> proof dict
  verify_proof(proof, trusted_root=None)                -> (ok, reason)
"""
import hashlib
import hmac
import json

ALGORITHM = "sha256-merkle-v1"
LEAF_FIELDS = ("event_id", "time_utc", "source", "host", "event_type", "user", "src_ip", "target", "outcome",
               "detail", "source_file", "line_ref", "flags", "techniques", "incident")
PROOF_VERSION = 1
EMPTY_ROOT = hashlib.sha256(b"").hexdigest()
_HEX = frozenset("0123456789abcdef")


# ------------------------------------------------------------------ hashing primitives
def leaf_fields(event):
    """The fields of an event (or of a proof's ``finding``) that are committed to by the tree."""
    return {k: event.get(k) for k in LEAF_FIELDS}


def canonical_json(fields):
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def leaf_hash(event):
    """Hex leaf hash of one finding: SHA-256(0x00 || canonical JSON)."""
    return hashlib.sha256(b"\x00" + canonical_json(leaf_fields(event)).encode("ascii")).hexdigest()


def _node(left_hex, right_hex):
    return hashlib.sha256(b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)).hexdigest()


def _is_hash(x):
    return isinstance(x, str) and len(x) == 64 and set(x) <= _HEX


def _levels(leaf_hashes):
    """All levels of the tree, level 0 = leaves. An odd last node is promoted, not duplicated."""
    level = list(leaf_hashes)
    levels = [level]
    while len(level) > 1:
        nxt = [_node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        levels.append(nxt)
        level = nxt
    return levels


def _root_of(leaf_hashes):
    return EMPTY_ROOT if not leaf_hashes else _levels(leaf_hashes)[-1][0]


def _expected_shape(index, leaf_count):
    """Sides of the siblings a valid path must contain for this leaf position (None entries are promotions, skipped)."""
    sides = []
    n = leaf_count
    i = index
    while n > 1:
        if i % 2 == 1:
            sides.append("left")
        elif i + 1 < n:
            sides.append("right")
        # else: odd last node, promoted, no sibling at this level
        i //= 2
        n = (n + 1) // 2
    return sides


# ------------------------------------------------------------------ Algorithm 1: build
def build_tree(findings):
    """Build the tree over findings (list of event dicts). Returns
    {algorithm, leaf_count, root, leaves:[{event_id, leaf_hash}]} with leaves sorted by event_id."""
    ordered = sorted(findings, key=lambda e: e["event_id"])
    ids = [e["event_id"] for e in ordered]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate event_id among findings")
    leaves = [{"event_id": e["event_id"], "leaf_hash": leaf_hash(e)} for e in ordered]
    return {"algorithm": ALGORITHM, "leaf_count": len(leaves), "root": _root_of([l["leaf_hash"] for l in leaves]),
            "leaves": leaves}


# ------------------------------------------------------------------ Algorithm 2: prove
def make_proof(tree, findings, event_id, ledger_info):
    """Inclusion proof for one finding.

    tree         result of build_tree (or merkle_tree.json loaded back)
    findings     the findings list (the proof embeds the finding itself, so it can be checked offline)
    event_id     which finding to prove
    ledger_info  dict with case_id and the ledger entry that holds the root. Accepted keys:
                 case_id, ledger_seq (or seq), ledger_entry_hash (or entry_hash). A full ledger entry plus case_id works.
    Raises KeyError if event_id is not a leaf; ValueError if the finding no longer matches the tree.
    """
    leaves = tree["leaves"]
    index = next((i for i, l in enumerate(leaves) if l["event_id"] == event_id), None)
    if index is None:
        raise KeyError(f"{event_id} is not a finding in this tree")
    finding = next((e for e in findings if e.get("event_id") == event_id), None)
    if finding is None:
        raise KeyError(f"{event_id} not found in the findings supplied")
    lh = leaf_hash(finding)
    if lh != leaves[index]["leaf_hash"]:
        raise ValueError(f"finding {event_id} does not match the tree (changed since the tree was built)")
    levels = _levels([l["leaf_hash"] for l in leaves])
    if levels[-1][0] != tree["root"]:
        raise ValueError("tree root does not match its own leaves")
    path = []
    i = index
    for level in levels[:-1]:
        if i % 2 == 1:
            path.append({"hash": level[i - 1], "side": "left"})
        elif i + 1 < len(level):
            path.append({"hash": level[i + 1], "side": "right"})
        i //= 2
    li = ledger_info or {}
    return {"version": PROOF_VERSION, "case_id": li.get("case_id"), "event_id": event_id, "leaf_hash": lh,
            "index": index, "leaf_count": len(leaves), "path": path, "root": tree["root"],
            "ledger_seq": li.get("ledger_seq", li.get("seq")),
            "ledger_entry_hash": li.get("ledger_entry_hash", li.get("entry_hash")),
            "finding": leaf_fields(finding)}


# ------------------------------------------------------------------ Algorithm 3: verify (offline)
def verify_proof(proof, trusted_root=None):
    """Check a proof using only the proof itself (and optionally a root taken from a trusted place).

    Returns (ok, reason); never raises on malformed input.
    Without trusted_root the result only says the proof is internally consistent with the root it carries:
    anyone can build a valid tree of invented findings, so pass the root read from the HMAC-verified ledger.
    """
    try:
        if not isinstance(proof, dict):
            return False, "proof is not an object"
        if proof.get("version") != PROOF_VERSION:
            return False, f"unsupported proof version {proof.get('version')!r}"
        finding, path = proof.get("finding"), proof.get("path")
        index, count = proof.get("index"), proof.get("leaf_count")
        if not isinstance(finding, dict) or not isinstance(path, list):
            return False, "malformed proof (finding or path missing)"
        if type(index) is not int or type(count) is not int or not (0 <= index < count):
            return False, "index or leaf_count invalid"
        if not _is_hash(proof.get("root")) or not _is_hash(proof.get("leaf_hash")):
            return False, "root or leaf_hash is not a SHA-256 hex string"
        if finding.get("event_id") != proof.get("event_id"):
            return False, "finding event_id differs from proof event_id"
        if set(finding) != set(LEAF_FIELDS):
            return False, "finding does not have exactly the committed fields"
        h = leaf_hash(finding)
        if h != proof["leaf_hash"]:
            return False, "finding does not match leaf_hash (finding was changed)"
        shape = _expected_shape(index, count)
        if len(path) != len(shape):
            return False, f"path length {len(path)} does not fit index {index} of {count} leaves"
        for step, want in zip(path, shape):
            if not isinstance(step, dict) or not _is_hash(step.get("hash")):
                return False, "path step is malformed"
            if step.get("side") != want:
                return False, "path side does not fit the leaf position"
            h = _node(step["hash"], h) if want == "left" else _node(h, step["hash"])
        if h != proof["root"]:
            return False, "path does not lead to the proof root"
        if trusted_root is not None:
            if not hmac.compare_digest(str(trusted_root).lower(), proof["root"]):
                return False, "proof root differs from the trusted root"
            return True, "valid: finding is a leaf of the tree with the trusted root"
        return True, "consistent with the proof's own root (no trusted root supplied, root not independently checked)"
    except Exception as exc:  # malformed input must give a clean failure, not a crash
        return False, f"malformed proof ({type(exc).__name__})"


# ------------------------------------------------------------------ Algorithm 4 helper: ledger-bind check for a proof
def verify_proof_against_ledger(proof, ledger_path, key=None):
    """Check a proof against a case's custody ledger (needs the ledger file, not the rest of the case).

    Verifies the whole ledger chain (and the HMACs when a key is available), then that the ledger entry named in
    the proof is a 'merkle' entry whose root equals the proof root, then the proof itself against that root.
    Returns (ok, reason).
    """
    import custody
    ledger = custody.CustodyLedger(ledger_path, key=key)
    ok, checks = ledger.verify(key=key)
    bad = [c for c in checks if c["type"] in ("ledger", "anchor", "merkle") and not c["ok"]]
    if bad:
        return False, f"ledger not intact: {bad[0]['item']}: {bad[0]['note']}"
    entry = next((e for e in ledger.entries if e.get("seq") == proof.get("ledger_seq")), None)
    if entry is None or entry.get("action") != "merkle":
        return False, "proof does not point to a merkle entry in this ledger"
    if entry.get("entry_hash") != proof.get("ledger_entry_hash"):
        return False, "ledger entry hash differs from the one in the proof"
    details = entry.get("details", {})
    if proof.get("leaf_count") != details.get("leaf_count"):
        return False, "proof leaf_count differs from the ledger entry (leaf_count is not covered by the root itself)"
    return verify_proof(proof, trusted_root=details.get("root"))
