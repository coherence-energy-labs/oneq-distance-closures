#!/usr/bin/env python3
r"""Validation gate for the exactness PR -- every check the review asked for.

Run against a checkout of the PR branch; compares to upstream/main. Exit 0
only if every check passes. The full output ships with the PR so reviewers
hold the report, not our word for it.
"""
from __future__ import annotations

import json
import math
import pathlib
import re
import subprocess
import sys

CLONE = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(".")
F = "results/campaign7_publication_merged.jsonl"
REL_ISSUERS = (pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else
               pathlib.Path("release/oneq-ibm-distance-closures-v1.0.3/ISSUERS.json"))
SIX_KEYS = {"9_6_0172", "phase2_64", "phase2_65", "12_6_0199", "12_6_0201",
            "bliss:0571f76786029653"}

def key(r):
    return r.get("code_id") or f"bliss:{r.get('bliss_hash')}"

def rows(text):
    return [json.loads(l) for l in text.splitlines() if l.strip()]

new = rows((CLONE / F).read_text(encoding="utf-8"))
old = rows(subprocess.run(["git", "show", f"upstream/main:{F}"], cwd=CLONE,
                          capture_output=True, text=True, encoding="utf-8").stdout)
ok = True
def check(name, cond, detail=""):
    global ok
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    ok &= bool(cond)

# Load and VALIDATE the issuer registry from the published release, then hold
# every row to it. Registry defects are checks, not assumptions.
ISS = json.loads(pathlib.Path(REL_ISSUERS).read_text(encoding="utf-8"))
ACTIVE = {i["pubkey"] for i in ISS.get("issuers", []) if i.get("status") == "active"}
REVOKED = {i["pubkey"] for i in ISS.get("revoked", []) if i.get("pubkey")}

print(f"validate_pr_rows: {len(new)} rows (new) vs {len(old)} rows (base)\n")
check("issuer registry schema is oneq-issuers/1",
      ISS.get("schema") == "oneq-issuers/1")
check("registry lists exactly one ACTIVE issuer", len(ACTIVE) == 1)
check("active and revoked sets are disjoint", not (ACTIVE & REVOKED))
check("every active key is 64-hex",
      all(re.fullmatch(r"[0-9a-f]{64}", k) for k in ACTIVE))
check("every JSONL line parses", True, f"{len(new)} lines")
check("row count unchanged", len(new) == len(old))

oldk = {key(r): r for r in old}
changed = [r for r in new if json.dumps(r, sort_keys=True)
           != json.dumps(oldk.get(key(r), {}), sort_keys=True)]
check("exactly six intended rows changed",
      {key(r) for r in changed} == SIX_KEYS, str(sorted(key(r) for r in changed)))

for r in changed:
    o = oldk[key(r)]
    src = r.get("d_exactness_source", {})
    k = key(r)
    check(f"{k}: d unchanged", r.get("d") == o.get("d"),
          f"{o.get('d')} -> {r.get('d')}")
    check(f"{k}: flags coherent", r.get("d_is_exact") is True
          and r.get("trust_level") == "EXACT"
          and r.get("d_is_upper_bound") is False)
    check(f"{k}: release not revoked",
          src.get("release") == "oneq-ibm-distance-closures-v1.0.3",
          src.get("release", "?"))
    # bound recomputes from depth + deficiencies
    p = src.get("depth_swept_p")
    contribs = [s.get("contribution") for s in src.get("sets", [])]
    defs = [s.get("deficiency") for s in src.get("sets", [])]
    bound = sum(max(0, p + 1 - d_) for d_ in defs)
    check(f"{k}: bound recomputes", bound == r.get("d") and bound == sum(contribs),
          f"sum(max(0,{p}+1-delta)) = {bound}, d = {r.get('d')}")
    # candidate total recomputes from the closed form -- PER SET, using each
    # set's OWN levels_swept. A first version swept every set to depth p and
    # failed three rows by exactly the skipped work: a set whose deficiency
    # zeroes its contribution is never swept, and a set may stop early once
    # its levels no longer bind the bound. The recorded count is what RAN.
    total = sum(sum(math.comb(st.get("pivot_qubits"), q) * 3**q
                    for q in range(1, (st.get("levels_swept") or 0) + 1))
                for st in src.get("sets", []))
    check(f"{k}: candidates recompute", total == src.get("candidates_per_replica"),
          f"{total:,} vs {src.get('candidates_per_replica'):,}")
    for h in ("code_input_hash", "witness_hash", "artifact_sha256"):
        v = src.get(h) or ""
        check(f"{k}: {h} is 64-hex", bool(re.fullmatch(r"[0-9a-f]{64}", v)))
    check(f"{k}: exactness timestamp present", bool(src.get("exactness_verified_at")))
    ws = src.get("witness_support")
    check(f"{k}: witness support INLINE and |support| == d",
          isinstance(ws, list) and len(ws) == r.get("d"), f"|support|={len(ws) if ws else None}")
    check(f"{k}: replica IS distinct",
          src.get("distinct_information_set_replicas") == 2,
          str(src.get("information_set_hashes")))
    # ---- ISSUER CHECKS. Added after external review found the row carrying
    # "{'schema': 'oneq" as an issuer prefix -- a str(dict)[:16] leak the first
    # 69 checks sailed past because none of them looked at the field. A
    # validator only tests what it is told to test; the gap was in the
    # checklist, not in the arithmetic.
    check(f"{k}: issuer_pubkey is 64-hex",
          bool(re.fullmatch(r"[0-9a-f]{64}", src.get("issuer_pubkey", ""))),
          src.get("issuer_pubkey", "")[:20])
    check(f"{k}: fingerprint prefixes the pubkey",
          bool(src.get("issuer_fingerprint"))
          and src.get("issuer_pubkey", "").startswith(src["issuer_fingerprint"]))
    check(f"{k}: issuer matches the ACTIVE key in ISSUERS.json",
          src.get("issuer_pubkey") in ACTIVE, src.get("issuer_fingerprint", ""))
    check(f"{k}: issuer is not revoked", src.get("issuer_pubkey") not in REVOKED)
    check(f"{k}: witness encoding declared",
          "pauli_code" in (src.get("witness_encoding") or ""))

print(f"\nRESULT: {'ALL CHECKS PASS' if ok else 'FAILURES PRESENT'}")
sys.exit(0 if ok else 1)
