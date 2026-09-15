"""Rebuild the six codes with IBM's own constructor from IBM's own catalogue rows, check each PR row's
inline witness against that reconstruction, and export the stabilizer matrices for an independent
distance check. Run from the root of a qiskit-community/qcode-discovery checkout, inside its locked
environment:

    uv run python ibm_rebuild_and_witness.py <IBM catalogue.jsonl> <PR catalogue.jsonl> <out dir>

Nothing here comes from the evidence bundle except the witness supports being checked.
"""
import json
import pathlib
import sys

import numpy as np

sys.path.insert(0, str(pathlib.Path.cwd()))
from evaluation.pbb_code import build_pbb_code  # noqa: E402  IBM's constructor

IDS = ["12_6_0199", "12_6_0201", "phase2_64", "phase2_65", "9_6_0172", "0571f76786029653"]


def key(row):
    return row.get("code_id") or row.get("bliss_hash")


def gf2_rank(m):
    a = (np.array(m, dtype=np.uint8) % 2).copy()
    rank = 0
    rows, cols = a.shape
    for c in range(cols):
        pivot = next((r for r in range(rank, rows) if a[r, c]), None)
        if pivot is None:
            continue
        a[[rank, pivot]] = a[[pivot, rank]]
        hits = np.nonzero(a[:, c])[0]
        for r in hits:
            if r != rank:
                a[r] ^= a[rank]
        rank += 1
        if rank == rows:
            break
    return rank


def load(path):
    rows = {}
    for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            if key(r) in IDS:
                rows[key(r)] = r
    return rows


ibm, pr = load(sys.argv[1]), load(sys.argv[2])
all_rows = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines() if line.strip()]
out = pathlib.Path(sys.argv[3])
out.mkdir(parents=True, exist_ok=True)
failures = 0
for cid in IDS:
    r, p = ibm[cid], pr[cid]
    code = build_pbb_code(r["ell"], r["m"], r["A_terms"], r["B_terms"], r.get("C_terms"), r.get("D_terms"))
    h = np.array(code.matrix, dtype=np.uint8) % 2
    n = h.shape[1] // 2
    rank = gf2_rank(h)
    k_from_rank = n - rank
    checks = {
        "IBM row and PR row describe the same code": all(r[f] == p[f] for f in ("ell", "m", "A_terms", "B_terms", "C_terms", "D_terms", "n", "k", "d")),
        "n matches the row": n == r["n"],
        "k from IBM's code object matches the row": int(code.dimension) == r["k"],
        "k from the GF(2) rank matches the row": k_from_rank == r["k"],
    }
    v = np.zeros(2 * n, dtype=np.uint8)
    for q, pauli in p["d_exactness_source"]["witness_support"]:
        if pauli in (1, 3):
            v[q] = 1
        if pauli in (2, 3):
            v[n + q] = 1
    sympl = (h[:, :n].astype(int) @ v[n:] + h[:, n:].astype(int) @ v[:n]) % 2
    weight = int(np.count_nonzero(v[:n] | v[n:]))
    checks["witness weight equals d"] = weight == r["d"]
    checks["witness commutes with every stabilizer (IBM's matrix)"] = not sympl.any()
    checks["witness is not a stabilizer (rank rises)"] = gf2_rank(np.vstack([h, v])) == rank + 1
    ok = all(checks.values())
    failures += not ok
    np.save(out / f"{cid}.npy", h)
    (out / f"{cid}.json").write_text(json.dumps({"code_id": cid, "ell": r["ell"], "m": r["m"], "n": n, "k": r["k"], "d": r["d"],
                                                 "stabilizer_rows": int(h.shape[0]), "rank": rank}), encoding="utf-8")
    print(f"{cid:18} n={n} k={r['k']} d={r['d']} rank={rank} -> {'ALL CHECKS PASS' if ok else 'FAILED'}")
    for name, good in checks.items():
        print(f"    {'ok  ' if good else 'FAIL'} {name}")
# CONTROLS: small non-CSS rows whose distance IBM itself proved exact (MILP or exhaustive weight search),
# none of them ours. The independent encoder must reproduce these, in both directions, before its
# verdict on the six means anything.
exact = sorted((row for row in all_rows
                if row.get("d_is_exact") and row.get("trust_level") == "EXACT"
                and (row.get("C_terms") or row.get("D_terms")) and key(row) not in IDS),
               key=lambda row: (row["n"], row["d"]))
picked = []
for method in ("milp_exact", "exact_w6"):
    first = next((row for row in exact if row["d_method"] == method), None)
    if first is not None:
        picked.append(first)
picked.append(next(row for row in exact if row not in picked))
for row in picked:
    code = build_pbb_code(row["ell"], row["m"], row["A_terms"], row["B_terms"], row.get("C_terms"), row.get("D_terms"))
    h = np.array(code.matrix, dtype=np.uint8) % 2
    n = h.shape[1] // 2
    good = n == row["n"] and int(code.dimension) == row["k"] and n - gf2_rank(h) == row["k"]
    failures += not good
    name = f"control_{key(row)}"
    np.save(out / f"{name}.npy", h)
    (out / f"{name}.json").write_text(json.dumps({"code_id": name, "ell": row["ell"], "m": row["m"], "n": n, "k": row["k"],
                                                  "d": row["d"], "d_method": row["d_method"], "control": True}), encoding="utf-8")
    print(f"{name:26} n={n} k={row['k']} d={row['d']} IBM method={row['d_method']} -> {'rebuilt, n and k match' if good else 'FAILED'}")
print("IBM RECONSTRUCTION AND WITNESSES: " + ("ALL SIX PASS" if not failures else f"{failures} FAILED"))
sys.exit(1 if failures else 0)
