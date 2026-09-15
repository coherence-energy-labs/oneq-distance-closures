"""Solve and check the independent CNFs, in both directions, for the codes exported from IBM's reconstruction.

For each code with exact distance d (claimed by the PR, or proven by IBM for a control):
  W = d-1, both anchors: CaDiCaL must say UNSATISFIABLE (exit 20) and lrat-check must print exactly
                         "c VERIFIED" on the LRAT proof; the proof is deleted afterwards.
  W = d,   both anchors: at least one must be SATISFIABLE, and each model found is re-checked OUTSIDE
                         the solver against IBM's matrix: commutes with every stabilizer, is not a
                         stabilizer, and has qubit weight <= d.

    python run_independent.py <export dir> <work dir> <jobs> <code id> [<code id> ...]
"""
import concurrent.futures as cf
import json
import pathlib
import subprocess
import sys
import time

import numpy as np

HERE = pathlib.Path(__file__).resolve().parent
CAD = "cadical"      # CaDiCaL 2.1.2 was used; any release with --lrat --no-binary works
CHK = "lrat-check"   # from drat-trim
PY = sys.executable


def gf2_rank(m):
    a = (np.array(m, dtype=np.uint8) % 2).copy()
    r = 0
    rows, cols = a.shape
    for c in range(cols):
        if r == rows:
            break
        hit = np.nonzero(a[r:, c])[0]
        if hit.size == 0:
            continue
        p = r + hit[0]
        a[[r, p]] = a[[p, r]]
        for rr in np.nonzero(a[:, c])[0]:
            if rr != r:
                a[rr] ^= a[r]
        r += 1
    return r


def generate(export, work, cid, W):
    subprocess.run([PY, str(HERE / "independent_distance_cnf.py"), str(export / f"{cid}.npy"),
                    str(export / f"{cid}.json"), str(W), str(work)], check=True, capture_output=True, text=True)


def unsat_with_proof(cnf):
    proof = cnf.with_suffix(".lrat")
    t0 = time.time()
    r = subprocess.run([CAD, "--lrat", "--no-binary", "-q", str(cnf), str(proof)], capture_output=True, text=True)
    solve = time.time() - t0
    size = proof.stat().st_size if proof.exists() else 0
    verdict = ""
    if r.returncode == 20:
        c = subprocess.run([CHK, str(cnf), str(proof)], capture_output=True, text=True)
        lines = (c.stdout + c.stderr).splitlines()
        verdict = next((ln for ln in lines if ln.strip() in ("c VERIFIED", "c NOT VERIFIED")), "").strip()
    proof.unlink(missing_ok=True)
    return r.returncode == 20 and verdict == "c VERIFIED", f"exit {r.returncode}, {solve:.0f} s, proof {size / 1e6:.0f} MB, [{verdict}]"


def sat_model(cnf):
    r = subprocess.run([CAD, "-q", str(cnf)], capture_output=True, text=True)
    if r.returncode != 10:
        return None, f"exit {r.returncode}"
    true = {int(t) for ln in r.stdout.splitlines() if ln.startswith("v ") for t in ln[2:].split() if int(t) > 0}
    return true, "exit 10"


def check_model(true, varmap, h, d):
    n = varmap["n"]
    v = np.zeros(2 * n, dtype=np.uint8)
    for q in range(n):
        v[q] = varmap["x"][q] in true
        v[n + q] = varmap["z"][q] in true
    commutes = not ((h[:, :n].astype(int) @ v[n:] + h[:, n:].astype(int) @ v[:n]) % 2).any()
    not_stab = gf2_rank(np.vstack([h, v])) == gf2_rank(h) + 1
    weight = int(np.count_nonzero(v[:n] | v[n:]))
    return commutes and not_stab and weight <= d, f"commutes={commutes} not_stabilizer={not_stab} weight={weight}"


def one_code(export, work, cid):
    meta = json.loads((export / f"{cid}.json").read_text(encoding="utf-8"))
    h = np.load(export / f"{cid}.npy").astype(np.uint8) % 2
    d = meta["d"]
    lines, ok = [], True
    generate(export, work, cid, d - 1)
    for a in (0, 1):
        good, info = unsat_with_proof(work / f"{cid}_W{d - 1}_anchor{a}.cnf")
        ok &= good
        lines.append(f"  W={d - 1} anchor{a}: {'UNSAT, proof VERIFIED' if good else 'NOT ESTABLISHED'} ({info})")
    generate(export, work, cid, d)
    varmap = json.loads((work / f"{cid}_W{d}_vars.json").read_text(encoding="utf-8"))
    found = False
    for a in (0, 1):
        true, info = sat_model(work / f"{cid}_W{d}_anchor{a}.cnf")
        if true is None:
            lines.append(f"  W={d} anchor{a}: no model ({info})")
            continue
        good, why = check_model(true, varmap, h, d)
        found |= good
        ok &= good
        lines.append(f"  W={d} anchor{a}: model {'VALID' if good else 'INVALID'} ({why})")
    ok &= found
    return cid, ok, d, lines


def main():
    export, work, jobs = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), int(sys.argv[3])
    work.mkdir(parents=True, exist_ok=True)
    ids = sys.argv[4:]
    bad = 0
    with cf.ThreadPoolExecutor(max_workers=jobs) as pool:
        for cid, ok, d, lines in pool.map(lambda c: one_code(export, work, c), ids):
            bad += not ok
            print(f"{cid}: d={d} {'PROVEN EXACT by the independent encoding' if ok else 'NOT PROVEN'}", flush=True)
            print("\n".join(lines), flush=True)
    print("INDEPENDENT DISTANCE CHECK: " + ("ALL PROVEN" if not bad else f"{bad} NOT PROVEN"))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
