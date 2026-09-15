"""An independent distance certificate: my own CNF, built from IBM's reconstruction of the code.

Shares no code with the evidence bundle's encoder, search or verifier. From a stabilizer matrix
H = [Hx | Hz] exported by ibm_rebuild_and_witness.py it writes, for weight bound W:

  variables   x_q, z_q per qubit; w_q <-> (x_q OR z_q)
  commutation for every stabilizer row h: XOR over {x_q : hz_q = 1} and {z_q : hx_q = 1} is 0
  not in S    for logical representatives L_1..L_2k (from my own GF(2) algebra): OR of the parities
  weight      sum w_q <= W with pysat's TOTALIZER encoding (the bundle used a sequential counter)
  anchors     case 0: w_0 = 1 (block-1 qubit 0); case 1: block 1 empty and w_N = 1

The anchors are sound only if Z_ell x Z_m acts on the code by translations, regularly on each block.
That is not assumed: the translation permutations are PROVEN to map the stabilizer space onto itself
on the actual matrix, for a qubit layout found by testing, before any CNF is written.

    python independent_distance_cnf.py <npy> <meta json> <W> <out dir>
"""
import json
import pathlib
import sys

import numpy as np
from pysat.card import CardEnc, EncType
from pysat.formula import IDPool


def gf2_rref(m):
    a = (np.array(m, dtype=np.uint8) % 2).copy()
    pivots = []
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
        pivots.append(c)
        r += 1
    return a[:r], pivots


def gf2_nullspace(m):
    rref, pivots = gf2_rref(m)
    cols = m.shape[1]
    free = [c for c in range(cols) if c not in set(pivots)]
    basis = []
    for f in free:
        v = np.zeros(cols, dtype=np.uint8)
        v[f] = 1
        for i, p in enumerate(pivots):
            v[p] = rref[i, f]
        basis.append(v)
    return np.array(basis, dtype=np.uint8)


def rank(m):
    return len(gf2_rref(m)[1])


def translations(h, ell, m, n):
    """Find a qubit layout under which x- and y-translations are automorphisms of the stabilizer space."""
    N = ell * m
    base = rank(h)
    layouts = {
        "index = a*m + b": lambda a, b: a * m + b,
        "index = b*ell + a": lambda a, b: b * ell + a,
    }
    for name, idx in layouts.items():
        perms = []
        for da, db in ((1, 0), (0, 1)):
            perm = np.empty(n, dtype=int)
            for a in range(ell):
                for b in range(m):
                    src, dst = idx(a, b), idx((a + da) % ell, (b + db) % m)
                    perm[src], perm[N + src] = dst, N + dst
            perms.append(perm)
        good = True
        for perm in perms:
            moved = np.zeros_like(h)
            moved[:, perm] = h[:, :n]
            moved[:, n + perm] = h[:, n:]
            if rank(np.vstack([h, moved])) != base:
                good = False
                break
        if good:
            return name
    return None


def xor_zero(clauses, pool, lits, rhs_true=False):
    """Constrain XOR(lits) = rhs; returns nothing. Tseitin chain, 4 clauses per gate."""
    if not lits:
        if rhs_true:
            clauses.append([])
        return
    acc = lits[0]
    for lit in lits[1:]:
        t = pool.id()
        clauses += [[-acc, -lit, -t], [acc, lit, -t], [acc, -lit, t], [-acc, lit, t]]
        acc = t
    clauses.append([acc] if rhs_true else [-acc])


def xor_output(clauses, pool, lits):
    """A fresh variable equal to XOR(lits)."""
    acc = lits[0]
    for lit in lits[1:]:
        t = pool.id()
        clauses += [[-acc, -lit, -t], [acc, lit, -t], [acc, -lit, t], [-acc, lit, t]]
        acc = t
    return acc


def main():
    h = np.load(sys.argv[1]).astype(np.uint8) % 2
    meta = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
    W = int(sys.argv[3])
    out = pathlib.Path(sys.argv[4])
    out.mkdir(parents=True, exist_ok=True)
    n = h.shape[1] // 2
    ell, m = meta["ell"], meta["m"]
    assert n == 2 * ell * m, "two blocks of ell*m qubits expected"

    layout = translations(h, ell, m, n)
    if layout is None:
        sys.exit("STOP: no tested layout makes the translations automorphisms; anchoring would be unsound")

    # N(S): vectors v with Hx.vz + Hz.vx = 0, i.e. the nullspace of [Hz | Hx]
    normalizer = gf2_nullspace(np.hstack([h[:, n:], h[:, :n]]))
    s_rank = rank(h)
    k = n - s_rank
    assert k == meta["k"], f"k {k} != row k {meta['k']}"
    assert normalizer.shape[0] == 2 * n - s_rank
    logicals, span = [], h.copy()
    for v in normalizer:
        if rank(np.vstack([span, v])) > rank(span):
            logicals.append(v)
            span = np.vstack([span, v])
        if len(logicals) == 2 * k:
            break
    assert len(logicals) == 2 * k, "could not complete 2k logical representatives"

    pool = IDPool()
    X = [pool.id(("x", q)) for q in range(n)]
    Z = [pool.id(("z", q)) for q in range(n)]
    Wv = [pool.id(("w", q)) for q in range(n)]
    base = []
    for q in range(n):
        base += [[-X[q], Wv[q]], [-Z[q], Wv[q]], [-Wv[q], X[q], Z[q]]]
    for row in h:
        lits = [X[q] for q in np.nonzero(row[n:])[0]] + [Z[q] for q in np.nonzero(row[:n])[0]]
        xor_zero(base, pool, lits)
    parities = []
    for lv in logicals:
        lits = [X[q] for q in np.nonzero(lv[n:])[0]] + [Z[q] for q in np.nonzero(lv[:n])[0]]
        parities.append(xor_output(base, pool, lits))
    base.append(parities)
    card = CardEnc.atmost(lits=Wv, bound=W, vpool=pool, encoding=EncType.totalizer)
    base += card.clauses

    N = ell * m
    cases = {0: [[Wv[0]]], 1: [[-Wv[q]] for q in range(N)] + [[Wv[N]]]}
    for case, extra in cases.items():
        clauses = base + extra
        nv = max(pool.top, max(abs(l) for c in clauses for l in c))
        path = out / f"{meta['code_id']}_W{W}_anchor{case}.cnf"
        with open(path, "w", encoding="ascii", newline="\n") as f:
            f.write(f"p cnf {nv} {len(clauses)}\n")
            for c in clauses:
                f.write(" ".join(map(str, c)) + " 0\n")
        print(f"{path.name}: {nv} variables, {len(clauses)} clauses")
    (out / f"{meta['code_id']}_W{W}_vars.json").write_text(
        json.dumps({"layout": layout, "n": n, "x": X, "z": Z}), encoding="utf-8")
    print(f"layout proven by rank: {layout}; k={k}; 2k={len(logicals)} logical representatives")


if __name__ == "__main__":
    main()
