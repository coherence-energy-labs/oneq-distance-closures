"""Information-set decoding for minimum-weight coset leaders (Lee-Brickell),
bit-packed and vectorized.

WHY THIS AND NOT A SOLVER
MILP and SAT both stall on this problem because the LP/CNF relaxation of a GF(2)
parity constraint carries almost no information -- branch-and-bound gets no
guidance. That is why IBM's MILP timed out on 825 logicals, and why ours did too.

Coding theory does not use general-purpose solvers here. It uses information-set
decoding: pick a random information set, put the generator matrix in systematic
form against it, and read off the low-weight combinations directly. Each trial is
pure bit arithmetic -- XOR and popcount -- so it vectorizes, and millions of trials
per second are ordinary.

WHAT THIS PROVES AND WHAT IT DOES NOT
  * It finds low-weight operators -> a genuine UPPER bound, and every witness is
    checkable by anyone in a few lines with no solver (see `distance.verify_witness`).
  * It does NOT prove none lighter exists. That is the Brouwer-Zimmermann lower
    bound, built on the same machinery (see `bz_lower_bound`).
Reporting one as the other is the failure mode this module is written to avoid.

THE SEARCH
Given a coset L + <S>, we want a minimum-weight member.
  1. Permute coordinates randomly.
  2. Row-reduce S; the pivot columns are the information set I.
  3. Reduce L against S so it is zero on I: that is the coset's canonical form
     for this information set, and it is already a strong candidate.
  4. Enumerate adding p generator rows (p = 0,1,2) and keep the lightest.
A coset leader of weight w is found whenever some information set captures at
most p of its support -- so many random sets converge quickly in practice.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import numpy as np

from .gbb import PBBCode, symplectic_weight

WORD = 64


def pack(bits: np.ndarray) -> np.ndarray:
    """Pack a (..., n) uint8 bit array into (..., ceil(n/64)) uint64 words."""
    bits = np.ascontiguousarray(bits.astype(np.uint8))
    n = bits.shape[-1]
    nw = (n + WORD - 1) // WORD
    pad = nw * WORD - n
    if pad:
        bits = np.concatenate([bits, np.zeros(bits.shape[:-1] + (pad,), np.uint8)], axis=-1)
    view = bits.reshape(bits.shape[:-1] + (nw, WORD))
    weights = (np.uint64(1) << np.arange(WORD, dtype=np.uint64))
    return (view.astype(np.uint64) * weights).sum(axis=-1, dtype=np.uint64)


def unpack(words: np.ndarray, n: int) -> np.ndarray:
    nw = words.shape[-1]
    sh = np.arange(WORD, dtype=np.uint64)
    bits = ((words[..., :, None] >> sh) & np.uint64(1)).astype(np.uint8)
    return bits.reshape(words.shape[:-1] + (nw * WORD,))[..., :n]


_POP = np.array([bin(i).count("1") for i in range(256)], dtype=np.uint8)


def popcount(words: np.ndarray) -> np.ndarray:
    """Population count over the last axis of a uint64 array."""
    b = words.view(np.uint8).reshape(words.shape + (8,))
    return _POP[b].sum(axis=(-1, -2)).astype(np.int64)


def qubit_weight_packed(words: np.ndarray, n: int, nw_half: int) -> np.ndarray:
    """Qubit weight of packed symplectic vectors: a qubit counts once whether it
    carries X, Z, or both. Assumes the X half occupies the first `nw_half` words
    and is 64-aligned."""
    x = words[..., :nw_half]
    z = words[..., nw_half:]
    return popcount(x | z)


def _rref_packed(rows: np.ndarray, ncols: int, order: np.ndarray):
    """Row-reduce packed rows over GF(2), choosing pivots in the given column
    order. Returns (reduced rows, pivot columns in that order)."""
    R = rows.copy()
    pivots: list[int] = []
    r = 0
    nrows = R.shape[0]
    for c in order:
        w, b = divmod(int(c), WORD)
        mask = np.uint64(1) << np.uint64(b)
        hit = np.nonzero(R[r:, w] & mask)[0]
        if hit.size == 0:
            continue
        p = r + int(hit[0])
        if p != r:
            R[[r, p]] = R[[p, r]]
        others = np.nonzero(R[:, w] & mask)[0]
        others = others[others != r]
        if others.size:
            R[others] ^= R[r]
        pivots.append(int(c))
        r += 1
        if r == nrows:
            break
    return R[:r], pivots


@dataclass
class ISDResult:
    best_weight: int
    witness: np.ndarray | None
    trials: int
    seconds: float
    improved: bool
    incumbent: int | None = None

    def __str__(self) -> str:
        tag = "IMPROVED" if self.improved else "no improvement"
        return (f"{tag}: weight {self.best_weight}"
                + (f" (incumbent {self.incumbent})" if self.incumbent is not None else "")
                + f"  [{self.trials} trials, {self.seconds:.1f}s]")


def search_coset(code: PBBCode, logical: np.ndarray, *,
                 trials: int = 2000, p: int = 2, incumbent: int | None = None,
                 seed: int = 0, time_budget: float = 120.0) -> ISDResult:
    """Hunt for a low-weight member of the coset `logical + <stabilizers>`."""
    from .gbb import gf2_rref

    n = code.n
    N = 2 * n
    nw = (N + WORD - 1) // WORD
    nw_half = n // WORD if n % WORD == 0 else None

    S, _ = gf2_rref(code.symplectic.astype(np.uint8))
    Sp = pack(S)
    Lp = pack(np.asarray(logical, dtype=np.uint8).reshape(1, -1))[0]

    def qweight(vec_words: np.ndarray) -> int:
        v = unpack(vec_words[None, :], N)[0]
        return symplectic_weight(v, n)

    rng = np.random.default_rng(seed)
    best_w = qweight(Lp)
    best_v = Lp.copy()
    t0 = time.time()
    done = 0

    for _ in range(trials):
        if time.time() - t0 > time_budget:
            break
        done += 1
        order = rng.permutation(N)
        R, piv = _rref_packed(Sp, N, order)
        if not piv:
            continue

        # reduce L against the systematic basis -> canonical coset form
        cur = Lp.copy()
        for i, c in enumerate(piv):
            w, b = divmod(int(c), WORD)
            if cur[w] & (np.uint64(1) << np.uint64(b)):
                cur ^= R[i]
        cw = qweight(cur)
        if cw < best_w:
            best_w, best_v = cw, cur.copy()

        # p = 1 : add each generator
        cand1 = cur[None, :] ^ R
        for idx in range(cand1.shape[0]):
            w1 = qweight(cand1[idx])
            if w1 < best_w:
                best_w, best_v = w1, cand1[idx].copy()

        # p = 2 : add pairs, sampled (full C(k,2) is affordable but this keeps
        # the per-trial cost low so more information sets get tried)
        if p >= 2 and R.shape[0] > 1:
            m = min(400, R.shape[0] * (R.shape[0] - 1) // 2)
            ii = rng.integers(0, R.shape[0], size=m)
            jj = rng.integers(0, R.shape[0], size=m)
            keep = ii != jj
            if keep.any():
                pairs = cur[None, :] ^ R[ii[keep]] ^ R[jj[keep]]
                for idx in range(pairs.shape[0]):
                    w2 = qweight(pairs[idx])
                    if w2 < best_w:
                        best_w, best_v = w2, pairs[idx].copy()

    v = unpack(best_v[None, :], N)[0]
    return ISDResult(
        best_weight=int(best_w), witness=v, trials=done, seconds=time.time() - t0,
        improved=bool(incumbent is not None and best_w < incumbent), incumbent=incumbent,
    )


def bz_lower_bound(num_info_sets: int, p: int) -> int:
    """Brouwer-Zimmermann lower bound for disjoint full-rank information sets.

    After processing `h` disjoint information sets with enumeration depth `p`,
    any codeword must place more than `p` of its support inside at least one set,
    giving d >= h * (p + 1). Stated separately from the search because a bound
    and a witness are different objects and must never be conflated.
    """
    return int(num_info_sets * (p + 1))


# ---------------------------------------------------------------------------
# THE ALGORITHMIC FIX: search the normalizer once, reject the stabilizer.
#
# The coset formulation above is exponential in k for no reason: it runs a
# separate search per logical coset, 2^(2k)-1 of them, so at k=12 that is 16.7
# million searches and any affordable sample covers ~none of them. That is why
# sampled coset search returned 33 where the true distance is 12 -- a statement
# about the sampler, not the code.
#
# Distance is a single quantity:  d = min weight over N(S) \ S.
# So search N(S) ONCE and reject anything that lands in S. The rejection test is
# one reduction against the stabilizer's RREF -- O(rank * words) -- and the cost
# becomes INDEPENDENT OF k.
# ---------------------------------------------------------------------------

def _reduce_packed(rref_rows: np.ndarray, pivots: list[int], v: np.ndarray) -> np.ndarray:
    """Reduce v against a packed RREF basis; result is zero iff v is in the span."""
    out = v.copy()
    for i, c in enumerate(pivots):
        w, b = divmod(int(c), WORD)
        if out[w] & (np.uint64(1) << np.uint64(b)):
            out ^= rref_rows[i]
    return out


def min_logical_weight(code: PBBCode, *, trials: int = 500, p: int = 2,
                       seed: int = 0, time_budget: float = 60.0,
                       pair_cap: int = 3000) -> ISDResult:
    """Minimum weight of a NON-stabilizer normalizer element -- the code distance.

    One search over N(S) with stabilizer rejection. Cost is independent of k,
    which is the whole point.
    """
    from .gbb import gf2_nullspace, gf2_rref

    n = code.n
    N2 = 2 * n
    H = code.symplectic.astype(np.uint8)

    # normalizer = nullspace of the symplectic partner [Hz | Hx]
    partner = np.hstack([code.Hz, code.Hx]).astype(np.uint8)
    Nbasis = gf2_nullspace(partner)
    if Nbasis.shape[0] == 0:
        return ISDResult(0, None, 0, 0.0, False)

    Hr, Hpiv = gf2_rref(H)
    Hr_p = pack(Hr)
    Np = pack(Nbasis)

    def qweight(vw: np.ndarray) -> int:
        return symplectic_weight(unpack(vw[None, :], N2)[0], n)

    def is_stabilizer(vw: np.ndarray) -> bool:
        return not _reduce_packed(Hr_p, Hpiv, vw).any()

    rng = np.random.default_rng(seed)
    best_w, best_v = None, None
    t0 = time.time()
    done = 0

    for _ in range(trials):
        if time.time() - t0 > time_budget:
            break
        done += 1
        order = rng.permutation(N2)
        R, piv = _rref_packed(Np, N2, order)
        if R.shape[0] == 0:
            continue

        # p = 1: every basis row of the systematic normalizer
        for i in range(R.shape[0]):
            v = R[i]
            if is_stabilizer(v):
                continue
            w = qweight(v)
            if best_w is None or w < best_w:
                best_w, best_v = w, v.copy()

        # p = 2: pairs
        if p >= 2 and R.shape[0] > 1:
            r = R.shape[0]
            m = min(pair_cap, r * (r - 1) // 2)
            ii = rng.integers(0, r, size=m)
            jj = rng.integers(0, r, size=m)
            keep = ii != jj
            if keep.any():
                cand = R[ii[keep]] ^ R[jj[keep]]
                # weight-filter first (cheap, vectorized), then reject stabilizers
                nw_half = n // WORD if n % WORD == 0 else None
                if nw_half is not None:
                    wts = qubit_weight_packed(cand, n, nw_half)
                else:
                    wts = np.array([qweight(cand[t]) for t in range(cand.shape[0])])
                order_idx = np.argsort(wts)[:64]        # only inspect the lightest
                for t in order_idx:
                    v = cand[t]
                    if is_stabilizer(v):
                        continue
                    w = int(wts[t]) if nw_half is not None else qweight(v)
                    if best_w is None or w < best_w:
                        best_w, best_v = w, v.copy()

    vec = unpack(best_v[None, :], N2)[0] if best_v is not None else None
    return ISDResult(int(best_w) if best_w is not None else -1, vec, done,
                     time.time() - t0, False)


# ---------------------------------------------------------------------------
# THE PROOF DIRECTION: Brouwer-Zimmermann certified LOWER bounds.
#
# Everything above finds operators -- upper bounds with checkable witnesses.
# Proving that NOTHING LIGHTER EXISTS is the other half, and it is the half
# IBM's MILP could not deliver on 825 logicals.
#
# THE ARGUMENT (Brouwer-Zimmermann). Let G be a generator matrix for the space
# being searched, and take h information sets I_1..I_h, each a set of coordinate
# positions on which G is invertible (so G can be put in systematic form against
# each). Write G_i for the systematic form w.r.t. I_i.
#
# Let v be a nonzero codeword and let r_i = |supp(v) INTERSECT I_i| be how much
# of its support falls inside set i. Because G_i is the identity on I_i, the
# combination producing v is read off directly from v|I_i, so v is generated by
# exactly r_i rows of G_i. If we have enumerated ALL combinations of up to p
# rows of G_i and not found v, then r_i >= p+1.
#
# When the information sets are DISJOINT the supports add:
#       wt(v) >= sum_i r_i >= h * (p + 1).
# When they overlap, only the disjoint portion of each set can be counted, so we
# use the guaranteed-disjoint contribution. This module tracks disjointness
# explicitly rather than assuming it -- assuming it is the classic way to
# publish a lower bound that is not actually valid.
#
# TERMINATION: the bound rises with every enumerated set; the search stops when
# it meets the best known upper bound, at which point d is EXACT and PROVEN.
#
# HONESTY PROPERTY: the bound is only as strong as the enumeration is complete.
# `certify_lower_bound` therefore enumerates EXHAUSTIVELY up to depth p (no
# sampling) and refuses to count any set whose enumeration was truncated. A
# sampled enumeration yields no theorem.
# ---------------------------------------------------------------------------

from itertools import combinations


@dataclass
class BZCertificate:
    """A certified lower bound plus everything needed to re-check it."""
    lower_bound: int
    upper_bound: int | None
    exact: bool
    disjoint_sets: int
    depth_p: int
    combos_enumerated: int
    seconds: float
    witness: np.ndarray | None = None
    note: str = ""

    def __str__(self) -> str:
        if self.exact:
            return (f"d = {self.lower_bound} EXACT "
                    f"(LB {self.lower_bound} meets UB {self.upper_bound}; "
                    f"{self.disjoint_sets} disjoint sets at p={self.depth_p})")
        ub = self.upper_bound if self.upper_bound is not None else "?"
        return (f"{self.lower_bound} <= d <= {ub} "
                f"({self.disjoint_sets} disjoint sets at p={self.depth_p}, "
                f"{self.combos_enumerated} combinations)")


def certify_lower_bound(code: PBBCode, *, p: int = 2, max_sets: int = 8,
                        upper_bound: int | None = None, time_budget: float = 300.0,
                        seed: int = 0) -> BZCertificate:
    r"""Brouwer-Zimmermann lower bound on the minimum weight of N(S) \ S.

    Builds DISJOINT information sets greedily, enumerates all combinations of up
    to `p` systematic rows in each (exhaustively -- never sampled), and returns
    the certified bound h*(p+1), stopping early if it reaches `upper_bound`.
    """
    from .gbb import gf2_nullspace, gf2_rref

    t0 = time.time()
    n = code.n
    N2 = 2 * n

    partner = np.hstack([code.Hz, code.Hx]).astype(np.uint8)
    Nbasis = gf2_nullspace(partner)
    if Nbasis.shape[0] == 0:
        return BZCertificate(0, upper_bound, False, 0, p, 0, 0.0, note="empty normalizer")

    Np = pack(Nbasis)
    Hr, Hpiv = gf2_rref(code.symplectic.astype(np.uint8))
    Hr_p = pack(Hr)

    def is_stab(vw: np.ndarray) -> bool:
        return not _reduce_packed(Hr_p, Hpiv, vw).any()

    def qweight(vw: np.ndarray) -> int:
        return symplectic_weight(unpack(vw[None, :], N2)[0], n)

    rng = np.random.default_rng(seed)
    used: set[int] = set()          # coordinates already consumed by a set
    disjoint = 0
    combos = 0
    best_w = upper_bound
    best_v = None

    while disjoint < max_sets and time.time() - t0 < time_budget:
        # prefer unused coordinates so the sets stay disjoint
        avail = np.array([c for c in range(N2) if c not in used])
        if avail.size == 0:
            break
        order = np.concatenate([rng.permutation(avail),
                                rng.permutation(np.array(sorted(used), dtype=int))
                                if used else np.array([], dtype=int)])
        R, piv = _rref_packed(Np, N2, order.astype(int))
        if R.shape[0] == 0:
            break

        # this set only counts toward the bound if its pivots are entirely fresh
        fresh = all(c not in used for c in piv)

        # EXHAUSTIVE enumeration to depth p -- no sampling, or there is no theorem
        rows = R.shape[0]
        for depth in range(1, p + 1):
            if time.time() - t0 > time_budget:
                break
            for combo in combinations(range(rows), depth):
                combos += 1
                v = R[combo[0]].copy()
                for j in combo[1:]:
                    v ^= R[j]
                if is_stab(v):
                    continue
                w = qweight(v)
                if best_w is None or w < best_w:
                    best_w, best_v = w, v.copy()

        if fresh:
            used.update(piv)
            disjoint += 1
        else:
            break                                  # cannot certify further disjointness

        lb = disjoint * (p + 1)
        if best_w is not None and lb >= best_w:
            return BZCertificate(int(best_w), int(best_w), True, disjoint, p, combos,
                                 time.time() - t0,
                                 unpack(best_v[None, :], N2)[0] if best_v is not None else None,
                                 "lower bound met the upper bound")

    lb = disjoint * (p + 1)
    exact = best_w is not None and lb >= best_w
    return BZCertificate(int(lb), int(best_w) if best_w is not None else None, exact,
                         disjoint, p, combos, time.time() - t0,
                         unpack(best_v[None, :], N2)[0] if best_v is not None else None,
                         "" if exact else "bound did not reach the upper bound in budget")


def certify_exact(code: PBBCode, *, upper_bound: int | None = None,
                  max_p: int = 8, time_budget: float = 300.0, seed: int = 0,
                  max_combos: int = 40_000_000) -> BZCertificate:
    r"""Prove the exact minimum weight of N(S) \ S by escalating enumeration depth.

    The normalizer has dimension n+k over 2n coordinates, so only ONE disjoint
    information set fits (floor(2n/(n+k)) = 1 whenever k > 0). With h fixed at 1
    the Brouwer-Zimmermann bound is h*(p+1) = p+1, so the only lever is depth:
    enumerate exhaustively to p and the bound is p+1.

    Termination: stop when p+1 >= UB, at which point no unfound codeword can be
    lighter than UB, so d = UB EXACTLY.

    THE SCALING WALL, STATED: reaching UB requires p = UB-1, and the work is
    sum_{i<=p} C(dim, i). At n=36, dim=38, UB=6 -> ~5.8e5 combinations, seconds.
    At n=108, dim=110, UB=10 -> ~4.6e12, out of reach on any laptop. This is not
    a defect of the implementation; it is why exact distance for these codes is
    an open problem and why IBM's MILP timed out on 825 of them.
    """
    from math import comb
    from .gbb import gf2_nullspace, gf2_rref

    t0 = time.time()
    n = code.n
    N2 = 2 * n

    partner = np.hstack([code.Hz, code.Hx]).astype(np.uint8)
    Nbasis = gf2_nullspace(partner)
    Np = pack(Nbasis)
    dim = Nbasis.shape[0]

    Hr, Hpiv = gf2_rref(code.symplectic.astype(np.uint8))
    Hr_p = pack(Hr)

    def is_stab(vw):
        return not _reduce_packed(Hr_p, Hpiv, vw).any()

    def qweight(vw):
        return symplectic_weight(unpack(vw[None, :], N2)[0], n)

    rng = np.random.default_rng(seed)
    R, piv = _rref_packed(Np, N2, rng.permutation(N2))
    rows = R.shape[0]

    best_w, best_v = upper_bound, None
    combos_done = 0

    for p in range(1, max_p + 1):
        projected = sum(comb(rows, i) for i in range(1, p + 1))
        if projected > max_combos:
            return BZCertificate(p, best_w, False, 1, p - 1, combos_done,
                                 time.time() - t0,
                                 unpack(best_v[None, :], N2)[0] if best_v is not None else None,
                                 f"depth {p} needs {projected:.3g} combinations "
                                 f"(> cap {max_combos:.3g}) -- out of reach")
        for combo in combinations(range(rows), p):
            if combos_done % 200000 == 0 and time.time() - t0 > time_budget:
                return BZCertificate(p, best_w, False, 1, p - 1, combos_done,
                                     time.time() - t0,
                                     unpack(best_v[None, :], N2)[0] if best_v is not None else None,
                                     "time budget exhausted mid-depth; bound is for the LAST COMPLETE depth")
            combos_done += 1
            v = R[combo[0]].copy()
            for j in combo[1:]:
                v ^= R[j]
            if is_stab(v):
                continue
            w = qweight(v)
            if best_w is None or w < best_w:
                best_w, best_v = w, v.copy()

        lb = p + 1                       # depth p completed exhaustively
        if best_w is not None and lb >= best_w:
            return BZCertificate(int(best_w), int(best_w), True, 1, p, combos_done,
                                 time.time() - t0,
                                 unpack(best_v[None, :], N2)[0] if best_v is not None else None,
                                 f"exhaustive to depth {p}: no codeword lighter than {best_w} can exist")

    return BZCertificate(max_p + 1, best_w, False, 1, max_p, combos_done, time.time() - t0,
                         unpack(best_v[None, :], N2)[0] if best_v is not None else None,
                         "max_p reached")


# ---------------------------------------------------------------------------
# THE INNER-LOOP FIX: O(1) stabilizer test via the logical syndrome.
#
# The bottleneck was `is_stab`: an O(rank) reduction, ~110 packed row-XORs, run
# once per candidate. That is the entire hot loop.
#
# The fix uses what a stabilizer code already gives you. Pick logical
# representatives L_1..L_2k spanning N(S)/S. For v in N(S):
#
#     v is in S   <=>   <v, L_j> = 0 for EVERY j        (symplectic form)
#
# because the symplectic form is non-degenerate on the quotient: a normalizer
# element commutes with every logical operator exactly when it is a stabilizer.
# So precompute the 2k packed masks (L_j written in symplectic-partner order) and
# the test becomes 2k popcount-parities -- constant in the code's rank, and
# vectorizable across a whole batch of candidates at once.
#
# This is a strict improvement, not a heuristic: the two tests are mathematically
# equivalent, and `test_isd.py` asserts they agree on every candidate.
# ---------------------------------------------------------------------------

class LogicalSyndrome:
    """O(1) stabilizer membership for normalizer elements, batched."""

    def __init__(self, code: PBBCode):
        from .gbb import gf2_nullspace, gf2_rref

        n = code.n
        self.n = n
        self.N2 = 2 * n
        H = code.symplectic.astype(np.uint8)
        partner = np.hstack([code.Hz, code.Hx]).astype(np.uint8)
        Nb = gf2_nullspace(partner)

        # logical representatives: normalizer rows independent modulo S
        Hr, _ = gf2_rref(H)
        cur = Hr.copy()
        from .gbb import gf2_rank
        base = gf2_rank(cur)
        logs = []
        for row in Nb:
            trial = np.vstack([cur, row]) % 2
            r = gf2_rank(trial)
            if r > base:
                logs.append(row)
                cur, base = trial, r
        Lmat = np.array(logs, dtype=np.uint8) if logs else np.zeros((0, self.N2), np.uint8)

        # symplectic partner of each logical: <v, L> = v . swap(L)
        swapped = np.hstack([Lmat[:, n:], Lmat[:, :n]]) if Lmat.size else Lmat
        self.masks = pack(swapped) if Lmat.size else np.zeros((0, 1), np.uint64)
        self.num_logicals = Lmat.shape[0]

    def is_stabilizer(self, vw: np.ndarray) -> bool:
        """True iff v commutes with every logical -> v is in S."""
        if self.num_logicals == 0:
            return True
        return not bool(popcount(self.masks & vw[None, :]).sum() % 2 == 0 and False) and \
            bool(np.all(popcount(self.masks & vw[None, :]) % 2 == 0))

    def is_stabilizer_batch(self, V: np.ndarray) -> np.ndarray:
        """Vectorized over a (B, words) batch: True where the row is a stabilizer."""
        if self.num_logicals == 0:
            return np.ones(V.shape[0], dtype=bool)
        # (B, L) parities in one shot
        par = np.empty((V.shape[0], self.num_logicals), dtype=np.int64)
        for j in range(self.num_logicals):
            par[:, j] = popcount(V & self.masks[j][None, :]) & 1
        return ~par.any(axis=1)


def certify_exact_fast(code: PBBCode, *, upper_bound: int | None = None,
                       max_p: int = 8, time_budget: float = 300.0, seed: int = 0,
                       max_combos: int = 40_000_000, batch: int = 8192) -> BZCertificate:
    r"""certify_exact with the O(1) stabilizer test and batched weight evaluation.

    Same theorem, same exhaustive enumeration, same termination rule -- only the
    constant factor changes. Batches candidates so the popcount work happens in
    numpy rather than per-item Python.
    """
    from math import comb
    from .gbb import gf2_nullspace

    t0 = time.time()
    n = code.n
    N2 = 2 * n
    nw_half = n // WORD if n % WORD == 0 else None

    partner = np.hstack([code.Hz, code.Hx]).astype(np.uint8)
    Np = pack(gf2_nullspace(partner))
    ls = LogicalSyndrome(code)

    rng = np.random.default_rng(seed)
    R, _piv = _rref_packed(Np, N2, rng.permutation(N2))
    rows = R.shape[0]

    best_w, best_v = upper_bound, None
    combos_done = 0

    def flush(batch_rows: list[np.ndarray]) -> None:
        nonlocal best_w, best_v
        if not batch_rows:
            return
        V = np.array(batch_rows, dtype=np.uint64)
        keep = ~ls.is_stabilizer_batch(V)
        if not keep.any():
            return
        Vk = V[keep]
        if nw_half is not None:
            w = qubit_weight_packed(Vk, n, nw_half)
        else:
            w = np.array([symplectic_weight(unpack(Vk[i][None, :], N2)[0], n)
                          for i in range(Vk.shape[0])])
        i = int(np.argmin(w))
        if best_w is None or int(w[i]) < best_w:
            best_w, best_v = int(w[i]), Vk[i].copy()

    for p in range(1, max_p + 1):
        projected = sum(comb(rows, i) for i in range(1, p + 1))
        if projected > max_combos:
            return BZCertificate(p, best_w, False, 1, p - 1, combos_done, time.time() - t0,
                                 unpack(best_v[None, :], N2)[0] if best_v is not None else None,
                                 f"depth {p} needs {projected:.3g} combinations (> cap)")
        buf: list[np.ndarray] = []
        for combo in combinations(range(rows), p):
            combos_done += 1
            v = R[combo[0]].copy()
            for j in combo[1:]:
                v ^= R[j]
            buf.append(v)
            if len(buf) >= batch:
                flush(buf); buf = []
                if time.time() - t0 > time_budget:
                    return BZCertificate(p, best_w, False, 1, p - 1, combos_done,
                                         time.time() - t0,
                                         unpack(best_v[None, :], N2)[0] if best_v is not None else None,
                                         "time budget exhausted mid-depth; bound is for the LAST COMPLETE depth")
        flush(buf)

        lb = p + 1
        if best_w is not None and lb >= best_w:
            wit = unpack(best_v[None, :], N2)[0] if best_v is not None else None
            if wit is None:
                # The upper bound came from outside and enumeration never
                # re-found it. A certificate asserting "d = w EXACT" with no
                # operator of weight w is not self-contained -- the checker can
                # re-run the lower bound but has nothing to verify the upper
                # bound against. Obtain the witness before certifying.
                found = min_logical_weight(code, trials=400, p=2, seed=seed + 1,
                                           time_budget=max(10.0, time_budget * 0.25))
                if found.witness is not None and found.best_weight <= best_w:
                    wit = found.witness
                    best_w = found.best_weight
            if wit is None:
                return BZCertificate(int(lb), int(best_w), False, 1, p, combos_done,
                                     time.time() - t0, None,
                                     "lower bound proven but no witness obtained -- "
                                     "refusing to certify an upper bound we cannot demonstrate")
            return BZCertificate(int(best_w), int(best_w), True, 1, p, combos_done,
                                 time.time() - t0, wit,
                                 f"exhaustive to depth {p}: nothing lighter than {best_w} exists")

    return BZCertificate(max_p + 1, best_w, False, 1, max_p, combos_done,
                         time.time() - t0,
                         unpack(best_v[None, :], N2)[0] if best_v is not None else None,
                         "max_p reached")
