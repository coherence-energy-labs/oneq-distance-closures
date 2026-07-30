"""Certified lower bounds on quantum code distance -- Zimmermann's refinement,
enumerated over QUBITS rather than columns.

This module is the PROOF half. `isd.py` finds operators (upper bounds, each with
a witness anyone can check); this one proves that nothing lighter exists. Keeping
them apart is deliberate: a bound and a witness are different objects and the
classic way to publish a wrong result is to report one as the other.


WHY A SECOND CERTIFIER -- TWO DEFECTS IN THE FIRST ONE
------------------------------------------------------
`isd.certify_exact` enumerates XOR-combinations of up to p rows of a generator
matrix systematic on a pivot COLUMN set, then concludes `d >= p+1`. Two problems.

1. THE BOUND IS ON THE WRONG WEIGHT. Brouwer-Zimmermann justifies "v is produced
   by exactly |supp(v) & P| rows", so missing v at depth p gives

       |supp(v) & P| >= p+1                 <- HAMMING weight, over 2n columns

   but the quantity being bounded is QUBIT weight, and a symplectic vector's
   Hamming weight is up to TWICE its qubit weight (a Y is one qubit, two
   columns). The implication actually earned is `qubit_wt >= ceil((p+1)/2)`.
   `p+1` is sound only if minimum-weight operators carry no Y in the information
   set -- a property of the code that the engine never checks.

   MEASURED (experiments/gate0b_ibm825/probe_bound_soundness.py): across 8 codes
   and 48 runs from independent random information sets, zero false proofs, and
   all 334 minimum-weight logicals found carry zero Y. So the old engine never
   produced a wrong number on this corpus -- it was relying, silently, on a
   condition it did not state. Conditional soundness is not soundness.

2. ONLY ONE INFORMATION SET FITS. Its docstring reads: "The normalizer has
   dimension n+k over 2n coordinates, so only ONE disjoint information set fits
   ... the only lever is depth." That is Brouwer's original bound, which needs
   sets that are disjoint AND full rank. ZIMMERMANN's refinement drops the
   full-rank requirement and prices rank deficiency into the bound, which is
   exactly what a rate-1/2 code needs.

BOTH DISSOLVE AT ONCE by enumerating over qubits instead of columns.


THE CONSTRUCTION
----------------
Order the 2n columns so the two columns of a qubit are adjacent, and row-reduce.
Each pivot QUBIT then owns one or two pivot columns, hence one or two rows of the
systematic basis; a qubit owning rows {a, b} contributes three non-identity
options {a, b, a^b} -- precisely X, Z, Y on that qubit. Write

    M_i(v) = the qubit support of v restricted to matrix i's pivot columns.

Since the basis is systematic, v is the XOR of the chosen options over M_i(v).
Enumerating every subset of at most p pivot qubits against all of its options
therefore covers exactly the set { v : |M_i(v)| <= p }, EXHAUSTIVELY.


THE BOUND
---------
Take qubit sets I_1..I_m, pairwise DISJOINT, and let

    Q_i = pivot qubits of matrix i        d_i = |Q_i \\ I_i|   (the deficiency)

If v survived depth p in every matrix then |M_i(v)| >= p+1, and since
M_i(v) is a subset of the qubit support of v,

    |qsupp(v) & I_i|  >=  |M_i(v) & I_i|  >=  |M_i(v)| - d_i  >=  p + 1 - d_i

and the I_i are disjoint, so the contributions add:

    qubit_wt(v)  >=  SUM_i max(0, p + 1 - d_i).                          (*)

(*) bounds QUBIT weight directly. No Y caveat, no factor of two, sound for any
stabilizer code, CSS or not. Every d_i is MEASURED from the actual reduction --
never assumed -- because assuming disjointness or full rank is how invalid
lower bounds get published.

Stabilizer elements are rejected from the incumbent only, never from the
enumeration: the theorem needs total coverage, and a minimum-weight LOGICAL is
still enumerated whether or not stabilizers are also passing through.


WHAT IT BUYS
------------
For n=108, K=110 the normalizer has 55 pivot qubits; one full set of 55 leaves
53 for a second, whose measured deficiency is small. The bound becomes roughly
2p instead of p+1, so proving d >= 10 needs p=5 rather than p=9:

    column enumeration, p=9   5.09e12 combinations
    qubit enumeration,  p=5   1.59e09 candidates          ~3,190x less work

for an identical conclusion. Same theorem, honest arithmetic, three orders of
magnitude.


PACKING
-------
The X and Z halves are packed into SEPARATE 64-bit-aligned word blocks, so

    qubit_weight = popcount(words[:nwh] | words[nwh:])

is a vectorized expression for EVERY n. (The previous layout packed all 2n bits
contiguously and could only do this when 64 divides n -- true for none of the
catalogue's sizes {36, 72, 108, 144, 180, 360}, so its batched weight path was
dead code on every real code and every candidate fell back to a per-item Python
loop.) All array work goes through an `xp` module argument, so passing cupy runs
the identical enumeration on the GPU.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from itertools import combinations
from math import comb

import numpy as np

from .coverage import SpectrumCompleteness
from .gbb import PBBCode, gf2_nullspace, symplectic_weight

WORD = 64


# --------------------------------------------------------------- split packing

def sym_layout(n: int) -> tuple[int, int]:
    """(words per half, total words) for the split-aligned symplectic layout."""
    nwh = (n + WORD - 1) // WORD
    return nwh, 2 * nwh


def pack_sym(bits: np.ndarray, n: int) -> np.ndarray:
    """Pack (..., 2n) uint8 symplectic vectors into (..., 2*nwh) uint64 with the
    X and Z halves independently word-aligned."""
    bits = np.ascontiguousarray(np.asarray(bits, dtype=np.uint8))
    nwh, _ = sym_layout(n)

    def half(h):
        pad = nwh * WORD - n
        if pad:
            h = np.concatenate([h, np.zeros(h.shape[:-1] + (pad,), np.uint8)], axis=-1)
        v = h.reshape(h.shape[:-1] + (nwh, WORD))
        w = np.uint64(1) << np.arange(WORD, dtype=np.uint64)
        return (v.astype(np.uint64) * w).sum(axis=-1, dtype=np.uint64)

    return np.concatenate([half(bits[..., :n]), half(bits[..., n:])], axis=-1)


def unpack_sym(words: np.ndarray, n: int) -> np.ndarray:
    """Inverse of `pack_sym`."""
    nwh, _ = sym_layout(n)
    sh = np.arange(WORD, dtype=np.uint64)

    def half(w):
        b = ((w[..., :, None] >> sh) & np.uint64(1)).astype(np.uint8)
        return b.reshape(w.shape[:-1] + (w.shape[-1] * WORD,))[..., :n]

    return np.concatenate([half(words[..., :nwh]), half(words[..., nwh:])], axis=-1)


def import_cupy():
    """Import cupy with a working JIT, or return None.

    cupy compiles every kernel at run time through its OWN bundled NVRTC, but
    feeds it the headers under CUDA_PATH. When those versions differ the
    compiler chokes on syntax from the newer headers and EVERY kernel fails --
    here cupy ships NVRTC 12.9 while CUDA_PATH points at 13.1, so its fp4/fp6/
    fp8 headers fail to parse and the GPU path dies on first use.

    Clearing CUDA_PATH makes cupy fall back to its own bundled headers, which
    match its compiler. Done before the import so nothing has cached the bad
    path, and only when the versions actually disagree. Silently dropping to
    CPU instead would turn a 10-minute proof into a 2-hour one with no notice.
    """
    import os
    saved = {k: os.environ.pop(k, None) for k in ("CUDA_PATH", "CUDA_HOME")}
    try:
        import cupy as cp
        cp.arange(4, dtype=cp.uint64).sum()      # force one real compile
        return cp
    except Exception:                                       # pragma: no cover
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
        return None


_BITWISE_COUNT_OK: dict[str, bool] = {}


def _native_popcount(xp):
    """The native popcount ufunc if it both EXISTS and RUNS, else None.

    Presence is not capability: cupy exposes `bitwise_count` but compiles it
    through NVRTC, which raises CompileException against mismatched CUDA
    headers -- exactly the case on this machine (CUDA 13.1). Probing by
    attribute would take a path that dies mid-enumeration, so probe by
    EXECUTION, once, and cache the answer."""
    name = getattr(xp, "__name__", str(xp))
    ok = _BITWISE_COUNT_OK.get(name)
    bc = getattr(xp, "bitwise_count", None)
    if bc is None:
        return None
    if ok is None:
        try:
            int(bc(xp.asarray([np.uint64(0xFF)], dtype=xp.uint64)).sum())
            ok = True
        except Exception:
            ok = False
        _BITWISE_COUNT_OK[name] = ok
    return bc if ok else None


def popcount(a, xp=np):
    """Population count over the last axis. Uses the native ufunc where it is
    genuinely usable and falls back to SWAR, which is still fully vectorized."""
    bc = _native_popcount(xp)
    if bc is not None:
        return bc(a).sum(axis=-1, dtype=xp.int64)
    x = a
    m1 = xp.uint64(0x5555555555555555)
    m2 = xp.uint64(0x3333333333333333)
    m4 = xp.uint64(0x0F0F0F0F0F0F0F0F)
    h1 = xp.uint64(0x0101010101010101)
    x = x - ((x >> xp.uint64(1)) & m1)
    x = (x & m2) + ((x >> xp.uint64(2)) & m2)
    x = (x + (x >> xp.uint64(4))) & m4
    return ((x * h1) >> xp.uint64(56)).sum(axis=-1, dtype=xp.int64)


def qweight_sym(V, nwh: int, xp=np):
    """Qubit weight of split-packed symplectic vectors -- valid for every n."""
    return popcount(V[..., :nwh] | V[..., nwh:], xp)


def _col_tables(n: int) -> tuple[np.ndarray, np.ndarray]:
    """Column index -> (word, bit) under the split layout."""
    nwh, nw = sym_layout(n)
    c = np.arange(2 * n)
    x = c < n
    d = np.where(x, c, c - n)
    return np.where(x, d // WORD, nwh + d // WORD).astype(int), (d % WORD).astype(int)


def rref_sym(rows: np.ndarray, order, cw: np.ndarray, cb: np.ndarray):
    """Row-reduce split-packed rows over GF(2), taking pivots in `order`."""
    R = rows.copy()
    pivots: list[int] = []
    r = 0
    nr = R.shape[0]
    for c in order:
        c = int(c)
        w = cw[c]
        mask = np.uint64(1) << np.uint64(cb[c])
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
        pivots.append(c)
        r += 1
        if r == nr:
            break
    return R[:r], pivots


# ------------------------------------------------------------------ the engine

@dataclass
class SetInfo:
    """One information set, with the deficiency that was MEASURED, not assumed."""
    index: int
    pivot_qubits: int
    assigned_qubits: int
    deficiency: int
    contribution: int = 0
    levels_swept: int = 0        # how many depths 1..p were actually enumerated
    # WHICH qubits, not just how many. The counts alone cannot distinguish two
    # genuinely different information sets, so a certificate carrying only
    # `pivot_qubits: 56` makes "the replicas used different sets" an assertion a
    # reader must take on faith. The list makes it checkable.
    pivot_list: list[int] = field(default_factory=list)

    def to_json(self) -> dict:
        return {"index": self.index, "pivot_qubits": self.pivot_qubits,
                "assigned_qubits": self.assigned_qubits,
                "deficiency": self.deficiency, "contribution": self.contribution,
                "levels_swept": self.levels_swept,
                "pivot_list": list(self.pivot_list)}


def _witness_support(v) -> list[list[int]]:
    """Symplectic vector -> [[qubit, pauli], ...] with pauli 1=X, 2=Z, 3=Y.

    Compact, order-stable, and re-inflatable by anyone with the code's matrices,
    which is what makes a published certificate checkable by a stranger."""
    v = np.asarray(v, dtype=np.uint8).reshape(-1)
    n = v.shape[0] // 2
    out = []
    for q in range(n):
        code = int(v[q]) | (int(v[n + q]) << 1)      # 1=X, 2=Z, 3=Y
        if code:
            out.append([q, code])
    return out


def witness_from_support(support, n: int) -> np.ndarray:
    """Inverse of `_witness_support` -- rebuild the operator to re-verify it."""
    v = np.zeros(2 * n, dtype=np.uint8)
    for q, code in support:
        if code & 1:
            v[int(q)] = 1
        if code & 2:
            v[n + int(q)] = 1
    return v


@dataclass
class ZCertificate:
    """A certified lower bound plus everything needed to re-check it."""
    lower_bound: int
    upper_bound: int | None
    exact: bool
    depth_p: int
    candidates: int
    seconds: float
    sets: list[SetInfo] = field(default_factory=list)
    witness: np.ndarray | None = None
    note: str = ""
    backend: str = "numpy"
    # A_d -- the number of DISTINCT minimum-weight logical operators found.
    # Logical error rate scales as A_d * p^d: the distance sets the exponent,
    # the multiplicity sets the PREFACTOR, and two codes of equal d can differ
    # by orders of magnitude. The sweep already visits every candidate at
    # weight <= p, so this costs nothing extra -- it was simply being discarded
    # by returning a scalar. Counted over the enumeration actually performed.
    multiplicity_at_best: int = 0
    multiplicity_is_complete: bool = False
    # The minimum-weight operators THEMSELVES, packed, not merely their tally.
    # A count cannot be decomposed; the vectors can be sorted into logical
    # classes, which is the only way to tell a genuine spread in failure modes
    # from a code that simply has more stabilizer-equivalent spellings of the
    # same one.
    min_weight_packed: list = field(default_factory=list)
    # Completeness DERIVED, never declared. `multiplicity_is_complete` above is
    # kept as a convenience mirror of this object's verdict; the object is what
    # a verifier recomputes.
    spectrum: object | None = None

    def __str__(self) -> str:
        if self.exact:
            return (f"d = {self.lower_bound} EXACT  [p={self.depth_p}, "
                    f"{len(self.sets)} sets, {self.candidates:,} candidates, "
                    f"{self.seconds:.1f}s, {self.backend}]")
        ub = self.upper_bound if self.upper_bound is not None else "?"
        return (f"{self.lower_bound} <= d <= {ub}  [p={self.depth_p}, "
                f"{len(self.sets)} sets, {self.candidates:,} candidates, "
                f"{self.seconds:.1f}s, {self.backend}]")

    def to_json(self) -> dict:
        from .provenance import SCHEMA_VERSION, SEARCHER_VERSION, VERIFIER_MIN_VERSION
        return {"schema_version": SCHEMA_VERSION,
                "searcher_version": SEARCHER_VERSION,
                "verifier_min_version": VERIFIER_MIN_VERSION,
                "lower_bound": self.lower_bound, "upper_bound": self.upper_bound,
                "exact": self.exact, "depth_p": self.depth_p,
                "candidates": self.candidates, "seconds": round(self.seconds, 3),
                "sets": [s.to_json() for s in self.sets], "note": self.note,
                "backend": self.backend, "has_witness": self.witness is not None,
                "A_d_observed": self.multiplicity_at_best,
                "A_d_is_complete_count": self.multiplicity_is_complete,
                # The completeness RULE and depth, so a reader re-derives the
                # weight range instead of trusting a boolean. A depth-3 sweep of
                # a distance-6 code reported "complete" under the old flag and
                # cost us a retracted headline.
                "spectrum": (None if self.spectrum is None
                             else self.spectrum.to_json(self.lower_bound)),
                # THE WITNESS VECTOR ITSELF, not just a flag saying one existed.
                # `has_witness: true` is an assertion; the operator is evidence.
                # Without it a reader can re-check the lower bound's arithmetic
                # but has nothing to verify the UPPER bound against -- which is
                # exactly the self-contained-certificate rule this engine
                # enforces internally and was silently dropping at serialization.
                # Stored as the support list (qubit, pauli) so it stays compact
                # and human-checkable: pauli 1=X, 2=Z, 3=Y.
                "witness_support": (None if self.witness is None else
                                    _witness_support(self.witness))}


def _logical_masks(code: PBBCode) -> np.ndarray:
    """Split-packed symplectic partners of a logical basis. v is a stabilizer iff
    it has even overlap with every one of these."""
    from .gbb import gf2_rank, gf2_rref

    n = code.n
    Nb = gf2_nullspace(np.hstack([code.Hz, code.Hx]).astype(np.uint8))
    Hr, _ = gf2_rref(code.symplectic.astype(np.uint8))
    cur, base, logs = Hr.copy(), None, []
    base = gf2_rank(cur)
    for row in Nb:
        trial = np.vstack([cur, row]) % 2
        r = gf2_rank(trial)
        if r > base:
            logs.append(row)
            cur, base = trial, r
    L = np.array(logs, dtype=np.uint8) if logs else np.zeros((0, 2 * n), np.uint8)
    swapped = np.hstack([L[:, n:], L[:, :n]]) if L.size else L
    return pack_sym(swapped, n) if L.size else np.zeros((0, sym_layout(n)[1]), np.uint64)


def _interleaved(qubits, n: int) -> list[int]:
    """Column order putting both columns of each listed qubit together."""
    out: list[int] = []
    for q in qubits:
        out.append(int(q))
        out.append(int(q) + n)
    return out


def _pack_bits(bits: np.ndarray) -> np.ndarray:
    """Pack (M, L) uint8 into (M, ceil(L/64)) uint64."""
    bits = np.ascontiguousarray(np.asarray(bits, dtype=np.uint8))
    L = bits.shape[-1]
    nw = (L + WORD - 1) // WORD
    pad = nw * WORD - L
    if pad:
        bits = np.concatenate([bits, np.zeros(bits.shape[:-1] + (pad,), np.uint8)], axis=-1)
    v = bits.reshape(bits.shape[:-1] + (nw, WORD))
    w = np.uint64(1) << np.arange(WORD, dtype=np.uint64)
    return (v.astype(np.uint64) * w).sum(axis=-1, dtype=np.uint64)


def _lsb(v: np.ndarray) -> int | None:
    """Index of the lowest set bit of a packed vector, or None if it is zero."""
    nz = np.nonzero(v)[0]
    if nz.size == 0:
        return None
    w = int(nz[0])
    word = int(v[w])
    return w * WORD + (word & -word).bit_length() - 1


def _pair_greedy_qubits(Nb: np.ndarray, n: int, rng, avail: list[int]) -> list[int]:
    r"""Choose an information set made of FULLY PAIRED qubits.

    A qubit contributing only one pivot column pushes the pivot-qubit count Kq
    one above its floor ceil(K/2), and since the next disjoint set's deficiency
    is 2*Kq - n, every such qubit costs TWO off that set's contribution to the
    bound. Greedy elimination in a random column order accepts singletons freely.

    This accepts a qubit only when BOTH of its columns are independent of what
    has been taken, deferring the rest -- a matroid greedy over the column space,
    which reaches the floor whenever the code admits it. Falls back to singletons
    only if the paired pass cannot reach full rank, so it can never do worse.
    """
    K = Nb.shape[0]
    cols = _pack_bits(np.ascontiguousarray(Nb.T))          # (2n, ceil(K/64))
    basis: dict[int, np.ndarray] = {}
    chosen: list[int] = []

    def reduce(v):
        v = v.copy()
        while True:
            b = _lsb(v)
            if b is None:
                return None, None
            if b in basis:
                v = v ^ basis[b]
            else:
                return v, b

    for q in rng.permutation(avail):
        if len(basis) >= K:
            break
        q = int(q)
        va, ba = reduce(cols[q])
        if va is None:
            continue                                        # x column dependent
        saved = dict(basis)
        basis[ba] = va
        vb, bb = reduce(cols[q + n])
        if vb is None:                                      # z column dependent
            basis = saved                                   # take neither: defer
            continue
        basis[bb] = vb
        chosen.append(q)
    return chosen


def _groups_from_pivots(R: np.ndarray, pivots: list[int], n: int):
    """Bundle the systematic rows by pivot QUBIT.

    Returns (options, qubit_ids). options[j] holds the three non-identity
    settings of qubit j -- {X, Z, Y} when it owns two pivot columns; a single
    setting repeated when it owns one, which enumerates a superset and so keeps
    coverage total."""
    by_q: dict[int, list[int]] = {}
    for row_idx, c in enumerate(pivots):
        by_q.setdefault(c if c < n else c - n, []).append(row_idx)
    qids = sorted(by_q)
    opts = np.empty((len(qids), 3, R.shape[1]), dtype=np.uint64)
    for j, q in enumerate(qids):
        rr = by_q[q]
        a = R[rr[0]]
        b = R[rr[1]] if len(rr) > 1 else a
        opts[j, 0], opts[j, 1], opts[j, 2] = a, b, a ^ b
    return opts, np.array(qids, dtype=int)


def _choice_table(p: int) -> np.ndarray:
    """All 3^p option tuples for a depth-p qubit combination."""
    t = np.indices((3,) * p).reshape(p, -1).T if p else np.zeros((1, 0), int)
    return np.ascontiguousarray(t.astype(np.int64))


def _chain(*iterables):
    """itertools.chain, local so the sweep's backoff can re-queue work without
    importing at call time."""
    for it in iterables:
        for x in it:
            yield x


def _sweep_depth(opts, masks, nwh, p, best_w, deadline, xp, chunk,
                 acc: set | None = None):
    """Exhaustively enumerate every candidate with qubit-message-support exactly
    p. Returns (best_w, best_v, candidates, completed)."""
    nq = opts.shape[0]
    if nq < p:
        return best_w, None, 0, True, 0
    table_h = _choice_table(p)                               # (3^p, p) on host
    T = table_h.shape[0]
    # Flatten (qubit, option) into ONE axis so each term is a single-axis gather
    # -- numpy and cupy both dispatch that to `take`, which is markedly faster
    # than two-axis advanced indexing on the same data.
    optsf = opts.reshape(-1, opts.shape[-1])                 # (nq*3, NW)
    tcol = [xp.asarray(np.ascontiguousarray(table_h[:, t]))[None, :] for t in range(p)]
    best_v = None
    seen = 0
    # A_d accumulates across the ENTIRE certification, not per sweep: the
    # minimum-weight operator is typically found at an EARLY depth, while the
    # bound terminates at a LATER one where no new minimum appears. A per-call
    # tally therefore reported 0 -- correct for that call, useless as A_d.
    seen_min: set = acc if acc is not None else set()
    it = combinations(range(nq), p)
    while True:
        block = []
        for _ in range(chunk):
            nxt = next(it, None)
            if nxt is None:
                break
            block.append(nxt)
        if not block:
            return best_w, best_v, seen, True, len(seen_min)
        # ADAPTIVE BACKOFF. A 25-minute proof must not die because the machine
        # is momentarily tight -- three separate closures were lost to a failed
        # 1.75 MiB allocation while other work held the RAM. On MemoryError,
        # halve the block and retry; the enumeration is IDENTICAL either way
        # (chunking is a scheduling detail, never a coverage one), so a smaller
        # block changes speed and nothing else. Only give up when even a single
        # combination cannot be processed.
        while True:
            try:
                C = xp.asarray(np.asarray(block, dtype=np.int64) * 3)
                acc = optsf[C[:, 0][:, None] + tcol[0]]        # (B, 3^p, NW)
                for t in range(1, p):
                    acc = acc ^ optsf[C[:, t][:, None] + tcol[t]]
                break
            except MemoryError as exc:      # D7: _ArrayMemoryError IS a subclass;
                # naming it via np.core._exceptions (deprecated on numpy 2.x)
                # would raise AttributeError while evaluating the except clause
                # and DEFEAT the backoff. MemoryError alone catches both.
                if len(block) <= 1:
                    raise
                keep = len(block) // 2
                deferred = block[keep:]
                block = block[:keep]
                # push the deferred half back onto the iterator so COVERAGE is
                # preserved exactly -- dropping it would silently break the
                # exhaustiveness the whole theorem rests on
                it = _chain(iter(deferred), it)
        seen += acc.shape[0] * T

        w = qweight_sym(acc, nwh, xp)                          # (B, 3^p)
        if best_w is not None:
            hit = w <= best_w                # <=, so A_d ties at the incumbent
        else:
            # D6 (red team): `w == w.min()` kept ONLY the block minimum, so if
            # every block-minimum candidate is a stabilizer they are all
            # filtered below and best_w stays None -- permanently discarding
            # lighter logicals in this block whenever the search starts with no
            # upper bound (every test path). Consider the whole light tail so a
            # non-stabilizer behind a stabilizer front cannot be lost.
            cut = int(w.min()) + 2
            hit = w <= cut
        if bool(hit.any()):
            idx = xp.nonzero(hit)
            cand = acc[idx]
            cw = w[idx]
            # stabilizer rejection applies to the INCUMBENT only -- coverage of
            # the enumeration is what the theorem needs and is never filtered.
            if masks.shape[0]:
                par = xp.zeros((cand.shape[0],), dtype=xp.int64)
                for j in range(masks.shape[0]):
                    par |= popcount(cand & masks[j][None, :], xp) & 1
                keep = par.astype(bool)
                cand, cw = cand[keep], cw[keep]
            if cand.shape[0]:
                i = int(xp.argmin(cw))
                wv = int(cw[i])
                if best_w is None or wv < best_w:
                    best_w = wv
                    best_v = xp.asnumpy(cand[i]) if hasattr(xp, "asnumpy") else np.array(cand[i])
                    seen_min.clear()          # a better weight invalidates the tally
                # tally EVERY distinct operator achieving the current best --
                # dedup by bytes, since the same operator arrives from many
                # different qubit-subset/Pauli combinations
                if best_w is not None:
                    at = cw == best_w
                    if bool(at.any()):
                        rows_at = cand[at]
                        host = (xp.asnumpy(rows_at) if hasattr(xp, "asnumpy")
                                else np.asarray(rows_at))
                        for rr in host:
                            if len(seen_min) < 200000:
                                seen_min.add(rr.tobytes())
        if time.time() > deadline:
            return best_w, best_v, seen, False, len(seen_min)


def certify_distance(code: PBBCode, *, upper_bound: int | None = None,
                     max_p: int = 8, max_sets: int = 4, time_budget: float = 600.0,
                     seed: int = 0, gpu: bool = False, chunk: int | None = None,
                     max_candidates: float = 2e11, restarts: int = 24,
                     witness: np.ndarray | None = None,
                     min_depth: int = 0,
                     verbose: bool = False) -> ZCertificate:
    r"""Prove a lower bound on the minimum qubit weight of N(S) \ S.

    Escalates the enumeration depth p, and at each completed depth reports the
    Zimmermann bound SUM_i max(0, p+1-d_i) over disjoint qubit sets whose
    deficiencies d_i were measured from the actual reductions. Stops when the
    bound meets the best known upper bound -- at which point d is EXACT.
    """
    xp = np
    backend = "numpy"
    if gpu:
        xp_gpu = import_cupy()
        if xp_gpu is not None:
            xp, backend = xp_gpu, "cupy"
    if chunk is None:
        # measured on an RTX 5080 at n=108 depth 5: 160M/s at 8k, 355M/s at 32k,
        # 50M/s at 128k -- the last one thrashes, so the optimum is not "bigger".
        chunk = 32768 if backend == "cupy" else 512

    t0 = time.time()
    deadline = t0 + time_budget
    n = code.n
    nwh, _nw = sym_layout(n)
    cw, cb = _col_tables(n)

    Nb = gf2_nullspace(np.hstack([code.Hz, code.Hx]).astype(np.uint8))
    if Nb.shape[0] == 0:
        return ZCertificate(0, upper_bound, False, 0, 0, 0.0, note="empty normalizer")
    Np = pack_sym(Nb, n)
    masks_np = _logical_masks(code)

    # ---- plan disjoint qubit sets: each new set claims the qubits no earlier
    #      set has taken, and its deficiency is whatever leaks outside.
    #
    # THE PIVOT-QUBIT COUNT IS THE LEVER. A set spanning Kq pivot qubits leaves
    # n - Kq for the next one, whose deficiency is therefore about 2*Kq - n. Kq
    # is at least ceil(K/2) and exceeds it by one for every qubit that ends up
    # owning a single pivot column instead of a pair -- and each such qubit costs
    # TWO off the next set's contribution. Greedy elimination takes whatever
    # pivots it meets, so restart it and keep the tightest pairing found. The
    # enumeration is exponential in Kq as well, so this is a win twice over.
    rng = np.random.default_rng(seed)
    plans = []
    taken: set[int] = set()
    for i in range(max_sets):
        avail = [q for q in range(n) if q not in taken]
        if not avail:
            break
        rest = [q for q in range(n) if q in taken]
        best_plan = None
        for t in range(max(1, restarts)):
            if t % 2 == 0:                                  # pair-greedy proposal
                paired = _pair_greedy_qubits(Nb, n, rng, avail)
                tail = [q for q in avail if q not in set(paired)]
                head = _interleaved(paired, n) + _interleaved(rng.permutation(tail), n)
            else:                                           # plain random order
                head = _interleaved(rng.permutation(avail), n)
            order = head + _interleaved(rng.permutation(rest) if rest else [], n)
            R, piv = rref_sym(Np, order, cw, cb)
            if R.shape[0] == 0:
                continue
            qids = sorted({c if c < n else c - n for c in piv})
            assigned = [q for q in qids if q not in taken]
            key = (len(qids) - len(assigned), len(qids))    # deficiency, then size
            if best_plan is None or key < best_plan[0]:
                best_plan = (key, R, piv, qids, assigned)
        if best_plan is None:
            break
        (deficiency, _kq), R, piv, qids, assigned = best_plan
        opts, _ = _groups_from_pivots(R, piv, n)
        plans.append((opts, SetInfo(i, len(qids), len(assigned), int(deficiency),
                                    pivot_list=[int(q) for q in qids])))
        taken.update(assigned)
        if len(taken) >= n:
            break

    if not plans:
        return ZCertificate(0, upper_bound, False, 0, 0, time.time() - t0,
                            note="no information set could be built")

    opts_dev = [xp.asarray(o) for o, _ in plans]
    masks = xp.asarray(masks_np)
    best_w, best_v = upper_bound, None
    total = 0

    swept = [0] * len(plans)                # deepest level completed, per set
    a_d_acc: set = set()                    # distinct minimum-weight logicals, A_d

    for p in range(1, max_p + 1):
        # A set whose deficiency is at least p+1 contributes max(0, p+1-d_i) = 0
        # at this depth, so enumerating it buys nothing -- at n=108 k=6 the
        # second set has deficiency 9 while the proof needs p=7, and half the
        # work was being spent for zero bound.
        #
        # CATCH-UP IS MANDATORY, NOT AN OPTIMIZATION DETAIL. The premise is
        # "every v with |M_i(v)| <= p was enumerated in set i". A set skipped at
        # depths 1..4 and swept only at 5 has not covered 1..4, so it may not
        # contribute at ANY depth until those levels are filled in. Shallow
        # levels are a rounding error against the deepest one, so this costs
        # almost nothing -- but omitting it would silently invalidate the bound.
        active = [i for i, (_o, s) in enumerate(plans) if p + 1 - s.deficiency > 0]
        if not active:
            active = [0]
        todo = [(i, q) for i in active for q in range(swept[i] + 1, p + 1)]
        projected = sum(comb(opts_dev[i].shape[0], q) * 3 ** q for i, q in todo)
        if projected > max_candidates:
            return ZCertificate(_bound(plans, p - 1, swept), best_w, False, p - 1,
                                total, time.time() - t0, [s for _, s in plans],
                                _wit(best_v, n), f"depth {p} needs {projected:.3g} "
                                f"candidates (> cap {max_candidates:.3g})", backend)
        mult_at_depth = 0
        for i, q in todo:
            best_w, v, seen, done, mult = _sweep_depth(opts_dev[i], masks, nwh, q,
                                                       best_w, deadline, xp, chunk,
                                                       acc=a_d_acc)
            total += seen
            mult_at_depth = len(a_d_acc)
            if v is not None:
                best_v = v
            if not done:
                return ZCertificate(_bound(plans, p - 1, swept), best_w, False,
                                    p - 1, total, time.time() - t0,
                                    [s for _, s in plans], _wit(best_v, n),
                                    "time budget exhausted mid-depth; the bound "
                                    "reported is for the LAST COMPLETE depth", backend)
            swept[i] = q
            plans[i][1].levels_swept += 1
        lb = _bound(plans, p, swept)
        if verbose:
            print(f"  p={p}: LB={lb} UB={best_w} candidates={total:,} "
                  f"{time.time() - t0:.1f}s")
        if best_w is not None and lb >= best_w:
            wit = _wit(best_v, n)
            # The sweep only records candidates STRICTLY lighter than the
            # incumbent, so when the upper bound came from outside and is
            # already tight, nothing is captured and the proof arrives with
            # nothing demonstrating its upper end. A lower bound with no
            # operator achieving it is not a proof a stranger can check, so
            # take the caller's witness, or go find one, before certifying.
            if wit is None and witness is not None:
                cand = np.asarray(witness, dtype=np.uint8).reshape(-1)
                if symplectic_weight(cand, n) <= best_w:
                    wit, best_w = cand, int(symplectic_weight(cand, n))
            if wit is None:
                from .isd import min_logical_weight
                found = min_logical_weight(code, trials=600, p=2, seed=seed + 1,
                                           time_budget=max(15.0, time_budget * 0.1))
                if found.witness is not None and 0 < found.best_weight <= best_w:
                    wit, best_w = found.witness, int(found.best_weight)
            if wit is None:
                return ZCertificate(int(lb), int(best_w), False, p, total,
                                    time.time() - t0, [s for _, s in plans], None,
                                    "lower bound proven but no witness obtained -- "
                                    "refusing to certify an upper bound we cannot "
                                    "demonstrate", backend)
            # A_d NEEDS MORE DEPTH THAN d DOES. The bound is met as soon as
            # sum_i max(0, p+1-d_i) reaches best_w -- two sets reach 6 at p=3 --
            # but a weight-w operator is only GUARANTEED enumerated once p >= w.
            # Stopping at the bound therefore yields a multiplicity that counts
            # just the operators whose support fell thinly across the pivots.
            # `min_depth` keeps sweeping when the spectrum, not the distance, is
            # the question.
            if p < min_depth:
                continue
            _spec = SpectrumCompleteness(completed_depth=p, accumulator_cap=200000,
                                         observed_count=mult_at_depth)
            contributing = sum(1 for _o, si in plans if si.contribution > 0)
            return ZCertificate(int(best_w), int(best_w), True, p, total,
                                time.time() - t0, [s for _, s in plans], wit,
                                f"exhaustive to depth {p}; {contributing} of "
                                f"{len(plans)} qubit sets CONTRIBUTED to the bound",
                                backend,
                                multiplicity_at_best=mult_at_depth,
                                # COMPLETE ONLY WHEN IT IS. This flag was set
                                # unconditionally on the exact-certificate path,
                                # which overclaims in the one direction that
                                # matters: `9_6_0172` proves d=10 from depth 6,
                                # and a depth-6 sweep cannot have seen every
                                # weight-10 operator.
                                #
                                # A weight-w operator has at most w nonzero
                                # qubits, hence at most w inside any pivot set,
                                # so depth p >= w enumerates ALL of them from
                                # every set -- and p < w enumerates only those
                                # whose support happens to fall thinly across
                                # the pivots. The 200k accumulator cap is the
                                # other way the tally can be short of the truth.
                                multiplicity_is_complete=_spec.complete_for_weight(
                                    int(best_w)),
                                spectrum=_spec,
                                min_weight_packed=list(a_d_acc))

    return ZCertificate(_bound(plans, max_p, swept), best_w, False, max_p, total,
                        time.time() - t0, [s for _, s in plans], _wit(best_v, n),
                        "max_p reached", backend)


def _bound(plans, p: int, swept=None) -> int:
    """Zimmermann bound at depth p: SUM_i max(0, p+1-d_i) over disjoint sets.

    A set counts only if it was actually enumerated to depth p. `swept` records
    how deep each set got; without that check a set could contribute a bound it
    never earned."""
    if p < 1:
        return 0
    tot = 0
    for i, (_o, info) in enumerate(plans):
        earned = swept is None or swept[i] >= p
        info.contribution = max(0, p + 1 - info.deficiency) if earned else 0
        tot += info.contribution
    return int(tot)


def _wit(v, n: int):
    return None if v is None else unpack_sym(np.asarray(v, dtype=np.uint64)[None, :], n)[0]


def verify_certificate(code: PBBCode, cert: ZCertificate) -> dict:
    """Re-check a certificate's checkable parts without redoing the enumeration.

    The lower bound's validity rests on the enumeration having been exhaustive,
    which only re-running proves. What IS checkable in a few lines: the witness
    is a genuine logical operator of the claimed weight, and the arithmetic of
    the bound matches the recorded deficiencies. Anyone can run this.
    """
    out = {"bound_arithmetic": None, "witness_is_logical": None,
           "witness_weight_matches": None, "valid": False}
    expect = sum(max(0, cert.depth_p + 1 - s.deficiency) for s in cert.sets)
    out["bound_arithmetic"] = bool(expect >= cert.lower_bound)
    if cert.witness is None:
        out["valid"] = False
        return out
    n = code.n
    w = np.asarray(cert.witness, dtype=np.uint8)
    out["witness_weight_matches"] = bool(symplectic_weight(w, n) == cert.upper_bound)
    commutes = not ((code.Hx @ w[n:] + code.Hz @ w[:n]) % 2).any()
    from .gbb import gf2_rank
    H = code.symplectic.astype(np.uint8)
    in_stab = gf2_rank(np.vstack([H, w])) == gf2_rank(H)
    out["witness_is_logical"] = bool(commutes and not in_stab)
    out["valid"] = bool(out["bound_arithmetic"] and out["witness_is_logical"]
                        and out["witness_weight_matches"])
    return out
