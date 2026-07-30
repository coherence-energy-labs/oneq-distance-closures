r"""The lower bound, made addressable: coverage as arithmetic, execution as a
function of an index.

THE GAP THIS ATTACKS. A distance claim has two halves with wildly different
checkability. The upper bound ships a witness anyone verifies in milliseconds.
The lower bound -- "nothing lighter exists" -- has been checkable only by
re-running the search: 8.1 hours and 4.9 trillion candidates for `12_6_0201`.
That is the single largest credibility gap in the program, and every honest
statement about it has so far been an apology rather than a fix.

WHAT WAS TRIED AND WHY IT IS DEAD. A succinct algebraic certificate (Delsarte /
LP duality, MacWilliams) would be the ideal object: a few numbers a reader
checks by hand. It cannot work here, for a reason that is measured rather than
suspected. Any such bound bounds the minimum weight of N(S) AS A LINEAR CODE,
and N(S) contains the stabilizers -- `phase2_45` has a weight-5 stabilizer
against distance 6. No bound on the linear code can exceed the lightest
stabilizer, which sits BELOW the distance. Applying the LP per logical coset
instead needs the weight distribution of S, which is 2^106 for n=108. That lane
is closed with a stated reason; it is not undertuned.

WHAT WORKS INSTEAD. Split the claim in two and make each half checkable on its
own terms.

  COVERAGE becomes an arithmetic identity. The sweep enumerates, for each
  information set i and each depth q it completed, every q-subset of that set's
  Kq pivot qubits against all 3^q Pauli assignments:

      candidates  =  SUM_i  SUM_{q=1..swept_i}  C(Kq_i, q) * 3^q

  Three small integers per set reproduce 4,945,164,656,133 exactly. Verified
  against all ten promoted certificates, and it is SENSITIVE: using the global
  depth instead of each set's own `levels_swept` gives 10,382,234,627,268 for
  the same code -- it catches the one-set-not-two case the red team found.

  EXECUTION becomes a pure function. Nothing about candidate number i depends on
  candidates 0..i-1: unrank i into (set, depth, combination, assignment), XOR
  the corresponding option rows, done in microseconds. So a reader may check ANY
  index, including one they choose adversarially, without re-running anything.

WHAT THIS DOES NOT DO, stated as plainly as the rest. Sampling R indices out of
N does not prove absence over N -- a single mis-evaluated candidate hides with
probability 1 - R/N, and no amount of random sampling fixes that. What changes
is the SHAPE of the remaining work. Re-execution used to be one indivisible
8-hour monolith that only its author could run. It is now a partition into
independently checkable ranges, so:

  * coverage cannot be overstated -- the total is derived, not reported;
  * a specific doubt is answerable in microseconds instead of hours;
  * re-execution is shardable, resumable, and composable across strangers, and
    "31% of the space independently re-verified by a third party" becomes a
    well-defined statement rather than a figure of speech.

That is the honest ceiling for an absence claim over a space this size, and it
is a long way above "trust the log".
"""

from __future__ import annotations

import itertools
from math import comb

import numpy as np

from .bz import (_choice_table, _col_tables, _groups_from_pivots, _interleaved,
                 gf2_nullspace, pack_sym, qweight_sym, rref_sym, sym_layout)


# ------------------------------------------------------------------- coverage

def set_space(pivot_qubits: int, levels_swept: int) -> int:
    """Candidates a single information set contributes: SUM_q C(Kq,q)*3^q."""
    return sum(comb(pivot_qubits, q) * 3 ** q
               for q in range(1, int(levels_swept) + 1))


def total_candidates(sets: list[dict]) -> int:
    """The certificate's whole candidate count, from three integers per set.

    Uses each set's OWN `levels_swept`. A set that never ran contributes zero,
    which is what makes this identity able to detect the difference between a
    two-set Zimmermann sweep and a one-set Brouwer sweep wearing its clothes.
    """
    return sum(set_space(s["pivot_qubits"], s.get("levels_swept", 0)) for s in sets)


def coverage_matches(cert: dict) -> tuple[bool, int, int]:
    """(agrees, derived, recorded) for a certificate's candidate accounting."""
    derived = total_candidates(cert.get("sets", []))
    recorded = int(cert.get("candidates", -1))
    return derived == recorded, derived, recorded


# ------------------------------------------------------------------ unranking

def unrank_combination(rank: int, n: int, k: int) -> list[int]:
    """The `rank`-th k-subset of range(n) in LEXICOGRAPHIC order.

    Must match `itertools.combinations`, which the sweep iterates -- the
    combinatorial number system read forwards. A mismatch here would silently
    address a different candidate than the one the engine evaluated, so
    `tools/challenge_lower_bound.py` cross-checks it against `combinations`
    directly rather than trusting this docstring.
    """
    if not 0 <= rank < comb(n, k):
        raise IndexError(f"combination rank {rank} out of range for C({n},{k})")
    out: list[int] = []
    x = 0
    for i in range(k):
        remaining = k - i - 1
        while True:
            c = comb(n - x - 1, remaining)
            if rank < c:
                break
            rank -= c
            x += 1
        out.append(x)
        x += 1
    return out


def unrank_assignment(rank: int, p: int) -> list[int]:
    """The `rank`-th row of `_choice_table(p)`.

    `np.indices((3,)*p).reshape(p,-1).T` varies the LAST axis fastest, so this
    is plain base-3 with the most significant digit first.
    """
    digits = [0] * p
    for i in range(p - 1, -1, -1):
        digits[i] = rank % 3
        rank //= 3
    return digits


# --------------------------------------------------------- plan reconstruction

def rebuild_options(code, pivot_list: list[int]) -> tuple[np.ndarray, list[int]]:
    """Rebuild one information set's option table from its PIVOT QUBITS alone.

    THE POINT: no seed, no RNG, no greedy restarts, no heuristic. The
    certificate records which qubits were pivots; ordering those qubits' columns
    first and row-reducing reproduces the systematic basis deterministically.
    A verifier therefore never replays the searcher's random choices, and never
    has to trust that its own copy of the planner matches the prover's.
    """
    n = code.n
    Nb = gf2_nullspace(np.hstack([code.Hz, code.Hx]).astype(np.uint8))
    Np = pack_sym(Nb, n)
    cw, cb = _col_tables(n)
    rest = [q for q in range(n) if q not in set(pivot_list)]
    order = _interleaved(list(pivot_list), n) + _interleaved(rest, n)
    R, piv = rref_sym(Np, order, cw, cb)
    opts, qids = _groups_from_pivots(R, piv, n)
    return opts, qids


def candidate_at(opts: np.ndarray, depth: int, comb_rank: int,
                 assign_rank: int) -> np.ndarray:
    """The single packed candidate at (depth, combination, assignment).

    O(depth * Kq) and independent of every other candidate -- which is the whole
    reason a stranger can audit index 3,141,592,653,589 without touching the
    3,141,592,653,588 before it.
    """
    nq = opts.shape[0]
    qs = unrank_combination(comb_rank, nq, depth)
    ch = unrank_assignment(assign_rank, depth)
    v = opts[qs[0], ch[0]].copy()
    for t in range(1, depth):
        v ^= opts[qs[t], ch[t]]
    return v


def locate(sets: list[dict], index: int) -> tuple[int, int, int, int]:
    """Global candidate index -> (set_index, depth, comb_rank, assign_rank).

    The global space is the concatenation of each set's per-depth blocks, in the
    order the sweep walks them. Raises IndexError past the end, so an
    out-of-range challenge is refused rather than silently wrapped.
    """
    if index < 0:
        raise IndexError("negative candidate index")
    off = index
    for si, s in enumerate(sets):
        kq, swept = s["pivot_qubits"], int(s.get("levels_swept", 0))
        for q in range(1, swept + 1):
            block = comb(kq, q) * 3 ** q
            if off < block:
                per = 3 ** q
                return si, q, off // per, off % per
            off -= block
    raise IndexError(f"candidate index {index} past the end of the swept space")


# ------------------------------------------------------------------- sharding

def shard_bounds(total: int, n_shards: int) -> list[tuple[int, int]]:
    """Partition [0, total) into contiguous half-open ranges.

    Exhaustive and disjoint by construction: shard j starts where shard j-1
    ends. A coordinator therefore checks coverage by comparing endpoints, not
    by trusting a set of claimed ranges to tile the space.
    """
    if n_shards <= 0:
        raise ValueError("n_shards must be positive")
    step, rem = divmod(total, n_shards)
    out, lo = [], 0
    for j in range(n_shards):
        hi = lo + step + (1 if j < rem else 0)
        out.append((lo, hi))
        lo = hi
    return out


def level_sizes(sets: list[dict]) -> list[tuple[int, int, int]]:
    """[(set_index, depth, size)] for every level the sweep completed."""
    out = []
    for si, s in enumerate(sets):
        kq, swept = s["pivot_qubits"], int(s.get("levels_swept", 0))
        for q in range(1, swept + 1):
            out.append((si, q, comb(kq, q) * 3 ** q))
    return out


def level_offset(sets: list[dict], set_index: int, depth: int) -> int:
    """Global index where a given (set, depth) level begins."""
    off = 0
    for si, q, size in level_sizes(sets):
        if si == set_index and q == depth:
            return off
        off += size
    raise KeyError(f"no level (set {set_index}, depth {depth})")


def recompute_deficiencies(sets: list[dict]) -> list[int]:
    r"""Re-derive each set's deficiency from the pivot lists ALONE.

    The certificate records a deficiency per set, and the bound is built from
    them -- so a verifier that reads those numbers back is trusting the single
    quantity most worth checking. They are recoverable instead.

    Sets claim qubits in order: set i OWNS the pivot qubits no earlier set took,
    and everything else in its pivot list leaks outside its own territory:

        I_i = Q_i \ (Q_0 u ... u Q_{i-1}),    deficiency_i = |Q_i| - |I_i|

    which is exactly the d_i in

        qubit_wt(v) >= SUM_i max(0, p + 1 - d_i).

    Agreement with the recorded values is then evidence, not bookkeeping.
    """
    taken: set[int] = set()
    out = []
    for s in sets:
        q = set(int(x) for x in s.get("pivot_list", []))
        if not q:
            raise ValueError("no pivot_list: deficiency is not recomputable")
        owned = q - taken
        out.append(len(q) - len(owned))
        taken |= owned
    return out


def certified_bound_at_depth(deficiencies: list[int], depth: int) -> int:
    """Zimmermann's bound from an EXHAUSTIVE sweep to `depth`.

    THE REASON TIERED VERIFICATION IS MORE THAN SAMPLING. Enumerating every
    candidate with at most `depth` pivots in each set is precisely the
    hypothesis of the theorem, so a verifier that completes those levels earns
    its OWN lower bound rather than merely failing to find a counterexample:

        9_6_0172, deficiencies [0, 4]
            depth 3 -> d >= 4       depth 5 -> d >= 8
            depth 4 -> d >= 6       depth 6 -> d >= 10   (the full claim)

    So "exhaustive through depth L" converts directly into a number, and the
    frontier is a statement about how much of the claim has been independently
    re-established rather than about how many samples were drawn.
    """
    return sum(max(0, depth + 1 - int(d)) for d in deficiencies)


def certified_bound_per_set(deficiencies: list[int], depths: dict) -> int:
    r"""Bound earned when each set was exhausted to its OWN depth.

    SOUNDNESS FIX. The uniform-depth form above sums over EVERY set, including
    ones this run never enumerated. On the six promoted closures that happened
    to be harmless -- the unswept sets carry deficiencies 8 and 9, which
    contribute 0 at the depths reached -- but the logic is wrong, and a
    constructed case shows it doubling a claim:

        sets swept [4, 0], deficiencies [0, 0]
            over all sets   -> d >= 10
            over swept only -> d >=  5

    A set that was not enumerated has established nothing and must contribute
    nothing. `depths` maps set index -> the depth to which THIS run exhausted
    it; absent keys contribute zero.

    Per-set depths are also STRONGER than a common minimum, and legitimately so.
    Zimmermann needs |M_i(v)| >= p_i + 1 in each set separately, so a set swept
    to depth 5 may claim its full 6 - d_i even while a sibling stopped at 3.
    That is the same per-set accounting `levels_swept` already records and the
    coverage identity already relies on.
    """
    return sum(max(0, int(depths.get(i, -1)) + 1 - int(d))
               for i, d in enumerate(deficiencies))


def sweep_level(opts, masks, nwh, depth: int, d: int, *,
                comb_lo: int = 0, comb_hi: int | None = None,
                batch: int = 4096, xp=None):
    """Exhaustively check one (set, depth) level -- vectorized, in batches.

    WHY THIS EXISTS. Checking candidates one at a time through `candidate_at`
    runs near 10^5/s, which caps a stranger's exhaustive frontier at depth 3 and
    leaves 99.9% of the space reachable only by sampling. The same arithmetic
    done batchwise runs orders of magnitude faster, which moves the frontier
    several levels deeper -- and the frontier is the entire value of the tiered
    claim.

    Independence is preserved: `opts` still comes from `rebuild_options`, which
    is derived from the certificate's recorded pivot qubits. This shares the
    mathematics with the searcher, as any second implementation of the same
    theorem must, but none of its code, plan construction, scheduling, or state.

    Returns (checked, lightest_logical, violations) over combination ranks in
    [comb_lo, comb_hi).
    """
    xp = np if xp is None else xp
    nq = opts.shape[0]
    total_combs = comb(nq, depth)
    comb_hi = total_combs if comb_hi is None else min(comb_hi, total_combs)
    if comb_lo >= comb_hi:
        return 0, None, []
    from .bz import _choice_table, popcount
    table = _choice_table(depth)                       # (3^depth, depth)
    per = table.shape[0]
    optsf = xp.asarray(opts.reshape(-1, opts.shape[-1]))   # (nq*3, NW)
    masks_d = xp.asarray(np.asarray(masks))
    tcol = [xp.asarray(np.ascontiguousarray(table[:, t]))[None, :]
            for t in range(depth)]
    lightest, violations = None, []
    checked = 0

    rank = comb_lo
    it = itertools.islice(itertools.combinations(range(nq), depth),
                          comb_lo, comb_hi)
    while True:
        block = list(itertools.islice(it, batch))
        if not block:
            break
        C = xp.asarray(np.asarray(block, dtype=np.int64) * 3)
        acc = optsf[C[:, 0][:, None] + tcol[0]]        # (B, 3^depth, NW)
        for t in range(1, depth):
            acc = acc ^ optsf[C[:, t][:, None] + tcol[t]]
        w = qweight_sym(acc, nwh, xp)                  # (B, 3^depth)
        checked += int(acc.shape[0]) * per
        # logical iff odd overlap with at least one mask; stabilizers weigh
        # less than d legitimately and must not be counted as violations
        par = xp.zeros(w.shape, dtype=xp.int64)
        for j in range(masks_d.shape[0]):
            par |= popcount(acc & masks_d[j][None, None, :], xp) & 1
        is_log = par.astype(bool) & (w > 0)
        if bool(is_log.any()):
            lw = int(w[is_log].min())
            if lightest is None or lw < lightest:
                lightest = lw
            bad = is_log & (w < d)
            if bool(bad.any()):
                bi, bj = xp.nonzero(bad)
                bi = bi.get().tolist() if hasattr(bi, "get") else bi.tolist()
                bj = bj.get().tolist() if hasattr(bj, "get") else bj.tolist()
                wh = w.get() if hasattr(w, "get") else w
                for u, v in list(zip(bi, bj))[:32]:
                    violations.append({"comb_rank": rank + int(u),
                                       "assign_rank": int(v),
                                       "weight": int(wh[u, v]), "depth": depth})
        rank += len(block)
    return checked, lightest, violations


def popcount_np(V):
    """Population count over the last axis of a uint64 array."""
    x = V.copy()
    x = x - ((x >> np.uint64(1)) & np.uint64(0x5555555555555555))
    x = (x & np.uint64(0x3333333333333333)) + ((x >> np.uint64(2)) & np.uint64(0x3333333333333333))
    x = (x + (x >> np.uint64(4))) & np.uint64(0x0F0F0F0F0F0F0F0F)
    return ((x * np.uint64(0x0101010101010101)) >> np.uint64(56)).sum(axis=-1).astype(np.int64)


def verify_levels(code, cert: dict, *, budget_per_level: int = 40_000_000,
                  samples_per_big_level: int = 200_000, seed: int = 0):
    r"""Tiered verification: enumerate the small levels ENTIRELY, sample the rest.

    WHY UNIFORM SAMPLING IS NEARLY USELESS HERE, measured rather than assumed.
    Level sizes grow like C(Kq, q)*3^q, so for `9_6_0172` depth 6 holds 99.9% of
    the 49.2 billion candidates -- and uniform sampling therefore spends
    essentially every draw at the DEEPEST level, where candidates are XORs of
    six basis rows and correspondingly heavy. 20,000 uniform draws on a
    distance-10 code never produced anything under weight 20. A test that cannot
    get near the bound cannot challenge it.

    The minimum-weight operators live at LOW depth, and the low levels are tiny:
    for Kq=56 the first four depths hold 168, 13,860, 741,960 and 29,514,240
    candidates -- about 30 million, which is exhaustible in minutes. So verify
    them ALL, and sample only the levels that are genuinely too large.

    That converts a uniform probabilistic gesture into a tiered claim with a
    hard part: "exhaustive through depth L, sampled above it". The boundary L is
    reported rather than chosen for comfort, and anyone with more compute moves
    it up without re-running anything below.
    """
    from .bz import _logical_masks, popcount
    n = code.n
    nwh, _ = sym_layout(n)
    d = int(cert["lower_bound"])
    sets = cert["sets"]
    masks = _logical_masks(code)
    rng = np.random.default_rng(seed)
    rows, violations = [], []
    exhaustive_through = {}

    for si, q, size in level_sizes(sets):
        pl = sets[si].get("pivot_list")
        if not pl:
            raise ValueError(f"set {si} has no pivot_list: not addressable")
        opts, _ = rebuild_options(code, pl)
        base = level_offset(sets, si, q)
        full = size <= budget_per_level
        if full:
            # EXHAUSTIVE LEVELS GO THROUGH THE BATCHED PATH. The per-candidate
            # loop below runs near 1e5/s, which capped the exhaustive frontier
            # at depth 3 and left the EARNED bound at d >= 4 against a claim of
            # 10. Batched, depth 4 is 23s and depth 5 is 790s. The frontier is
            # the whole point: exhausting depth L earns SUM_i max(0, L+1-d_i).
            ck, lightest, vio = sweep_level(opts, masks, nwh, q, d)
            for v in vio:
                v["index"] = base + v["comb_rank"] * (3 ** q) + v["assign_rank"]
                v["set"] = si
            violations.extend(vio)
            rows.append({"set": si, "depth": q, "level_size": size,
                         "checked": ck, "exhaustive": True,
                         "lightest_non_stabilizer": lightest})
            exhaustive_through[si] = max(exhaustive_through.get(si, 0), q)
            continue
        it = rng.integers(0, size, size=samples_per_big_level, dtype=np.int64)
        n_check = samples_per_big_level
        per = 3 ** q
        lightest = None
        for off in it:
            off = int(off)
            v = candidate_at(opts, q, off // per, off % per)
            w = int(qweight_sym(v[None, :], nwh)[0])
            if w == 0:
                continue
            # A candidate is a LOGICAL iff it has odd overlap with at least one
            # logical mask; even overlap with all of them means it is in S.
            # Stabilizers legitimately weigh less than d -- these codes carry
            # weight-6 stabilizers against distance 10 -- so they are skipped,
            # not flagged. Getting this backwards reported 252 "violations"
            # against a closure whose every one of them was a stabilizer,
            # confirmed 4/4 against the rank test.
            is_logical = any(int(popcount(v & m, np)) & 1 for m in masks)
            if not is_logical:
                continue
            if lightest is None or w < lightest:
                lightest = w
            if w < d:
                violations.append({"index": base + off, "weight": w,
                                   "set": si, "depth": q})
        rows.append({"set": si, "depth": q, "level_size": size,
                     "checked": n_check, "exhaustive": False,
                     "lightest_non_stabilizer": lightest})
        exhaustive_through.setdefault(si, q - 1)
    # THE BOUND THIS RUN EARNED. Deficiencies are RECOMPUTED from the pivot
    # lists, never read back from the certificate whose claim is under test --
    # the bound is SUM_i max(0, L+1-d_i), so d_i is the one number a verifier
    # should least want to be handed.
    my_def = recompute_deficiencies(sets)
    rec_def = [s.get("deficiency") for s in sets]
    # Only sets this run EXHAUSTED may contribute, and each contributes at its
    # own depth. `exhaustive_through` holds a per-set entry only where a level
    # was fully enumerated; a set that was merely sampled, or never swept by the
    # prover at all, is absent and therefore earns nothing.
    exhausted = {si: L for si, L in exhaustive_through.items() if L >= 1}
    L = min(exhausted.values()) if exhausted else 0
    earned = certified_bound_per_set(my_def, exhausted)
    return {"levels": rows, "violations": violations,
            "deficiencies_recomputed": my_def,
            "deficiencies_recorded": rec_def,
            "deficiencies_agree": my_def == rec_def,
            "exhaustive_depth_min_over_sets": L,
            "independently_earned_bound": earned,
            "earned_bound_reaches_claim": bool(earned >= d and not violations),
            "exhaustive_through_depth": exhaustive_through,
            "claimed_d": d}


def check_indices(code, cert: dict, indices, *, ignore_stabilizers: bool = True):
    """Evaluate specific candidates and report any that undercut the bound.

    Returns (checked, violations, lightest). A violation is a candidate whose
    qubit weight is BELOW the certified distance and which is not a stabilizer;
    stabilizers legitimately weigh less (the theorem needs total coverage of the
    enumeration, and rejection applies only to the incumbent), so counting them
    as violations would manufacture failures.
    """
    # STABILIZER TEST IN THE ENGINE'S OWN FORMAT. `isd.pack` lays 2n bits down
    # contiguously; `bz.pack_sym` word-aligns the X and Z halves SEPARATELY. For
    # n=108 both produce four uint64s -- identical size, different meaning -- so
    # handing a split-packed candidate to `isd.LogicalSyndrome.is_stabilizer`
    # type-checks, runs, and answers nonsense. Use the split-packed logical
    # masks the sweep itself uses: v is a stabilizer iff it has even overlap
    # with every one.
    from .bz import _logical_masks, popcount
    n = code.n
    nwh, _ = sym_layout(n)
    d = int(cert["lower_bound"])
    sets = cert["sets"]
    masks = _logical_masks(code)

    def _is_stabilizer(v: np.ndarray) -> bool:
        return not any(int(popcount(v & m, np)) & 1 for m in masks)

    cache: dict[int, np.ndarray] = {}
    violations, lightest = [], None
    checked = 0
    for idx in indices:
        si, q, cr, ar = locate(sets, int(idx))
        if si not in cache:
            pl = sets[si].get("pivot_list")
            if not pl:
                raise ValueError(f"set {si} has no pivot_list: schema 1 artifact, "
                                 "not addressable")
            cache[si], _ = rebuild_options(code, pl)
        v = candidate_at(cache[si], q, cr, ar)
        w = int(qweight_sym(v[None, :], nwh)[0])
        checked += 1
        if lightest is None or w < lightest:
            lightest = w
        if w < d and w > 0:
            if ignore_stabilizers and _is_stabilizer(v):
                continue
            violations.append({"index": int(idx), "weight": w,
                               "set": si, "depth": q})
    return checked, violations, lightest
