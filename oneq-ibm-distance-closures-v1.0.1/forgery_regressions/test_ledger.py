"""The addressable lower bound: the index must name the candidate the sweep saw.

If unranking is off by anything at all, every check runs against a different
space than the one the certificate is about -- and passes, cheerfully, forever.
So the first tests pin the addressing against `itertools.combinations` and the
engine's own choice table rather than against a description of them.

The rest are the controls. A challenge tool that cannot refute is decoration,
and this one shipped with the refutation logic INVERTED: it flagged a violation
when a candidate WAS a stabilizer instead of when it was not, and reported 252
violations against a sound closure. Every one of them was a weight-6 stabilizer,
confirmed 4/4 against the definitive rank test. These codes carry stabilizers
lighter than their distance, so that distinction is not a detail.
"""

from __future__ import annotations

import copy
import itertools
import pathlib
import sys

import numpy as np
import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from oneq.bz import _choice_table                                  # noqa: E402
from oneq.gbb import build_pbb, gf2_rank                           # noqa: E402
from oneq.ledger import (candidate_at, check_indices,              # noqa: E402
                         coverage_matches, locate, rebuild_options,
                         set_space, shard_bounds, total_candidates,
                         unrank_assignment, unrank_combination,
                         verify_levels)


@pytest.mark.parametrize("n,k", [(8, 3), (12, 4), (20, 2), (15, 5), (9, 1)])
def test_combination_unranking_matches_itertools_exactly(n, k):
    ref = list(itertools.combinations(range(n), k))
    assert [tuple(unrank_combination(r, n, k)) for r in range(len(ref))] == ref


@pytest.mark.parametrize("p", [1, 2, 3, 4])
def test_assignment_unranking_matches_the_engines_choice_table(p):
    tbl = _choice_table(p)
    assert all(tuple(unrank_assignment(r, p)) == tuple(tbl[r])
               for r in range(3 ** p))


def test_locate_is_a_bijection_onto_the_level_structure():
    sets = [{"pivot_qubits": 6, "levels_swept": 2},
            {"pivot_qubits": 5, "levels_swept": 3}]
    total = total_candidates(sets)
    seen = {locate(sets, i) for i in range(total)}
    assert len(seen) == total, "locate() collides -- two indices, one candidate"
    with pytest.raises(IndexError):
        locate(sets, total)
    with pytest.raises(IndexError):
        locate(sets, -1)


def test_set_space_is_the_combinatorial_total():
    from math import comb
    assert set_space(10, 3) == sum(comb(10, q) * 3 ** q for q in (1, 2, 3))
    assert set_space(10, 0) == 0


def test_shards_tile_the_space_exactly():
    for total, n in ((1000, 7), (49, 49), (10, 3), (0, 4)):
        b = shard_bounds(total, n)
        assert b[0][0] == 0 and b[-1][1] == total
        assert all(b[i][1] == b[i + 1][0] for i in range(len(b) - 1))
        assert sum(hi - lo for lo, hi in b) == total


# ------------------------------------------------------- against real closures

def _closures():
    try:
        from verify_closures import _catalogue, _records
        cat = _catalogue()
    except Exception:                                    # pragma: no cover
        pytest.skip("IBM catalogue not present")
    recs = [r for r in _records() if r.get("status") in ("CLOSED", "IMPROVED")]
    if not recs:                                         # pragma: no cover
        pytest.skip("no promoted closures present")
    return recs, cat


def test_coverage_identity_reproduces_every_promoted_certificate():
    """4,945,164,656,133 from three integers per set."""
    recs, _ = _closures()
    for rec in recs:
        for cert in rec["certificates"]:
            agrees, derived, recorded = coverage_matches(cert)
            assert agrees, (f"{rec['code_id']}: derived {derived:,} != "
                            f"recorded {recorded:,}")


def test_the_coverage_identity_is_sensitive_not_a_tautology():
    """It must DISAGREE when the bookkeeping is perturbed.

    Uses each set's own `levels_swept`; substituting the global depth gives
    10,382,234,627,268 instead of 4,945,164,656,133 for the same code, which is
    exactly how the one-set-not-two case shows up.
    """
    recs, _ = _closures()
    rec = recs[0]
    cert = copy.deepcopy(rec["certificates"][0])
    assert coverage_matches(cert)[0]
    cert["candidates"] += 1
    assert not coverage_matches(cert)[0], "an altered total went unnoticed"
    cert = copy.deepcopy(rec["certificates"][0])
    cert["sets"][-1]["levels_swept"] = 0
    assert not coverage_matches(cert)[0], "a set marked unswept went unnoticed"


@pytest.fixture(scope="module")
def small_closure():
    recs, cat = _closures()
    recs = sorted(recs, key=lambda r: r["n"])
    rec = recs[0]
    r = cat[rec["code_id"]]
    code = build_pbb(r["ell"], r["m"], r["A_terms"], r["B_terms"],
                     r.get("C_terms"), r.get("D_terms"),
                     code_id=rec["code_id"], expect_k=r["k"])
    return code, rec["certificates"][0]


def test_stabilizers_lighter_than_d_are_not_reported_as_violations(small_closure):
    """THE REGRESSION. These codes carry stabilizers below their distance.

    The first build inverted this and reported 252 violations against a sound
    closure. A stabilizer weighing less than d is expected, not a refutation:
    the theorem needs total coverage of the enumeration, and rejection applies
    only to the incumbent.
    """
    code, cert = small_closure
    res = verify_levels(code, cert, budget_per_level=20000,
                        samples_per_big_level=4000, seed=3)
    assert res["violations"] == [], (
        f"sound closure reported {len(res['violations'])} violations")
    # and the code really does contain such stabilizers, or this proves nothing
    n = code.n
    S = np.vstack([np.hstack([code.Hx, np.zeros_like(code.Hx)]),
                   np.hstack([np.zeros_like(code.Hz), code.Hz])]).astype(np.uint8)
    from oneq.gbb import symplectic_weight
    lightest = min(int(symplectic_weight(x, n)) for x in S if x.any())
    assert lightest < cert["lower_bound"], (
        f"lightest stabilizer {lightest} is not below d={cert['lower_bound']}: "
        "this code cannot exercise the distinction")


def test_the_challenge_refutes_an_inflated_claim(small_closure):
    """The control. A test that never fails is not a test."""
    code, cert = small_closure
    bad = copy.deepcopy(cert)
    bad["lower_bound"] = cert["lower_bound"] + 8
    res = verify_levels(code, bad, budget_per_level=20000,
                        samples_per_big_level=4000, seed=3)
    assert res["violations"], (
        f"claiming d>={bad['lower_bound']} against true "
        f"{cert['lower_bound']} was NOT refuted")


def test_an_independent_rebuild_finds_the_certified_minimum(small_closure):
    """The strongest available signal short of re-execution.

    The information set is rebuilt from the recorded pivot QUBITS -- no seed, no
    RNG, no copy of the planner. If that rebuild addressed a different space,
    recovering exactly the certified distance would be a coincidence.
    """
    code, cert = small_closure
    res = verify_levels(code, cert, budget_per_level=800000,
                        samples_per_big_level=20000, seed=5)
    lights = [x["lightest_non_stabilizer"] for x in res["levels"]
              if x["lightest_non_stabilizer"] is not None]
    assert lights and min(lights) == cert["lower_bound"], (
        f"independent rebuild found lightest logical {min(lights) if lights else None}, "
        f"certificate claims {cert['lower_bound']}")


def test_an_unaddressable_schema_1_certificate_is_refused(small_closure):
    code, cert = small_closure
    old = copy.deepcopy(cert)
    for s in old["sets"]:
        s.pop("pivot_list", None)
    with pytest.raises(ValueError, match="pivot_list"):
        check_indices(code, old, [0, 1, 2])


def test_rebuilt_options_are_deterministic(small_closure):
    """Given the pivot qubits the reduced form is unique, so two rebuilds must
    agree bit for bit -- otherwise the index names different candidates on
    different machines."""
    code, cert = small_closure
    pl = cert["sets"][0]["pivot_list"]
    a, _ = rebuild_options(code, pl)
    b, _ = rebuild_options(code, pl)
    assert np.array_equal(a, b)
    assert np.array_equal(candidate_at(a, 2, 17, 4), candidate_at(b, 2, 17, 4))


# ------------------------------------ the bound a verifier EARNS, independently

def test_deficiencies_recompute_from_pivot_lists_alone(small_closure):
    """The one quantity a verifier should least want to be told.

    The whole bound is SUM_i max(0, p+1-d_i), so reading d_i back from the
    artifact trusts exactly the number worth checking. Sets claim qubits in
    order, so d_i is recoverable from the pivot lists.
    """
    _code, cert = small_closure
    from oneq.ledger import recompute_deficiencies
    assert recompute_deficiencies(cert["sets"]) == [s["deficiency"] for s in cert["sets"]]


def test_deficiency_recomputation_is_sensitive_to_the_pivot_lists():
    """It must be derived from the qubits, not echoed from anywhere."""
    from oneq.ledger import recompute_deficiencies
    disjoint = [{"pivot_list": [0, 1, 2]}, {"pivot_list": [3, 4, 5]}]
    assert recompute_deficiencies(disjoint) == [0, 0]
    overlapping = [{"pivot_list": [0, 1, 2]}, {"pivot_list": [2, 3, 4]}]
    assert recompute_deficiencies(overlapping) == [0, 1]
    nested = [{"pivot_list": [0, 1, 2]}, {"pivot_list": [0, 1, 2]}]
    assert recompute_deficiencies(nested) == [0, 3]
    with pytest.raises(ValueError):
        recompute_deficiencies([{"pivot_qubits": 3}])


def test_the_earned_bound_ladder_matches_zimmermann():
    from oneq.ledger import certified_bound_at_depth
    assert [certified_bound_at_depth([0, 4], L) for L in range(1, 8)] == \
        [2, 3, 4, 6, 8, 10, 12]
    assert [certified_bound_at_depth([0, 8], L) for L in range(1, 8)] == \
        [2, 3, 4, 5, 6, 7, 8]
    assert certified_bound_at_depth([0, 4], 0) == 1


def test_vectorized_sweep_agrees_with_the_per_candidate_path(small_closure):
    """Two implementations of the same level must give the same verdict.

    The batched path exists so a stranger's exhaustive frontier reaches depth 5
    instead of depth 3; if it disagreed with the addressable path it would be
    checking a different space fast.
    """
    from math import comb as _comb
    from oneq.bz import _logical_masks, sym_layout
    from oneq.ledger import sweep_level
    code, cert = small_closure
    nwh, _ = sym_layout(code.n)
    masks = _logical_masks(code)
    opts, _ = rebuild_options(code, cert["sets"][0]["pivot_list"])
    d = cert["lower_bound"]
    for depth in (1, 2):
        ck, light, vio = sweep_level(opts, masks, nwh, depth, d)
        assert ck == _comb(opts.shape[0], depth) * 3 ** depth
        assert vio == []
        # the same level, one candidate at a time
        best = None
        from oneq.bz import popcount
        for cr in range(_comb(opts.shape[0], depth)):
            for ar in range(3 ** depth):
                v = candidate_at(opts, depth, cr, ar)
                w = int(popcount(v[:nwh] | v[nwh:], np))
                if w and any(int(popcount(v & m, np)) & 1 for m in masks):
                    best = w if best is None else min(best, w)
        assert light == best, f"batched says {light}, per-candidate says {best}"


def test_sweep_level_respects_a_shard_range(small_closure):
    """Sharding is by combination rank, and the shards must tile the level."""
    from math import comb as _comb
    from oneq.bz import _logical_masks, sym_layout
    from oneq.ledger import sweep_level
    code, cert = small_closure
    nwh, _ = sym_layout(code.n)
    masks = _logical_masks(code)
    opts, _ = rebuild_options(code, cert["sets"][0]["pivot_list"])
    total = _comb(opts.shape[0], 2)
    whole, _l, _v = sweep_level(opts, masks, nwh, 2, cert["lower_bound"])
    parts = sum(sweep_level(opts, masks, nwh, 2, cert["lower_bound"],
                            comb_lo=lo, comb_hi=hi)[0]
                for lo, hi in shard_bounds(total, 7))
    assert parts == whole


# ------------------------------------------------- symmetry orbits (the atlas)

def test_translation_permutations_form_a_group_action():
    """Orbits are only meaningful if the action is one.

    Each translation must be a bijection on qubits, must never mix the two
    blocks, and composing (a,b) with (c,d) must equal (a+c, b+d).
    """
    sys.path.insert(0, str(ROOT / "experiments" / "gate0b_ibm825"))
    from exposure_atlas import translation_perm
    ell, m = 6, 3
    half = ell * m
    for a in range(ell):
        for b in range(m):
            p = translation_perm(ell, m, a, b)
            assert sorted(p.tolist()) == list(range(2 * half)), "not a bijection"
            assert (p[:half] < half).all() and (p[half:] >= half).all(), \
                "a translation mixed the two qubit blocks"
    idp = translation_perm(ell, m, 0, 0)
    assert (idp == np.arange(2 * half)).all()
    a1 = translation_perm(ell, m, 2, 1)
    a2 = translation_perm(ell, m, 3, 1)
    assert (a2[a1] == translation_perm(ell, m, 5, 2)).all(), "action is not a homomorphism"


def test_orbit_sizes_must_divide_the_group_order_and_tile_the_set():
    """Orbit-stabilizer, as an arithmetic check on the decomposition.

    Measured on the d=6 cohort every code gives [18,18,18,18,18,6] or
    [18,...,6,6,6] -- sizes 18 = |G| (free) and 6 = |G|/3 (stabilizer of order
    3). Anything not dividing |G| would mean the decomposition is not orbits.
    """
    sys.path.insert(0, str(ROOT / "experiments" / "gate0b_ibm825"))
    import json as _json
    art = ROOT / "experiments" / "gate0b_ibm825" / "exposure_atlas.json"
    if not art.exists():
        pytest.skip("atlas not yet computed")
    for r in _json.loads(art.read_text())["codes"]:
        if r.get("skipped"):
            continue
        g = r["group_order"]
        assert sum(r["orbit_sizes"]) == r["A_d_raw"], (
            f"{r['code_id']}: orbits do not tile the minimum-weight set")
        for s in r["orbit_sizes"]:
            assert g % s == 0, (
                f"{r['code_id']}: orbit of size {s} does not divide |G|={g}")


def test_an_unenumerated_set_earns_nothing():
    """SOUNDNESS. A set this run never enumerated has established nothing.

    The uniform-depth form sums over every set. On the six promoted closures
    that was harmless -- the unswept sets carry deficiencies 8 and 9 and
    contribute 0 at the depths reached -- so no published number was wrong. The
    logic was still wrong, and this is the case that shows it doubling a claim.
    """
    from oneq.ledger import certified_bound_at_depth, certified_bound_per_set
    defs = [0, 0]
    assert certified_bound_at_depth(defs, 4) == 10, "uniform form sums both sets"
    assert certified_bound_per_set(defs, {0: 4}) == 5, \
        "a set that was never enumerated must contribute nothing"
    assert certified_bound_per_set(defs, {}) == 0
    assert certified_bound_per_set(defs, {0: 4, 1: 4}) == 10


def test_per_set_depths_are_honoured_and_are_stronger_than_the_minimum():
    """Zimmermann needs |M_i(v)| >= p_i + 1 in each set SEPARATELY, so a set
    swept deeper may claim its full share even while a sibling stopped short."""
    from oneq.ledger import certified_bound_at_depth, certified_bound_per_set
    defs = [0, 0]
    assert certified_bound_per_set(defs, {0: 5, 1: 3}) == 6 + 4
    assert certified_bound_at_depth(defs, 3) == 4 + 4, "common-depth is weaker"
    assert certified_bound_per_set(defs, {0: 5, 1: 3}) > certified_bound_at_depth(defs, 3)


def test_the_published_earned_bounds_are_unchanged_by_the_fix(small_closure):
    """The fix must not silently move a number that was already correct."""
    from oneq.ledger import verify_levels
    code, cert = small_closure
    res = verify_levels(code, cert, budget_per_level=800000,
                        samples_per_big_level=8000, seed=11)
    assert res["independently_earned_bound"] == 4, (
        f"9_6_0172 at exhaustive depth 3 earns 4; got "
        f"{res['independently_earned_bound']}")
    assert res["deficiencies_agree"]
    assert res["violations"] == []
