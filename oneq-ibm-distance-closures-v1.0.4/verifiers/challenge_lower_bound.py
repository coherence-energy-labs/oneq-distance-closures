"""Challenge the promoted lower bounds through a path that shares no code with
the engine that produced them.

WHAT A CHALLENGE IS. The certificate asserts that across its whole enumerated
space, no candidate is a non-stabilizer of qubit weight below the certified
distance. That space is now ADDRESSABLE: any index unranks to a candidate in
microseconds. So the assertion can be attacked directly -- pick indices, build
those exact candidates, weigh them, and look for one that undercuts the bound.

WHAT MAKES IT INDEPENDENT. Nothing here runs the sweep. The information set is
rebuilt from the certificate's recorded pivot QUBITS by row-reducing the
normalizer with those columns taken first -- the reduced form is unique given
the pivots, so no seed is replayed, no greedy restart is repeated, and no copy
of the planner has to stay in sync with the prover's. The candidate count is
re-derived from three integers per set rather than read from the artifact.

WHAT A PASS MEANS, EXACTLY. Sampling R of N indices leaves a single bad
candidate hidden with probability 1 - R/N, which for N in the trillions is
essentially 1. A pass is therefore NOT a proof of absence and is not reported as
one. What it does establish, and what no previous artifact could:

  * the coverage arithmetic is self-consistent and reproduces the recorded total
  * the recorded pivot sets rebuild into a working enumeration at all
  * the sampled region genuinely contains no counterexample
  * any FAILURE is decisive -- one violating index refutes the closure outright,
    and the index is printed so anyone can recheck it in isolation

A tool that can only confirm is not a challenge, so this reports the lightest
non-stabilizer weight it saw against the claim, and exits non-zero on violation.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

import numpy as np

_HERE = pathlib.Path(__file__).resolve().parent
# Works from the repository (tools/) AND from a frozen release, where this file
# sits in challenge/ and the verifier it imports sits in a SIBLING verifier/.
# The first standalone run of the bundle died here, which is the point of
# running it standalone.
for _p in (_HERE.parent / "src", _HERE, _HERE.parent,
           _HERE.parent / "verifier", _HERE.parent / "tools"):
    if _p.exists():
        sys.path.insert(0, str(_p))

from oneq.gbb import build_pbb                                     # noqa: E402
from oneq.ledger import (coverage_matches, total_candidates,       # noqa: E402
                         verify_levels)
from verify_closures import _catalogue, _records                   # noqa: E402


def challenge(rec: dict, cat: dict, samples: int, seed: int,
              budget: int) -> dict:
    cid = rec["code_id"]
    r = cat[cid]
    code = build_pbb(r["ell"], r["m"], r["A_terms"], r["B_terms"],
                     r.get("C_terms"), r.get("D_terms"),
                     code_id=cid, expect_k=r["k"])
    out = {"code_id": cid, "n": code.n, "k": code.k, "replicas": []}
    for i, cert in enumerate(rec["certificates"]):
        t0 = time.time()
        agrees, derived, recorded = coverage_matches(cert)
        res = verify_levels(code, cert, budget_per_level=budget,
                            samples_per_big_level=samples, seed=seed + i)
        lv = res["levels"]
        exh = min(res["exhaustive_through_depth"].values()) if res["exhaustive_through_depth"] else 0
        checked = sum(x["checked"] for x in lv)
        lights = [x["lightest_non_stabilizer"] for x in lv
                  if x["lightest_non_stabilizer"] is not None]
        lightest = min(lights) if lights else None
        exh_checked = sum(x["checked"] for x in lv if x["exhaustive"])
        row = {"replica": i, "claimed_d": cert["lower_bound"],
               "deficiencies_recomputed": res["deficiencies_recomputed"],
               "deficiencies_agree": res["deficiencies_agree"],
               "independently_earned_bound": res["independently_earned_bound"],
               "earned_bound_reaches_claim": res["earned_bound_reaches_claim"],
               "coverage_agrees": bool(agrees),
               "derived_candidates": derived, "recorded_candidates": recorded,
               "exhaustive_through_depth": exh,
               "candidates_verified_exhaustively": exh_checked,
               "candidates_checked_total": checked,
               "lightest_logical_seen": lightest,
               "levels": lv, "violations": res["violations"],
               "seconds": round(time.time() - t0, 1)}
        out["replicas"].append(row)
        flag = ("REFUTED" if res["violations"]
                else ("OK" if agrees else "COVERAGE MISMATCH"))
        print(f"  {cid:20s} rep{i}  d>={cert['lower_bound']:2d}  "
              f"coverage {derived:>18,} {'==' if agrees else '!='} recorded  "
              f"EXH<=depth {exh} ({exh_checked:,} cands)  "
              f"lightest {lightest}  EARNED d>={res['independently_earned_bound']}"
              f"{'  == CLAIM' if res['earned_bound_reaches_claim'] else ''}"
              f"  defs {res['deficiencies_recomputed']}"
              f"{'' if res['deficiencies_agree'] else ' DISAGREE!'}  -> {flag}",
              flush=True)
        for v in res["violations"][:3]:
            print(f"      !! index {v['index']} weight {v['weight']} < "
                  f"{cert['lower_bound']} (set {v['set']}, depth {v['depth']})")
    return out


def main() -> int:
    # Refuse to START if a running certification would be the thing
    # that dies. Three closures were already lost this way.
    from oneq.headroom import require
    require('challenge_lower_bound')
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", type=int, default=60000)
    ap.add_argument("--budget", type=int, default=800000,
                    help="levels at or below this size are enumerated ENTIRELY")
    ap.add_argument("--seed", type=int, default=20260728)
    a = ap.parse_args()

    cat = _catalogue()
    recs = [r for r in _records() if r.get("status") in ("CLOSED", "IMPROVED")]
    print(f"CHALLENGING {len(recs)} promoted closures -- {a.samples:,} indices "
          f"per replica, rebuilt from recorded pivots, sharing no code with the "
          f"sweep\n")
    t0 = time.time()
    results, violated = [], 0
    for rec in recs:
        res = challenge(rec, cat, a.samples, a.seed, a.budget)
        results.append(res)
        violated += sum(len(x["violations"]) for x in res["replicas"])

    cov_ok = all(x["coverage_agrees"] for r in results for x in r["replicas"])
    out = {"closures": results, "total_violations": violated,
           "coverage_identity_holds_everywhere": bool(cov_ok),
           "samples_per_big_level": a.samples, "seed": a.seed,
           "exhaustive_level_budget": a.budget,
           "claim": ("no counterexample in the sampled region; this is NOT a "
                     "proof of absence -- see the module docstring"),
           "seconds": round(time.time() - t0, 1)}
    dst = _HERE.parent / "evidence" / "challenge_lower_bound.json"
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(f"\n  coverage identity holds on every replica: {cov_ok}")
    print(f"  violations found: {violated}")
    print(f"  evidence -> {dst}")
    return 1 if (violated or not cov_ok) else 0


if __name__ == "__main__":
    raise SystemExit(main())
