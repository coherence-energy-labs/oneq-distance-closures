"""Reproduce a promoted lower bound from scratch, by code that never searched.

THE CLAIM THIS SETTLES. Until now the honest statement was "the lower bound
requires re-execution, and the only runner is ours." That is a real limitation:
a reviewer either trusts the searcher or reruns the searcher.

This is a second, independent runner. It shares the THEOREM with the engine, as
any reimplementation must, and none of its machinery:

  * the information set comes from the certificate's recorded pivot QUBITS, by
    row-reducing the normalizer with those columns first. The reduced form is
    unique given the pivots, so no seed is replayed and no planner is duplicated.
  * the DEFICIENCIES are recomputed from the pivot lists rather than read back --
    d_i = |Q_i| - |Q_i \\ (earlier sets)| -- which is the one quantity the whole
    bound rests on, and the one a verifier should least want to be told.
  * the bound is then earned depth by depth: exhausting every candidate with at
    most L pivots per set is exactly the theorem's hypothesis, so completing
    those levels yields SUM_i max(0, L+1-d_i) as an independent number.

For 9_6_0172 (deficiencies [0,4]) that ladder reads

    L=3 -> d>=4    L=4 -> d>=6    L=5 -> d>=8    L=6 -> d>=10

so completing depth 6 on both sets reproduces the full promoted claim without
ever running `certify_distance`.

SHARDING. Work is split by COMBINATION RANK, and every shard's range is derived
from C(Kq, L) rather than recorded, so a coordinator checks coverage by
arithmetic. Progress is written after each shard, so a run that dies at hour
five resumes at hour five.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time
from math import comb

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from oneq.bz import _logical_masks, sym_layout                     # noqa: E402
from oneq.gbb import build_pbb                                     # noqa: E402
from oneq.ledger import (certified_bound_at_depth,                 # noqa: E402
                         certified_bound_per_set, rebuild_options,
                         recompute_deficiencies, sweep_level)
from verify_closures import _catalogue, _records                   # noqa: E402


def main() -> int:
    # Refuse to START if a running certification would be the thing
    # that dies. Three closures were already lost this way.
    from oneq.headroom import require
    require('independent_reproduction')
    ap = argparse.ArgumentParser()
    ap.add_argument("--code", default="9_6_0172")
    ap.add_argument("--replica", type=int, default=0)
    ap.add_argument("--depth", type=int, default=6)
    ap.add_argument("--shards", type=int, default=64)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    cat = _catalogue()
    rec = next(r for r in _records() if r["code_id"] == a.code)
    r = cat[a.code]
    code = build_pbb(r["ell"], r["m"], r["A_terms"], r["B_terms"],
                     r.get("C_terms"), r.get("D_terms"),
                     code_id=a.code, expect_k=r["k"])
    cert = rec["certificates"][a.replica]
    claimed = int(cert["lower_bound"])
    sets = cert["sets"]

    recorded_def = [s["deficiency"] for s in sets]
    my_def = recompute_deficiencies(sets)
    print(f"{a.code} replica {a.replica}: certificate claims d = {claimed}")
    print(f"  deficiencies recorded {recorded_def}  RECOMPUTED {my_def}  "
          f"agree={recorded_def == my_def}")
    if recorded_def != my_def:
        print("  REFUSING: recomputed deficiencies disagree with the certificate",
              file=sys.stderr)
        return 2
    # ONLY SETS THIS RUN WILL ACTUALLY ENUMERATE MAY CONTRIBUTE.
    #
    # An external audit caught this: with set 1 marked unswept the runner
    # printed "skipping" and then INDEPENDENTLY CERTIFIED d >= 6, one of which
    # came from the set it had just skipped. `certified_bound_per_set` -- the
    # fix, whose docstring documents this exact failure -- had landed in
    # ledger.py and never reached the runner. A twin-copy miss, hours after
    # writing the rule against them.
    #
    # It does not move the published 9_6_0172 figure (both sets were genuinely
    # swept there), but the arithmetic was wrong and would have inflated any
    # future one-set case.
    will_sweep = {i for i, s_ in enumerate(sets)
                  if int(s_.get("levels_swept", 0)) > 0}
    ladder = {L: certified_bound_per_set(my_def, {i: L for i in will_sweep})
              for L in range(1, a.depth + 2)}
    print(f"  sets this run will enumerate: {sorted(will_sweep)} of "
          f"{len(sets)}  (skipped sets contribute NOTHING)")
    print(f"  bound earned per exhaustive depth: "
          + "  ".join(f"L={L}->{b}" for L, b in ladder.items()))
    target = certified_bound_per_set(my_def, {i: a.depth for i in will_sweep})
    print(f"  completing depth {a.depth} on every set earns d >= {target}"
          f"  ({'FULL claim' if target >= claimed else 'partial'})\n")

    nwh, _ = sym_layout(code.n)
    masks = _logical_masks(code)
    dst = pathlib.Path(a.out) if a.out else (
        pathlib.Path(__file__).resolve().parent.parent / "evidence"
        / f"independent_reproduction_{a.code}_r{a.replica}.json")
    dst.parent.mkdir(parents=True, exist_ok=True)
    state = json.loads(dst.read_text()) if dst.exists() else {}
    state.setdefault("code_id", a.code)
    state.setdefault("replica", a.replica)
    state.setdefault("claimed_d", claimed)
    state.setdefault("deficiencies_recomputed", my_def)
    state.setdefault("bound_ladder", {str(k): v for k, v in ladder.items()})
    state.setdefault("shards", {})
    t0 = time.time()

    for si, s in enumerate(sets):
        if int(s.get("levels_swept", 0)) == 0:
            print(f"  set {si}: never swept by the prover, skipping")
            continue
        opts, _ = rebuild_options(code, s["pivot_list"])
        nq = opts.shape[0]
        for L in range(1, a.depth + 1):
            total = comb(nq, L)
            nsh = 1 if total < 100000 else a.shards
            step = (total + nsh - 1) // nsh
            for j in range(nsh):
                key = f"s{si}_L{L}_sh{j}"
                if key in state["shards"]:
                    continue
                lo, hi = j * step, min((j + 1) * step, total)
                if lo >= hi:
                    continue
                ts = time.time()
                ck, light, vio = sweep_level(opts, masks, nwh, L, claimed,
                                             comb_lo=lo, comb_hi=hi)
                state["shards"][key] = {
                    "set": si, "depth": L, "comb_lo": lo, "comb_hi": hi,
                    "checked": ck, "lightest_logical": light,
                    "violations": vio, "seconds": round(time.time() - ts, 1)}
                dst.write_text(json.dumps(state, indent=2), encoding="utf-8")
                if vio:
                    print(f"  !! VIOLATION in {key}: {vio[:2]}", flush=True)
            done = [v for k, v in state["shards"].items()
                    if v["set"] == si and v["depth"] == L]
            lights = [v["lightest_logical"] for v in done
                      if v["lightest_logical"] is not None]
            print(f"  set {si} depth {L}: {sum(v['checked'] for v in done):>15,} "
                  f"candidates, lightest logical {min(lights) if lights else '-'}, "
                  f"violations {sum(len(v['violations']) for v in done)}  "
                  f"[{time.time() - t0:.0f}s total]", flush=True)

    vio_total = sum(len(v["violations"]) for v in state["shards"].values())
    checked = sum(v["checked"] for v in state["shards"].values())
    lights = [v["lightest_logical"] for v in state["shards"].values()
              if v["lightest_logical"] is not None]
    state["candidates_checked"] = checked
    state["violations"] = vio_total
    state["lightest_logical"] = min(lights) if lights else None
    state["independently_certified_d"] = target if not vio_total else None
    state["reproduces_full_claim"] = bool(not vio_total and target >= claimed)
    state["seconds"] = round(time.time() - t0, 1)
    dst.write_text(json.dumps(state, indent=2), encoding="utf-8")
    print(f"\n  {checked:,} candidates checked, {vio_total} violations, "
          f"lightest logical {state['lightest_logical']}")
    print(f"  INDEPENDENTLY CERTIFIED d >= {state['independently_certified_d']} "
          f"(certificate claims {claimed})")
    print(f"  reproduces the full claim: {state['reproduces_full_claim']}")
    print(f"  evidence -> {dst}")
    return 1 if vio_total else 0


if __name__ == "__main__":
    raise SystemExit(main())
