"""Does the 'independent' verifier actually import the producer?

WHY A GATE AND NOT A REVIEW. This programme published a top independence tier
reading "a separately implemented runner that never invokes the production
certification engine". An outside audit checked the imports. The runner pulls
`_logical_masks` and `sym_layout` out of `bz.py` -- the search engine -- and its
bound formula out of `ledger.py`. `certify_distance` is genuinely not invoked,
which is the defensible scope, but the wording claimed more than the imports
supported.

The audit also found one I had missed entirely: `challenge_lower_bound.py`
imports `verify_levels` from `oneq.ledger`, and `verify_levels` IS the sweep it
describes itself as sharing no code with.

A claim of independence that a human re-reads each time it changes will drift
again. This makes it a build step: declare the producer symbols, declare each
verifier's permitted scope, and fail when the imports outrun the words.

WHAT THIS CANNOT DO. It sees imports, not semantics. A verifier that
re-implements a producer routine line-for-line under a new name passes here and
is no more independent for it. Token-level checking catches drift and
copy-paste, not deliberate laundering -- and saying so is the point, since a
gate whose limits are unstated gets read as a proof.
"""

from __future__ import annotations

import ast
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Symbols that BELONG to the producer. Importing one is not automatically
#: wrong -- a second implementation of a theorem must share the mathematics --
#: but it must be declared, because every undeclared one is an overclaim.
PRODUCER_SYMBOLS = {
    "oneq.bz": ["certify_distance", "_sweep_depth", "_pair_greedy_qubits",
                "_groups_from_pivots", "_choice_table", "_logical_masks",
                "sym_layout", "pack_sym", "unpack_sym", "rref_sym",
                "qweight_sym", "popcount", "_col_tables", "_interleaved"],
    "oneq.ledger": ["sweep_level", "verify_levels", "certified_bound_at_depth",
                    "certified_bound_per_set", "rebuild_options",
                    "recompute_deficiencies", "candidate_at"],
    "oneq.isd": ["min_logical_weight", "certify_exact", "LogicalSyndrome"],
    "oneq.certify": ["certify"],
}

#: What each verifier is ALLOWED to import, and the claim that allowance
#: supports. Anything outside the allow-list fails the gate.
POLICY = {
    "tools/independent_reproduction.py": {
        "claim": "certify_distance is not invoked; the information set is "
                 "rebuilt from recorded pivots and the deficiencies recomputed",
        "forbidden": ["certify_distance", "_pair_greedy_qubits", "_sweep_depth"],
        "allowed": ["_logical_masks", "sym_layout", "sweep_level",
                    "rebuild_options", "recompute_deficiencies",
                    "certified_bound_at_depth", "certified_bound_per_set"],
    },
    "tools/challenge_lower_bound.py": {
        "claim": "rebuilt from recorded pivots; certify_distance not invoked",
        "forbidden": ["certify_distance", "_pair_greedy_qubits", "_sweep_depth"],
        "allowed": ["verify_levels", "coverage_matches", "total_candidates",
                    "recompute_deficiencies", "certified_bound_per_set"],
    },
    "tools/verify_closures.py": {
        "claim": "imports nothing from the search engines that produced the "
                 "result -- only code reconstruction and GF(2) linear algebra",
        "forbidden": ["certify_distance", "sweep_level", "verify_levels",
                      "_sweep_depth", "_pair_greedy_qubits", "min_logical_weight"],
        "allowed": ["witness_from_support"],
    },
}


def imported_symbols(path: pathlib.Path) -> list[tuple[str, str]]:
    """(module, symbol) for every import, including function-local ones."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                out.append((node.module, a.name))
        elif isinstance(node, ast.Import):
            for a in node.names:
                out.append((a.name, "*"))
    return out


def check(rel: str, policy: dict) -> dict:
    path = ROOT / rel
    if not path.exists():
        return {"file": rel, "ok": False, "reason": "file not found"}
    producer_all = {s for v in PRODUCER_SYMBOLS.values() for s in v}
    hits = [(m, s) for m, s in imported_symbols(path)
            if s in producer_all or s in policy["forbidden"]]
    forbidden = sorted({s for _m, s in hits if s in policy["forbidden"]})
    undeclared = sorted({s for _m, s in hits
                         if s not in policy["allowed"]
                         and s not in policy["forbidden"]})
    return {"file": rel, "claim": policy["claim"],
            "producer_symbols_imported": sorted({s for _m, s in hits}),
            "forbidden_imports": forbidden,
            "undeclared_producer_imports": undeclared,
            "ok": not forbidden and not undeclared}


#: The claim the RELEASE actually made, before the audit narrowed it. Kept so
#: the gate can be shown to have teeth: an allow-list written from the code it
#: inspects proves nothing, so the negative control runs the OLD wording and
#: must fail.
OVERCLAIMED_POLICY = {
    "tools/independent_reproduction.py": {
        "claim": "a SEPARATELY IMPLEMENTED runner sharing no code with the "
                 "engine (the release's original wording)",
        "forbidden": ["certify_distance", "_pair_greedy_qubits", "_sweep_depth",
                      "_logical_masks", "sym_layout", "sweep_level",
                      "rebuild_options", "certified_bound_at_depth"],
        "allowed": [],
    },
    "tools/challenge_lower_bound.py": {
        "claim": "shares no code with the sweep (the tool's own docstring)",
        "forbidden": ["verify_levels", "sweep_level", "certify_distance"],
        "allowed": [],
    },
}


def demo_overclaim() -> int:
    """Show the gate refusing the wording the release shipped with."""
    print()
    print("NEGATIVE CONTROL -- the gate against the ORIGINAL claim:")
    print()
    fails = 0
    for rel, pol in OVERCLAIMED_POLICY.items():
        r = check(rel, pol)
        fails += not r["ok"]
        print(f"  [{'OK  ' if r['ok'] else 'FAIL'}] {rel}")
        print(f"         claimed: {r['claim'][:66]}")
        if r.get("forbidden_imports"):
            print(f"         refuted by: {r['forbidden_imports']}")
    print()
    print(f"  {fails}/{len(OVERCLAIMED_POLICY)} original claims REFUTED by "
          f"their own imports"
          + ("  <- the gate has teeth" if fails else "  <- GATE IS VACUOUS"))
    return fails


def main() -> int:
    print("PRODUCER-IMPORT GATE -- do the imports support the independence claim?\n")
    rows = [check(rel, pol) for rel, pol in POLICY.items()]
    bad = 0
    for r in rows:
        mark = "OK  " if r["ok"] else "FAIL"
        print(f"  [{mark}] {r['file']}")
        print(f"         imports from the producer: "
              f"{r.get('producer_symbols_imported') or 'none'}")
        if r.get("forbidden_imports"):
            print(f"         FORBIDDEN: {r['forbidden_imports']}")
        if r.get("undeclared_producer_imports"):
            print(f"         UNDECLARED (widen the claim or drop the import): "
                  f"{r['undeclared_producer_imports']}")
        bad += not r["ok"]
    out = {"rows": rows, "failures": bad,
           "limitation": "token-level: catches drift and copy-paste, NOT a "
                         "verifier that re-implements a producer routine under "
                         "a new name"}
    dst = ROOT / "evidence" / "independence_gate.json"
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(out, indent=2), encoding="utf-8")
    # THE ALLOW-LISTS WERE WRITTEN FROM THE CODE THEY INSPECT, so passing them
    # proves nothing on its own. Run the wording the release actually shipped
    # and require it to FAIL, or this gate is a mirror.
    refuted = demo_overclaim()
    out["overclaim_control_refutations"] = refuted
    out["gate_has_teeth"] = bool(refuted)
    dst.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print()
    print(f"  {len(rows) - bad}/{len(rows)} current claims pass; "
          f"{refuted} original claims refuted   evidence -> {dst.name}")
    return 1 if (bad or not refuted) else 0


if __name__ == "__main__":
    raise SystemExit(main())
