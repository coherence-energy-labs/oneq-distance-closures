# Independent re-check of the six exact distances — 2026-09-15

A second derivation of every claim in qiskit-community/qcode-discovery PR #2, sharing no code
with the evidence bundle's search, encoder or verifier. Everything here was run on the day
named, against upstream `main` at `d12bea2` and the PR head at `20bb68a`.

## What was checked, and by what

| step | tool | result |
|---|---|---|
| Codes rebuilt from the rows at upstream `main` with IBM's own constructor, `evaluation/pbb_code.build_pbb_code`, in IBM's uv-locked environment (Python 3.12.13, qldpc 0.2.6) | `ibm_rebuild_and_witness.py` | n and k match the rows for all six; k agrees between `code.dimension` and a GF(2) rank computed here |
| Inline witnesses (`witness_support`) against those matrices | same | weight = d, commute with every stabilizer, not a stabilizer (rank rises), all six |
| Controls: three of IBM's own EXACT rows, none ours (`6_6_0099` milp_exact; `phase2_2`, `phase2_3` exact_w6) | same, then `run_independent.py` | rebuilt, and their distances proven exact in both directions by the encoding below |
| Distance, both directions, with a separately written CNF: Tseitin XOR commutation, OR of logical parities for "not a stabilizer", **totalizer** cardinality (the bundle used a sequential counter), anchoring only after the translation permutations are proven by rank to preserve the stabilizer space of the actual matrix | `independent_distance_cnf.py`, `run_independent.py`, CaDiCaL 2.1.2, lrat-check (drat-trim) | all six: UNSAT at W = d−1 on both anchors with `c VERIFIED` proofs; SAT at W = d with the model re-checked outside the solver (commutes, non-stabilizer, weight ≤ d) |
| The 12 CNFs shipped in `certificates_lrat/` of the pinned v1.0.5 archive (fresh download, SHA256SUMS 71/71) | CaDiCaL 2.1.2 `--lrat --no-binary`, lrat-check | see `reprove_published.log` |
| `validate_pr_rows.py` (evidence repo, tag v1.0.5) on the PR head and on the corrected catalogue | — | 115/115 both |
| `challenge/verify.sh` (evidence repo, tag v1.0.5) | — | VALID accepted, 7/7 forgeries rejected |

## The catalogue correction

`build_corrected_catalogue.py` writes the 362 untouched rows as IBM's bytes and the six rows with
`json.dumps` defaults (the catalogue's own formatting), changing two fields: `publication_quality`
to `true` (IBM's `scripts/merge_deep_milp_results.py` holds EXACT ⇒ publication_quality) and
`d_exactness_source.supersedes` naming v1.0.4. It proves the result is six lines against `main`
and semantically identical to the reviewed head otherwise.

## Running it

```
# from the root of a qcode-discovery checkout, inside its environment
uv run python ibm_rebuild_and_witness.py <main catalogue.jsonl> <PR catalogue.jsonl> export/
# then, with cadical and lrat-check on PATH and python-sat installed
python run_independent.py export/ work/ 1 control_phase2_2 control_phase2_3 control_6_6_0099
python run_independent.py export/ work/ 1 phase2_64 phase2_65 9_6_0172 0571f76786029653 12_6_0201 12_6_0199
```

Proofs are deleted after checking; the independent encoding's largest proof (12_6_0199, anchor 0)
is 363 MB and solves in about 30 s.
