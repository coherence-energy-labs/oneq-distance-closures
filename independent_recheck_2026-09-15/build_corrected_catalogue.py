"""Build the corrected PR catalogue: IBM's 362 untouched lines byte for byte, plus our six rows
re-serialized with json.dumps defaults (IBM's own formatting), with two content corrections:
publication_quality True on EXACT rows (IBM's invariant, scripts/merge_deep_milp_results.py) and
supersedes naming v1.0.4 as well. Everything else in the six rows is left exactly as reviewed.

    python build_corrected_catalogue.py <base.jsonl> <ours.jsonl> <out.jsonl>

Prints the proof that the result differs from IBM's main by exactly six lines and from the reviewed
PR head by exactly the two intended fields.
"""
import json
import pathlib
import sys

base_p, ours_p, out_p = map(pathlib.Path, sys.argv[1:4])
base_lines = base_p.read_text(encoding="utf-8").split("\n")
ours_lines = ours_p.read_text(encoding="utf-8").split("\n")
assert base_lines[-1] == "" and ours_lines[-1] == "", "both files must end with one newline"
base_lines, ours_lines = base_lines[:-1], ours_lines[:-1]
assert len(base_lines) == len(ours_lines) == 368
IDS = {"12_6_0199", "12_6_0201", "phase2_64", "phase2_65", "9_6_0172", "0571f76786029653"}
key = lambda r: r.get("code_id") or r.get("bliss_hash")
SUPERSEDES = ("v1.0.1 (verifier failed open), v1.0.2 (manifest predated the fix), v1.0.3 (asset rebuilt under "
              "its own tag), v1.0.4 (lower bound not yet machine-checkable). Certificates unchanged throughout.")

out, changed, field_changes = [], 0, {}
for b_line, o_line in zip(base_lines, ours_lines):
    b, o = json.loads(b_line), json.loads(o_line)
    if key(b) not in IDS:
        assert b == o, f"row {key(b)} differs in content but is not one of the six"
        out.append(b_line)                      # IBM's bytes, untouched
        continue
    assert key(o) == key(b) and o["trust_level"] == "EXACT" and o["d_is_exact"] is True
    diffs = []
    if o["publication_quality"] is not True:
        o["publication_quality"] = True
        diffs.append("publication_quality: false -> true")
    src = o["d_exactness_source"]
    if "v1.0.4" not in src["supersedes"]:
        src["supersedes"] = SUPERSEDES
        diffs.append("supersedes: + v1.0.4")
    field_changes[key(o)] = diffs
    line = json.dumps(o)                        # IBM's formatting: default separators, ensure_ascii
    assert json.loads(line) == o
    out.append(line)
    changed += 1
out_p.write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")

# proofs
new_lines = out_p.read_text(encoding="utf-8").split("\n")[:-1]
n_diff = sum(a != c for a, c in zip(base_lines, new_lines))
print(f"rows rewritten: {changed}; lines differing from IBM main: {n_diff}; CR bytes: {out_p.read_bytes().count(13)}")
for cid, diffs in field_changes.items():
    print(f"  {cid:18} {', '.join(diffs) or 'no field change'}")
# semantic equality with the reviewed PR head except the two intended fields
for o_line, n_line in zip(ours_lines, new_lines):
    o, n = json.loads(o_line), json.loads(n_line)
    if key(o) in IDS:
        o["publication_quality"] = True
        o["d_exactness_source"]["supersedes"] = SUPERSEDES
    assert o == n, f"unexpected semantic change in {key(o)}"
print("semantically equal to the reviewed PR head apart from publication_quality and supersedes: yes")
# the six new lines re-serialize IBM's own formatting: test on an untouched row
sample = next(l for l in base_lines if json.loads(l).get("code_id") == "6_6_0099")
print("json.dumps defaults reproduce IBM's bytes on an untouched row:", json.dumps(json.loads(sample)) == sample)
sys.exit(0 if n_diff == 6 else 1)
