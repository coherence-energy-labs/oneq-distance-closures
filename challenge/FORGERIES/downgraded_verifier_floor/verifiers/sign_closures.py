"""Sign the closures. The four provenance hashes were integrity, not authenticity.

WHAT AN EXTERNAL AUDIT DEMONSTRATED. A forged certificate claiming d=10 for
`12_6_0201` -- a code this programme certified at 8 -- carrying a genuine
weight-10 logical as its witness and self-consistent bookkeeping, was sealed by
`verify_closures.py`: witness VERIFIED, hashes RECOMPUTED-MATCH, 6/6 PROMOTABLE,
exit 0.

The hole is structural, not a missed check. The verifier RECOMPUTES the four
hashes from the artifact's own data, which detects accidental corruption and
nothing else: an attacker who edits the numbers regenerates the hashes and every
one matches. Integrity answers "was this changed since it was written"; only a
signature answers "who wrote it". Nothing in the release was signed.

The bitter part is that the apparatus already existed and was pointed at the
wrong thing. `passport.py`, `ISSUERS.json`, the Ed25519 issuer key and the
cross-language conformance suite -- the whole G0 trust root -- were built,
tested, and never applied to the flagship artifact.

WHAT IS SIGNED. A canonical core over every field a forgery must touch to
inflate a claim:

    code_id, lower_bound, upper_bound, exact, depth_p, candidates,
    witness_support, and per set: pivot_list, deficiency, contribution,
    levels_swept

Editing any of them invalidates the signature. The forgery above changed
lower_bound, upper_bound, witness_support and two sets' deficiency and
contribution -- five of these fields.

WHAT SIGNING DOES NOT DO, so nobody reads more into it than it carries: it binds
the artifact to a key, not the mathematics to reality. A signed wrong number is
still wrong. Authenticity sits BESIDE the checks that establish correctness --
the witness, the coverage identity, the independent challenge -- and replaces
none of them.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from oneq.passport import digest_obj, mint                          # noqa: E402

KEY_PATH = pathlib.Path(os.environ.get(
    "ONEQ_ISSUER_KEY", pathlib.Path.home() / ".oneq" / "oneq-issuer.key"))


def certificate_core(code_id: str, cert: dict) -> dict:
    """Everything a forgery must alter to inflate a distance claim."""
    return {
        "schema": "oneq-closure-core/1",
        "code_id": code_id,
        "lower_bound": int(cert["lower_bound"]),
        "upper_bound": (None if cert.get("upper_bound") is None
                        else int(cert["upper_bound"])),
        "exact": bool(cert.get("exact")),
        "depth_p": int(cert.get("depth_p", 0)),
        "candidates": int(cert.get("candidates", 0)),
        "witness_support": cert.get("witness_support"),
        "sets": [{"index": int(s["index"]),
                  "pivot_list": [int(x) for x in s.get("pivot_list", [])],
                  "deficiency": int(s["deficiency"]),
                  "contribution": int(s["contribution"]),
                  "levels_swept": int(s["levels_swept"])}
                 for s in cert.get("sets", [])],
    }


def core_digest(code_id: str, cert: dict) -> str:
    return digest_obj(certificate_core(code_id, cert))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", default=str(KEY_PATH))
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    key_file = pathlib.Path(a.key)
    if not key_file.exists():
        print(f"issuer key not found at {key_file}. Generate one with "
              f"tools/keygen.py; it must live OUTSIDE the repository.",
              file=sys.stderr)
        return 2
    raw = key_file.read_bytes().strip()
    seed = bytes.fromhex(raw.decode()) if len(raw) == 64 else raw
    if len(seed) != 32:
        print(f"issuer key must be 32 raw bytes or 64 hex chars, got {len(seed)}",
              file=sys.stderr)
        return 2

    d = ROOT / "experiments" / "gate0b_ibm825"
    signed = 0
    for f in sorted(d.glob("closed_*.json")):
        recs = json.loads(f.read_text(encoding="utf-8"))
        changed = False
        for rec in recs:
            if rec.get("status") not in ("CLOSED", "IMPROVED"):
                continue
            for i, cert in enumerate(rec["certificates"]):
                core = certificate_core(rec["code_id"], cert)
                p = mint(core, private_key_bytes=seed)
                cert["signature"] = {
                    "schema": "oneq-closure-signature/1",
                    "digest": p["digest"], "pubkey": p["pubkey"],
                    "sig_alg": p["sig_alg"], "signature": p["signature"],
                    "signs": sorted(core.keys()),
                    "note": "binds the artifact to an issuer. It does NOT make "
                            "the number true -- authenticity sits beside the "
                            "witness and the challenge, replacing neither.",
                }
                signed += 1
                changed = True
                print(f"  {rec['code_id']:20s} replica {i}  "
                      f"digest={p['digest'][:16]}  key={p['pubkey'][:16]}")
        if changed and not a.dry_run:
            f.write_text(json.dumps(recs, indent=2), encoding="utf-8")
            print(f"  wrote {f.name}")
    print(f"\n{signed} certificate(s) signed"
          + ("  (DRY RUN, nothing written)" if a.dry_run else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
