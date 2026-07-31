# Limitations

Stated plainly, because a release that hides these is worth less than one that
does not exist.

## The lower bound has no succinct machine-checkable proof object

The upper bound ships a witness anyone verifies in milliseconds. The lower bound
is an **absence claim** over up to 8.15e12 candidates. Independently verifying it
from first principles requires **re-executing the declared search**.

We looked for a short certificate and did not find one, for a recorded reason:
any Delsarte/LP-style bound bounds the minimum weight of `N(S)` **as a linear
code**, and `N(S)` contains the stabilizers -- several of these codes carry
stabilizers *lighter than their distance* (weight 6 against d=10). No such bound
can exceed the lightest stabilizer. Applying the LP per logical coset instead
needs the weight distribution of `S`, which is 2^106 here.

Every certificate records `lower_bound_is_machine_checkable: false` internally,
so the caveat travels with the artifact.

## What is machine-checkable, and what is not

| claim | checkable from artifacts alone |
|---|---|
| the code is the one IBM published | yes, milliseconds |
| `d <= d*` (the witness) | yes, milliseconds |
| candidate accounting | yes, microseconds -- closed-form identity |
| replicas used distinct information sets | yes, minutes -- rebuilt from seeds |
| no light operator at low depth | yes, minutes -- levels enumerated by index |
| `d >= d*` in full | **no** -- requires re-execution |

## Independence is not uniform

Independently reproduced lower bound: 9_6_0172.
Two replicas only: 0571f76786029653, phase2_64, phase2_65, 12_6_0199, 12_6_0201.

## Provenance caveats

- `engine_fingerprint` on these certificates was computed **at upgrade time**,
  not at proof time; schema 1 recorded no engine identity. Each certificate says
  so via `engine_fingerprint_is_the_proving_engine: false`.
- Information sets are marked `recomputed`, not `captured`: they were re-derived
  from the recorded seed and **required** to reproduce the artifact's own
  deficiencies. That proves reproducibility, not that the original run
  enumerated them.

## Scope

These are six codes. Nothing here claims a general speedup, a bound on what
remains reachable in the catalogue, or that the method scales to arbitrary
parameters. `ERRATA.json` lists every claim this programme retracted, several
withdrawn by its own gates before publication.

## v1.0.2 supersedes v1.0.1 — trust-root fix

v1.0.1's bundled verifier **failed open**: `_trusted_pubkeys()` returned an
empty set when `ISSUERS.json` was missing or malformed, and the caller read
`if trusted and key not in trusted`, so an empty registry disabled issuer
pinning entirely and the certificate was checked against the public key
embedded inside itself. An attacker who deleted or corrupted the registry
could self-sign a certificate that passed the authenticity check.

v1.0.2 fails **closed**: no valid registry, a revoked key, or an unpinned key
each cause refusal. The loader validates the schema pin, 64-hex key format,
active/revoked disjointness, and duplicates.

**The certificates are unchanged and were never affected** — they carry the
correct active key, and the published registry lists it as active. What
changed is the verifier's behaviour under a damaged trust registry.

v1.0.1 remains downloadable for provenance, and should not be used to verify.
