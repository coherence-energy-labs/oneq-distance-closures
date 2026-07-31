# ONE-Q Distance Closures — public evidence release

Certified exact distances for six previously unresolved PBB codes from IBM's
qcode-discovery catalogue. Companion to
[qiskit-community/qcode-discovery#2](https://github.com/qiskit-community/qcode-discovery/pull/2).

## Verify in one command (~2 minutes, Python 3.10+, numpy and cryptography)

    cd oneq-ibm-distance-closures-v1.0.5
    PYTHONPATH=. python verifiers/verify_closures.py

Expected: `6/6 closures fully re-verified ... 6/6 PROMOTABLE`.

## The Stranger Verification Challenge

`challenge/` contains the VALID bundle **and seven deliberate forgeries** —
inflated bound, altered information set, substituted witness, downgraded
verifier, and three trust-root attacks (**missing**, **malformed**, and
**revoked** issuer registry). One command must accept the valid bundle and
reject all seven:

    cd challenge && ./verify.sh        # or .\verify.ps1

Tree-hash pin for the VALID bundle (compare against what the runner prints):

    (see PIN.txt -- computed over the bytes git serves, validated by fresh clone)

Run it, publish your unedited log, fill `challenge/ATTESTATION_TEMPLATE.json`.
An ambiguity report is as valuable as an attestation.

## What is and is not claimed

Upper bounds carry small inline witnesses (checkable in seconds). Lower bounds
are exhaustive-absence claims: re-executable with the included engine, but not
succinctly machine-checkable — see `LIMITATIONS.md` in the bundle. One closure
(`9_6_0172`) additionally has a separately implemented reproduction
(49,256,436,180 candidates re-enumerated across 582 shards).

## Machine-checkable lower bounds (new in v1.0.5)

The lower bounds are no longer attestations. `certificates_lrat/` carries, for
all six closures, the CNF encoding of *"a logical operator of qubit weight
≤ d−1 exists"* plus the SHA-256 of an **LRAT proof of its UNSATISFIABILITY**.
Each was checked with `lrat-check` (drat-trim) and reported `c VERIFIED`.

    cadical --lrat --no-binary anchor0.cnf anchor0.lrat   # s UNSATISFIABLE
    lrat-check anchor0.cnf anchor0.lrat                   # c VERIFIED

Both anchors must be UNSAT; the two anchored instances cover every orbit of the
translation group. Solve times ran 18 s to 25 min — against 8.15 × 10¹²
enumerated candidates and 6.4 GPU-hours per replica for `12_6_0199` alone.

Proofs total 17.3 GB and are **not** shipped; the CNFs (5 MB) are. Regenerating
a proof from the CNF is an independent re-derivation, which is stronger than
re-reading bytes we produced.

## Licensing

* **Code** (verifiers, engine, tools): Apache License 2.0 — see `LICENSE`.
* **Evidence** (certificates, witnesses, reports): **CC-BY-4.0** — reuse
  freely **with attribution** to Coherence Energy Labs.
* Certificates are Ed25519-signed; issuer public keys are pinned in
  `oneq-ibm-distance-closures-v1.0.5/ISSUERS.json`. A signature proves
  authorship; the archive SHA-256 below proves integrity.

Archive SHA-256 (`oneq-ibm-distance-closures-v1.0.5.tar.gz`, attached to the
v1.0.5 release):

    e3b5cf0ce7e61c1d17411321e51b7d9faf9054f44285b0f10efdf9cac4fc9778

## Validating the catalogue rows

`validate_pr_rows.py` reproduces the 103-check report attached to the PR
(row scope, unchanged distances, bound and candidate recomputation, hash
formats, witness sizes, replica distinctness, and issuer-registry pinning):

    python validate_pr_rows.py <path-to-qcode-discovery-checkout>         oneq-ibm-distance-closures-v1.0.5/ISSUERS.json

## Trust-root note — v1.0.2 SUPERSEDES v1.0.1

External review found the signature verifier **failed open**: an empty or
malformed `ISSUERS.json` disabled issuer pinning entirely, so a self-signed
certificate could pass authenticity. Deleting a file must never grant trust.
The verifier now **fails closed** — no valid registry, a revoked key, or an
unpinned key all refuse — and the registry loader validates schema, key
format, and active/revoked disjointness. The three issuer forgeries in
`challenge/` are the permanent proof this stays fixed.

Cite via `CITATION.cff`.

## Integrity, and how it was broken before

    cd oneq-ibm-distance-closures-v1.0.5 && sha256sum -c SHA256SUMS   # 58/58 OK

v1.0.0 through v1.0.2 each shipped an artifact that did not match its own
description: a crash on other machines, then directory/archive drift, then a
tree-hash pin no clean clone could reproduce (57/57 files failing their own
manifest) plus a manifest that predated the verifier fix. Root cause of the
last two: line-ending conversion between the authoring machine and git. This
release adds  with , normalizes every text file to
LF, regenerates SHA256SUMS **after** the final edit, and -- the part that was
missing -- validates the published pin **from a fresh clone on which nothing
was authored** before the pin is published at all.
