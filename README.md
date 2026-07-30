# ONE-Q Distance Closures — public evidence release

Certified exact distances for six previously unresolved PBB codes from IBM's
qcode-discovery catalogue. Companion to
[qiskit-community/qcode-discovery#2](https://github.com/qiskit-community/qcode-discovery/pull/2).

## Verify in one command (~2 minutes, Python 3.10+ and numpy)

    cd oneq-ibm-distance-closures-v1.0.1
    PYTHONPATH=. python verifiers/verify_closures.py

Expected: `6/6 closures fully re-verified ... 6/6 PROMOTABLE`.

## The Stranger Verification Challenge

`challenge/` contains the VALID bundle **and four deliberate forgeries**
(inflated bound, altered information set, substituted witness, downgraded
verifier). One command must accept the valid bundle and reject every forgery:

    cd challenge && ./verify.sh        # or .\verify.ps1

Tree-hash pin for the VALID bundle (compare against what the runner prints):

    8be84ab26ce280dd1852a9c062d74f0eff6914b62b51544d2d3e8d4986cb39a3

Run it, publish your unedited log, fill `challenge/ATTESTATION_TEMPLATE.json`.
An ambiguity report is as valuable as an attestation.

## What is and is not claimed

Upper bounds carry small inline witnesses (checkable in seconds). Lower bounds
are exhaustive-absence claims: re-executable with the included engine, but not
succinctly machine-checkable — see `LIMITATIONS.md` in the bundle. One closure
(`9_6_0172`) additionally has a separately implemented reproduction
(49,256,436,180 candidates re-enumerated across 582 shards).

## Licensing

* **Code** (verifiers, engine, tools): Apache License 2.0 — see `LICENSE`.
* **Evidence** (certificates, witnesses, reports): **CC-BY-4.0** — reuse
  freely **with attribution** to Coherence Energy Labs.
* Certificates are Ed25519-signed; issuer public keys are pinned in
  `oneq-ibm-distance-closures-v1.0.1/ISSUERS.json`. A signature proves
  authorship; the archive SHA-256 below proves integrity.

Archive SHA-256 (`oneq-ibm-distance-closures-v1.0.1.tar.gz`, attached to the
v1.0.1 release):

    ed04f1b10cd84869fa056c6e25d5dc2e3a8d9a663a1b8fd6489dcf58bd4e7add

Cite via `CITATION.cff`.
