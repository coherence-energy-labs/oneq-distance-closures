# Erratum — the challenge runner could report "rejected" without running anything

**Dated 2026-08-01. Affects `verify.sh` and `verify.ps1` in this directory, from
first publication until this commit. It does not affect the evidence bundles, the
forgeries, or the pin.**

## The defect

`verify.sh` invoked the verifier as `python verifiers/verify_closures.py`. A bare
`python` does not exist on macOS, on most current Linux distributions, or in
git-bash on Windows — those provide `python3`. On any such machine the command
printed `python: command not found`, and the runner's `run_bundle` returned false.

For the seven forgeries, false was read as **"the verifier refused this bundle."**
The report therefore said:

```json
"forgery_altered_information_set_rejected": true,
... seven of these ...
```

while the verifier had not executed a single time.

The cause is a conflation, not a typo: **"refused" and "could not run" shared one
return value.** A challenge whose entire purpose is to demonstrate that a
verification cannot be faked was, in that situation, printing seven verifications
that had not happened.

`verify.ps1` had the same conflation plus a second, independent fault: `Run-Bundle`
wrote its diagnostic output to the pipeline with `Write-Output` and then returned a
boolean. A PowerShell function returns everything written to the pipeline, so the
caller received a two-element array — and a non-empty array is always truthy. That
branch could not evaluate false regardless of what the verifier reported.

A third fault made the two runners disagree. Both files carry the comment
*"CANON … bytewise-sorted by relpath"*, but `verify.ps1` sorted with
`-Culture InvariantCulture`, a linguistic sort that folds case and weights
punctuation. Measured on this release: identical file sets, 72 files on each side,
with the order differing at **58 of 72 positions** — `CLAIMS.json` sorts before
`certificates_lrat/…` bytewise (`0x43 < 0x63`) and after it linguistically. Windows
users computed a different tree hash than POSIX users for identical bytes and had no
way to tell a runner bug from a genuine mismatch.

`verify.sh` also called `sha256sum`, which is coreutils and is absent on macOS.

## What was NOT wrong

State this plainly, because an erratum that overstates its own scope is its own kind
of error.

- **The published results are correct.** Re-running the fixed runner against these
  bundles reproduces `verification_report.json` **byte for byte**: VALID accepted,
  all seven forgeries rejected.
- **The pin is correct.** `ba95807b427d79311918e1f26ee8bf796f3770f4cb2ed885e388ad2046132881`
  is unchanged and was reproduced by both fixed runners.
- **The bundles and the forgeries are untouched.** No evidence file changed. The
  runners live beside `VALID/`, not inside it, so the tree hash never covered them.

The damage was to *reproducibility*, not to the claims: a stranger's confirmation
could not be distinguished from a stranger's broken environment, which makes the
confirmation worthless as evidence even when the underlying result is true.

## Were you affected?

If you ran the challenge and saw `python: command not found`, or saw
`VALID_accepted: false` while your printed tree hash equalled the pin above, you hit
this. Re-run with the corrected scripts. Nothing else on your side needs to change.

## What changed

- `run_bundle` / `Run-Bundle` now return **0 accepted, 1 refused, 2 did-not-run**,
  and a 2 **aborts the entire challenge** without writing a verdict. A result nobody
  computed is not a result.
- The interpreter is resolved once (`python3`, then `python`) and its absence is a
  fatal, explicit error rather than seven silent passes.
- `sha256sum` falls back to `shasum -a 256`. Both print `<hash>  <name>`, so the
  canon is unaffected.
- `verify.ps1` compares paths as **UTF-8 bytes** explicitly, writes diagnostics with
  `Write-Host`, and passes `-Force` to `Get-ChildItem` so hidden files are included
  the way `find` includes them. Both runners now emit identical reports.

Verified in both directions before publishing: the intact bundles pass on both
runners with matching hashes, and replacing one forgery's verifier with a stub that
exits non-zero now aborts with exit 2 on both runners, where the previous version
reported that forgery as rejected.
