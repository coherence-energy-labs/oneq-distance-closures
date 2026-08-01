# ONE-Q Stranger Verification Challenge

You are the control group. We claim the verifier accepts the VALID
release and rejects all **seven** FORGERIES. Do not trust us: run it.

    ./verify.sh          # or .\verify.ps1 on Windows

Requires Python 3.10+ and numpy (`pip install numpy`). ~2 minutes.
The runner resolves `python3` before `python`; if neither exists it
stops with a fatal error rather than printing verdicts.

Then: publish your UNEDITED log, fill ATTESTATION_TEMPLATE.json,
sign it with any key you control, and report anything ambiguous —
an ambiguity report is as valuable as the attestation.

What each forgery is (spoilers): FORGERIES/WHAT_EACH_FORGERY_IS.json

## Read this if you ran the challenge before 2026-08-01

**[ERRATUM_RUNNER_FAILED_OPEN.md](ERRATUM_RUNNER_FAILED_OPEN.md)** — the runner
could report all seven forgeries as "rejected" without having executed the verifier
at all, on any machine lacking a bare `python` (macOS, most current Linux,
git-bash). The evidence bundles, the forgeries and the pin were never affected, and
the published results reproduce byte-for-byte under the fixed runner. But a
confirmation produced by the old script could not be distinguished from a broken
environment, so if you attested on it, please re-run and re-attest.

This README also said "all four FORGERIES" while seven shipped. Corrected above.

The three ways a verification can be wrong are: it accepts a forgery, it refuses a
good artifact, or **it reports either without having run**. The third is the one
that looks like success, and it is the one we shipped.
