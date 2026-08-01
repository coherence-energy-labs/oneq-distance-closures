#!/bin/sh
# ONE-Q stranger verification -- one command, no arguments.
# ACCEPT = fully re-verified AND all-PROMOTABLE (parsed from output; the
# verifier exit code alone carries only the first).
#
# 2026-08-01 -- THIS SCRIPT FAILED OPEN. Read this before editing it.
#
# Line 6 was `python verifiers/verify_closures.py`. On any machine without a bare
# `python` on PATH -- macOS, most modern Linux, git-bash on Windows -- that printed
# "python: command not found" and run_bundle returned false. For the VALID bundle
# that looked like a plain failure. For the SEVEN FORGERIES it was read as
# "the verifier refused this one", and the report proudly declared
#
#     "forgery_..._rejected": true      x7
#
# while the verifier had not executed a single time. A stranger running the public
# challenge saw seven green rejections produced by an interpreter that was missing.
# That is the exact failure this artifact exists to disprove, sitting inside the
# artifact itself.
#
# THE STRUCTURAL FIX: "refused" and "could not run" are different facts and must
# never share a return value. run_bundle now returns 0 accepted / 1 refused /
# 2 DID NOT RUN, and a 2 aborts the whole challenge instead of scoring anything.
# A result nobody computed is not a result.

# Resolve an interpreter once, and say so out loud if there is none. Bare `python`
# is not a portable assumption; `python3` is the one a stranger is likely to have.
PY=""
for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
done
if [ -z "$PY" ]; then
    echo "FATAL: no python3 or python on PATH. The challenge cannot run, and a" >&2
    echo "challenge that cannot run must not print verdicts. Install Python 3 and" >&2
    echo "re-run. (This message exists because the previous version silently" >&2
    echo "reported all seven forgeries as rejected in exactly this situation.)" >&2
    exit 2
fi

# sha256sum is coreutils and is ABSENT on macOS, where the tool is `shasum -a 256`.
# Both print "<hash>  <name>", so `cut -d" " -f1` is unchanged and the CANON below
# is unaffected.
if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256; }
else
    echo "FATAL: neither sha256sum nor shasum on PATH; cannot compute the tree hash." >&2
    exit 2
fi

# 0 = accepted, 1 = refused by the verifier, 2 = the verifier DID NOT RUN.
run_bundle() {
    out=$(cd "$1" && PYTHONPATH=. "$PY" verifiers/verify_closures.py 2>&1)
    echo "$out"
    rv=$(echo "$out" | sed -n "s|^\([0-9]*\)/\([0-9]*\) closures fully re-verified.*|\1=\2|p")
    pm=$(echo "$out" | sed -n "s|^\([0-9]*\)/\([0-9]*\) PROMOTABLE.*|\1=\2|p")
    # The verifier always emits both summary lines. Neither present means it never
    # got far enough to have an opinion -- an import error, a missing interpreter, a
    # traceback. Reporting that as a refusal is what failed open.
    if [ -z "$rv" ] && [ -z "$pm" ]; then return 2; fi
    l=${rv%%=*}; r=${rv##*=}; lp=${pm%%=*}; rp=${pm##*=}
    [ -n "$rv" ] && [ "$l" = "$r" ] && [ -n "$pm" ] && [ "$lp" = "$rp" ]
}
abort_if_dead() {
    [ "$1" -eq 2 ] || return 0
    echo "" >&2
    echo "FATAL: the verifier did not RUN on '$2' -- no summary lines in its output." >&2
    echo "Nothing was verified, so nothing is being reported. This is an error, not" >&2
    echo "a rejection, and the difference is the whole point of the challenge." >&2
    exit 2
}
tree_hash() {
    # CANON (identical in the builder and verify.ps1): lines
    # "sha256hex<space>posix-relpath", bytewise-sorted by relpath, each line
    # newline-terminated; sha256 over the concatenation.
    (cd "$1" && find . -type f ! -path "*__pycache__*" ! -name "*.pyc" | sed "s|^[.]/||" | LC_ALL=C sort | while read -r f; do
        printf "%s %s\n" "$(sha256 < "$f" | cut -d" " -f1)" "$f"
    done) | sha256 | cut -d" " -f1
}
ok=1
# The pin's AUTHORITY is the public post; the local file is a convenience.
# A stranger overrides it:  PIN=<published-hash> ./verify.sh
pin=$(printf "%s" "${PIN:-$(cat RELEASE_PIN.txt 2>/dev/null)}" | tr -cd "0-9a-f")
echo "=== VALID bundle (must ACCEPT: verifier output AND tree hash == pin) ==="
th=$(tree_hash VALID)
run_bundle VALID; rc=$?
abort_if_dead "$rc" VALID
if [ "$rc" -eq 0 ] && [ -n "$pin" ] && [ "$th" = "$pin" ]; then v=true; else v=false; ok=0; fi
echo "VALID tree sha256: $th"
echo ">> Compare this hash to the pin in the PUBLIC POST (not this bundle):"
[ -f RELEASE_PIN.txt ] && echo ">> local RELEASE_PIN.txt says: $(cat RELEASE_PIN.txt) -- authority is the public post"
printf '{
  "VALID_accepted": %s,
  "VALID_tree_sha256": "%s"' "$v" "$th" > verification_report.json
for f in FORGERIES/*/; do
    name=$(basename "$f")
    echo "=== FORGERY $name (must REJECT) ==="
    # A forgery is rejected if the verifier's own output refuses it OR its
    # tree hash fails the pin. The floor-downgrade forgery is the reason the
    # second clause exists: a tampered verifier happily prints 6/6, and
    # NOTHING inside the bundle can catch that -- only the out-of-band pin.
    fh=$(tree_hash "$f")
    run_bundle "$f"; rc=$?
    abort_if_dead "$rc" "$name"
    if [ "$rc" -eq 0 ] && [ "$fh" = "$pin" ]; then r=false; ok=0; else r=true; fi
    printf ',
  "forgery_%s_rejected": %s' "$name" "$r" >> verification_report.json
done
printf '
}
' >> verification_report.json
cat verification_report.json
[ $ok -eq 1 ] && echo "CHALLENGE RESULT: ALL CHECKS AS EXPECTED" || echo "CHALLENGE RESULT: MISMATCH -- see report"
exit $((1 - ok))
