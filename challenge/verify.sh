#!/bin/sh
# ONE-Q stranger verification -- one command, no arguments.
# ACCEPT = fully re-verified AND all-PROMOTABLE (parsed from output; the
# verifier exit code alone carries only the first).
run_bundle() {
    out=$(cd "$1" && PYTHONPATH=. python verifiers/verify_closures.py 2>&1)
    echo "$out"
    rv=$(echo "$out" | sed -n "s|^\([0-9]*\)/\([0-9]*\) closures fully re-verified.*|\1=\2|p")
    pm=$(echo "$out" | sed -n "s|^\([0-9]*\)/\([0-9]*\) PROMOTABLE.*|\1=\2|p")
    l=${rv%%=*}; r=${rv##*=}; lp=${pm%%=*}; rp=${pm##*=}
    [ -n "$rv" ] && [ "$l" = "$r" ] && [ -n "$pm" ] && [ "$lp" = "$rp" ]
}
tree_hash() {
    # CANON (identical in the builder and verify.ps1): lines
    # "sha256hex<space>posix-relpath", bytewise-sorted by relpath, each line
    # newline-terminated; sha256 over the concatenation.
    (cd "$1" && find . -type f ! -path "*__pycache__*" ! -name "*.pyc" | sed "s|^[.]/||" | LC_ALL=C sort | while read -r f; do
        printf "%s %s\n" "$(sha256sum "$f" | cut -d" " -f1)" "$f"
    done) | sha256sum | cut -d" " -f1
}
ok=1
# The pin's AUTHORITY is the public post; the local file is a convenience.
# A stranger overrides it:  PIN=<published-hash> ./verify.sh
pin="${PIN:-$(cat RELEASE_PIN.txt 2>/dev/null)}"
echo "=== VALID bundle (must ACCEPT: verifier output AND tree hash == pin) ==="
th=$(tree_hash VALID)
if run_bundle VALID && [ -n "$pin" ] && [ "$th" = "$pin" ]; then v=true; else v=false; ok=0; fi
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
    if run_bundle "$f" && [ "$fh" = "$pin" ]; then r=false; ok=0; else r=true; fi
    printf ',
  "forgery_%s_rejected": %s' "$name" "$r" >> verification_report.json
done
printf '
}
' >> verification_report.json
cat verification_report.json
[ $ok -eq 1 ] && echo "CHALLENGE RESULT: ALL CHECKS AS EXPECTED" || echo "CHALLENGE RESULT: MISMATCH -- see report"
exit $((1 - ok))
