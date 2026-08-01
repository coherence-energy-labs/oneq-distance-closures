# ONE-Q stranger verification -- one command, no arguments.
# ACCEPT = fully re-verified AND all-PROMOTABLE. The verifier prints both; its
# exit code alone carries only the first, so the runner parses the second.
#
# 2026-08-01 -- THIS SCRIPT FAILED OPEN, in two independent ways. Read before editing.
#
# 1. THE CONFLATION (shared with verify.sh). Run-Bundle returned $false both when the
#    verifier REFUSED a bundle and when the verifier COULD NOT RUN. Line 42 read that
#    as "forgery rejected", so a missing interpreter or a broken verifier produced
#        "forgery_..._rejected": true
#    for every forgery while nothing had been verified. Demonstrated by breaking one
#    forgery's verifier: it was still reported rejected.
#
# 2. THE POWERSHELL TRAP, specific to this file. Run-Bundle did `Write-Output $out`
#    and then `return $bool`. A PowerShell function returns EVERYTHING written to the
#    pipeline, so the caller received a two-element array -- and a non-empty array is
#    truthy. `if ($vOut -and ...)` was therefore true no matter what the verifier said.
#    Diagnostic output must go to the HOST, never to the pipeline, in any function
#    whose return value is read.
#
# THE STRUCTURAL FIX: Run-Bundle returns exactly one integer -- 0 accepted,
# 1 refused, 2 DID NOT RUN -- and a 2 aborts the run. A result nobody computed is
# not a result.

$ErrorActionPreference = "Continue"

# Bare `python` is not a portable assumption. Resolve once, and refuse to print
# verdicts if there is no interpreter at all.
$script:PY = $null
foreach ($cand in @("python3", "python")) {
    $c = Get-Command $cand -ErrorAction SilentlyContinue
    if ($c) { $script:PY = $c.Source; break }
}
if (-not $script:PY) {
    Write-Error "FATAL: no python3 or python on PATH. The challenge cannot run, and a challenge that cannot run must not print verdicts. Install Python 3 and re-run."
    exit 2
}

function Run-Bundle($dir) {
    Push-Location $dir
    $env:PYTHONPATH = "."
    $out = & $script:PY verifiers/verify_closures.py 2>&1 | Out-String
    Pop-Location
    # Write-Host, NOT Write-Output. See note 2 above -- this line is why the old
    # version could never fail.
    Write-Host $out
    $rv = [regex]::Match($out, '(?m)^(\d+)/(\d+) closures fully re-verified')
    $pm = [regex]::Match($out, '(?m)^(\d+)/(\d+) PROMOTABLE')
    # The verifier always emits both summary lines. Neither present means it never
    # got far enough to have an opinion.
    if (-not $rv.Success -and -not $pm.Success) { return 2 }
    if ($rv.Success -and $pm.Success -and
        $rv.Groups[1].Value -eq $rv.Groups[2].Value -and
        $pm.Groups[1].Value -eq $pm.Groups[2].Value) { return 0 }
    return 1
}

function Abort-IfDead([int]$code, [string]$what) {
    if ($code -ne 2) { return }
    Write-Error "FATAL: the verifier did not RUN on '$what' -- no summary lines in its output. Nothing was verified, so nothing is being reported. This is an error, not a rejection, and the difference is the whole point of the challenge."
    exit 2
}

# BYTEWISE comparison of two paths, as UTF-8 bytes. This is what `LC_ALL=C sort`
# does and what the canon means by "bytewise-sorted".
#
# 2026-08-01: this file used `Sort-Object -Culture InvariantCulture`, which is a
# LINGUISTIC sort -- it folds case and weights punctuation, so `CLAIMS.json` sorted
# AFTER `certificates_lrat/...` where a bytewise sort puts it first (0x43 < 0x63).
# The file set was identical, 72 files both sides; the ORDER differed at 58 of 72
# positions, so the two runners computed different tree hashes for the same bytes.
# Every Windows stranger therefore saw VALID_accepted:false against a pin that was
# correct -- while the comment above claimed the canon was "identical in the builder
# and verify.sh". A canon that two implementations disagree on is not a canon, and
# this repository exists to make exactly that claim checkable.
function Compare-Utf8Bytes([string]$x, [string]$y) {
    $bx = [Text.Encoding]::UTF8.GetBytes($x)
    $by = [Text.Encoding]::UTF8.GetBytes($y)
    $n = [Math]::Min($bx.Length, $by.Length)
    for ($i = 0; $i -lt $n; $i++) {
        if ($bx[$i] -ne $by[$i]) { return [int]$bx[$i] - [int]$by[$i] }
    }
    return $bx.Length - $by.Length
}

function Tree-Hash($dir) {
    # CANON (identical in the builder and verify.sh): lines
    # "sha256hex<space>posix-relpath", bytewise-sorted by relpath, each line
    # newline-terminated; sha256 over the concatenation.
    $base = (Resolve-Path $dir).Path
    $rows = @(Get-ChildItem $base -Recurse -File -Force | Where-Object { $_.FullName -notmatch "__pycache__" -and $_.Extension -ne ".pyc" } | ForEach-Object {
        $rel = $_.FullName.Substring($base.Length + 1).Replace("\", "/")
        [pscustomobject]@{ Rel = $rel; Hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower() }
    })
    # -Force above so hidden files are included: `find` does not skip them, and a
    # file set that silently differs by platform is the same class of bug as the sort.
    [Array]::Sort($rows, [Comparison[object]] { param($a, $b) Compare-Utf8Bytes $a.Rel $b.Rel })
    $acc = ($rows | ForEach-Object { $_.Hash + " " + $_.Rel + "`n" }) -join ""
    $sha = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($acc))
    return ([BitConverter]::ToString($sha) -replace "-", "").ToLower()
}

$report = [ordered]@{}
if ($env:PIN) { $pinRaw = $env:PIN }
elseif (Test-Path RELEASE_PIN.txt) { $pinRaw = Get-Content RELEASE_PIN.txt -Raw }
else { $pinRaw = "" }
$pin = $pinRaw -replace "[^0-9a-f]", ""

Write-Output "=== VALID bundle (must ACCEPT: verifier output AND tree hash == pin) ==="
$vCode = Run-Bundle (Resolve-Path VALID)
Abort-IfDead $vCode "VALID"
$th = Tree-Hash (Resolve-Path VALID)
$report["VALID_accepted"] = (($vCode -eq 0) -and [bool]$pin -and ($th -eq $pin))
$report["VALID_tree_sha256"] = $th
Write-Output "VALID tree sha256: $th"
Write-Output ">> Compare this hash to the pin in the PUBLIC POST (not this bundle):"
if (Test-Path RELEASE_PIN.txt) { Write-Output (">> local RELEASE_PIN.txt says: " + (Get-Content RELEASE_PIN.txt -Raw).Trim() + " -- authority is the public post") }

foreach ($f in Get-ChildItem FORGERIES -Directory) {
    Write-Output "=== FORGERY $($f.Name) (must REJECT) ==="
    $fCode = Run-Bundle $f.FullName
    Abort-IfDead $fCode $f.Name
    $fh = Tree-Hash $f.FullName
    # Rejected if the verifier refused it OR its tree hash fails the pin. The
    # floor-downgrade forgery is why the second clause exists: a tampered verifier
    # happily prints 6/6, and only the out-of-band pin catches that.
    $report["forgery_$($f.Name)_rejected"] = -not (($fCode -eq 0) -and ($fh -eq $pin))
}

$report | ConvertTo-Json | Tee-Object -FilePath verification_report.json
$vals = @($report.Values | Where-Object { $_ -is [bool] })
$ok = ($vals | Where-Object { -not $_ }).Count -eq 0
Write-Output ("CHALLENGE RESULT: " + $(if ($ok) { "ALL CHECKS AS EXPECTED" } else { "MISMATCH -- see report" }))
exit $(if ($ok) { 0 } else { 1 })
