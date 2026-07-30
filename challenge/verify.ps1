# ONE-Q stranger verification -- one command, no arguments.
# ACCEPT = fully re-verified AND all-PROMOTABLE. The verifier prints both; its
# exit code alone carries only the first, so the runner parses the second.
$ErrorActionPreference = "Continue"
function Run-Bundle($dir) {
    Push-Location $dir
    $env:PYTHONPATH = "."
    $out = python verifiers/verify_closures.py 2>&1 | Out-String
    Pop-Location
    $reverified = $out -match "(\d+)/(\d+) closures fully re-verified" -and $Matches[1] -eq $Matches[2]
    $promotable = $out -match "(\d+)/(\d+) PROMOTABLE" -and $Matches[1] -eq $Matches[2]
    Write-Output $out
    return ($reverified -and $promotable)
}
function Tree-Hash($dir) {
    # CANON (identical in the builder and verify.sh): lines
    # "sha256hex<space>posix-relpath", bytewise-sorted by relpath, each line
    # newline-terminated; sha256 over the concatenation.
    $base = (Resolve-Path $dir).Path
    $rows = Get-ChildItem $base -Recurse -File | Where-Object { $_.FullName -notmatch "__pycache__" -and $_.Extension -ne ".pyc" } | ForEach-Object {
        $rel = $_.FullName.Substring($base.Length + 1).Replace("\", "/")
        [pscustomobject]@{ Rel = $rel; Hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower() }
    } | Sort-Object { $_.Rel } -Culture ([cultureinfo]::InvariantCulture)
    $acc = ($rows | ForEach-Object { $_.Hash + " " + $_.Rel + "`n" }) -join ""
    $sha = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($acc))
    return ([BitConverter]::ToString($sha) -replace "-", "").ToLower()
}
$report = [ordered]@{}
$pin = if ($env:PIN) { $env:PIN } elseif (Test-Path RELEASE_PIN.txt) { (Get-Content RELEASE_PIN.txt -Raw).Trim() } else { "" }
Write-Output "=== VALID bundle (must ACCEPT: verifier output AND tree hash == pin) ==="
$vOut = Run-Bundle (Resolve-Path VALID)
$th = Tree-Hash (Resolve-Path VALID)
$report["VALID_accepted"] = ($vOut -and $pin -and ($th -eq $pin))
$report["VALID_tree_sha256"] = $th
Write-Output "VALID tree sha256: $th"
Write-Output ">> Compare this hash to the pin in the PUBLIC POST (not this bundle):"
if (Test-Path RELEASE_PIN.txt) { Write-Output (">> local RELEASE_PIN.txt says: " + (Get-Content RELEASE_PIN.txt -Raw).Trim() + " -- authority is the public post") }
foreach ($f in Get-ChildItem FORGERIES -Directory) {
    Write-Output "=== FORGERY $($f.Name) (must REJECT) ==="
    $fOut = Run-Bundle $f.FullName
    $fh = Tree-Hash $f.FullName
    $report["forgery_$($f.Name)_rejected"] = -not ($fOut -and ($fh -eq $pin))
}
$report | ConvertTo-Json | Tee-Object -FilePath verification_report.json
$vals = @($report.Values | Where-Object { $_ -is [bool] })
$ok = ($vals | Where-Object { -not $_ }).Count -eq 0
Write-Output ("CHALLENGE RESULT: " + $(if ($ok) { "ALL CHECKS AS EXPECTED" } else { "MISMATCH -- see report" }))
exit $(if ($ok) { 0 } else { 1 })
