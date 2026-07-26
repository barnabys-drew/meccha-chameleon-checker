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
