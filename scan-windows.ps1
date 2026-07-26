<#
    Meccha Chameleon Workshop malware checker -- Windows scanner.

    Looks for the known indicators of the July 2026 Meccha Chameleon Steam
    Workshop dropper campaign. Read-only: this script never deletes, moves or
    modifies anything on your system.

    Exit codes:  0 = no known indicators found
                 1 = one or more indicators found
                 2 = the scan could not run properly
#>

[CmdletBinding()]
param(
    [string]$ScanRoot,
    [string]$Indicators,
    [switch]$NoColor
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Indicators) { $Indicators = Join-Path $ScriptDir 'indicators.json' }

$script:ReportLines  = New-Object System.Collections.Generic.List[string]
$script:FoundCount   = 0
$script:SuspectCount = 0

function Say {
    param([string]$Text, [string]$Color)
    $script:ReportLines.Add($Text)
    if ($NoColor -or -not $Color) { Write-Host $Text }
    else { Write-Host $Text -ForegroundColor $Color }
}

function Add-Finding {
    param([ValidateSet('FOUND','SUSPICIOUS')][string]$Severity, [string]$What, [string]$Where)
    if ($Severity -eq 'FOUND') {
        $script:FoundCount++
        Say "  [FOUND]      $What" 'Red'
    } else {
        $script:SuspectCount++
        Say "  [SUSPICIOUS] $What" 'Yellow'
    }
    Say "               $Where" 'DarkGray'
}

# ------------------------------------------------------------ indicator load
#
# If the indicator list fails to load we abort with exit 2. A scanner that
# silently lost its indicators would report "nothing found" on an infected
# machine, which is the single worst thing this tool could do.

if (-not (Test-Path -LiteralPath $Indicators)) {
    Write-Error "Cannot read indicators file: $Indicators"
    exit 2
}
try {
    $ioc = Get-Content -LiteralPath $Indicators -Raw -ErrorAction Stop | ConvertFrom-Json
} catch {
    Write-Error "Could not parse $Indicators -- refusing to report a misleading 'clean' result."
    exit 2
}

$AppId       = [string]$ioc.steam_appid
$BadIds      = @($ioc.malicious_workshop_ids | ForEach-Object { [string]$_.id })
$BadHashes   = @($ioc.file_hashes_sha256.PSObject.Properties.Name) | ForEach-Object { $_.ToLower() }
$BadStrings  = @($ioc.content_strings)
$DropNames   = @($ioc.dropped_filenames)

if (-not $AppId -or $BadHashes.Count -eq 0 -or $BadStrings.Count -eq 0) {
    Write-Error "Indicator file is missing required fields -- refusing to report a misleading 'clean' result."
    exit 2
}

# Does a file contain a marker, as plain text or as UTF-16?
# Read in chunks with an overlap so large .pak files do not blow up memory and
# markers spanning a chunk boundary are still caught. Removing 0x00 bytes turns
# UTF-16LE text into plain text, so one pass covers both encodings.
function Test-ContainsMarker {
    param([string]$Path, [string[]]$Markers)
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    } catch { return $null }
    try {
        $chunk   = New-Object byte[] (4MB)
        $overlap = 256
        $tail    = ''
        while (($read = $fs.Read($chunk, 0, $chunk.Length)) -gt 0) {
            $text = [System.Text.Encoding]::GetEncoding(28591).GetString($chunk, 0, $read)
            $hay  = $tail + $text
            $flat = $hay -replace "`0", ''
            foreach ($m in $Markers) {
                if ($hay.Contains($m) -or $flat.Contains($m)) { return $m }
            }
            $tail = if ($hay.Length -gt $overlap) { $hay.Substring($hay.Length - $overlap) } else { $hay }
        }
    } catch { return $null } finally { $fs.Dispose() }
    return $null
}

# Bounded breadth-first hunt for a "steamapps" folder, returning its parent.
#
# Deliberately not Get-ChildItem -Recurse: that walks the entire drive before
# the depth limit is applied, which takes minutes on a real disk. This stops at
# MaxDepth and skips the big system folders, none of which ever hold a Steam
# library. Keeps a whole-machine scan down to a few seconds.
function Find-SteamAppsDir {
    param([string]$Root, [int]$MaxDepth = 3)

    $skip = @('windows','$recycle.bin','system volume information','appdata',
              'programdata','windowsapps','node_modules','.git','.cache',
              'msocache','perflogs','recovery','onedrivetemp')
    $results  = New-Object System.Collections.Generic.List[string]
    $frontier = @($Root)

    for ($depth = 0; $depth -lt $MaxDepth -and $frontier.Count -gt 0 -and $results.Count -lt 40; $depth++) {
        $next = New-Object System.Collections.Generic.List[string]
        foreach ($dir in $frontier) {
            $kids = $null
            try { $kids = Get-ChildItem -LiteralPath $dir -Directory -Force -ErrorAction SilentlyContinue } catch { continue }
            foreach ($k in $kids) {
                if ($skip -contains $k.Name.ToLower()) { continue }
                if ($k.Name -ieq 'steamapps') { $results.Add($k.Parent.FullName); continue }
                $next.Add($k.FullName)
            }
        }
        $frontier = $next
    }
    return $results
}

# --------------------------------------------------------------------- banner

Say ''
Say '  Meccha Chameleon Workshop malware checker' 'White'
Say '  Read-only. This tool changes nothing on your computer.' 'DarkGray'
Say "  Indicators updated: $($ioc.updated)" 'DarkGray'
Say ''

# ------------------------------------------------------- locate steam / homes

$SteamRoots = New-Object System.Collections.Generic.List[string]
$Synthetic  = [bool]$ScanRoot

if ($Synthetic) {
    $HomeDir = Join-Path $ScanRoot 'home'
    $sr = Join-Path $ScanRoot 'steamroot'
    if (Test-Path -LiteralPath $sr) { $SteamRoots.Add($sr) }
} else {
    $HomeDir = $env:USERPROFILE

    # (a) Where Steam says it is.
    foreach ($rk in @(
        @{ Path = 'HKCU:\Software\Valve\Steam';                 Name = 'SteamPath' },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Valve\Steam';     Name = 'InstallPath' },
        @{ Path = 'HKLM:\SOFTWARE\Valve\Steam';                 Name = 'InstallPath' }
    )) {
        try {
            $v = (Get-ItemProperty -LiteralPath $rk.Path -Name $rk.Name -ErrorAction Stop).($rk.Name)
            if ($v) { $SteamRoots.Add(($v -replace '/','\')) }
        } catch { }
    }
    foreach ($d in @("${env:ProgramFiles(x86)}\Steam", "$env:ProgramFiles\Steam")) {
        if (Test-Path -LiteralPath (Join-Path $d 'steamapps')) { $SteamRoots.Add($d) }
    }

    # (b) Extra libraries Steam has on record.
    foreach ($root in @($SteamRoots)) {
        foreach ($vdf in @("$root\steamapps\libraryfolders.vdf", "$root\config\libraryfolders.vdf")) {
            if (-not (Test-Path -LiteralPath $vdf)) { continue }
            foreach ($line in (Get-Content -LiteralPath $vdf -ErrorAction SilentlyContinue)) {
                if ($line -match '"path"\s+"([^"]+)"') {
                    $p = $Matches[1] -replace '\\\\','\'
                    if (Test-Path -LiteralPath (Join-Path $p 'steamapps')) { $SteamRoots.Add($p) }
                }
            }
        }
    }

    # (c) Every drive on the machine.
    #
    # libraryfolders.vdf only lists libraries Steam currently knows about. A
    # drive that was disconnected, re-lettered, or whose library was removed
    # from Steam can still hold an infected map on disk, so we look at the
    # drives themselves rather than trusting Steam's own bookkeeping.
    $drives = @()
    try {
        $drives += (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
                    Where-Object { $_.Root -match '^[A-Za-z]:\\' } | ForEach-Object { $_.Root })
    } catch { }
    try {
        $drives += (Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction SilentlyContinue |
                    Where-Object { $_.DriveType -in 2,3,4,6 } | ForEach-Object { "$($_.DeviceID)\" })
    } catch { }
    $drives = $drives | Sort-Object -Unique
    Write-Host '  Searching all drives for Steam libraries...' -ForegroundColor DarkGray

    foreach ($dr in $drives) {
        foreach ($sub in @('SteamLibrary','Steam','Games\SteamLibrary','Games\Steam',
                           'Program Files (x86)\Steam','Program Files\Steam','')) {
            $cand = if ($sub) { Join-Path $dr $sub } else { $dr }
            if (Test-Path -LiteralPath (Join-Path $cand 'steamapps')) { $SteamRoots.Add($cand) }
        }
        # Depth-limited sweep for libraries in places we did not guess.
        foreach ($hit in (Find-SteamAppsDir -Root $dr -MaxDepth 3)) { $SteamRoots.Add($hit) }
    }
}

$SteamRoots = @($SteamRoots | Where-Object { $_ } | Sort-Object -Unique)

if ($SteamRoots.Count -eq 0) {
    Say '  No Steam installation found on any drive.' 'Yellow'
    Say '  The Workshop checks below were skipped -- this is not a clean result.' 'DarkGray'
    Say ''
} else {
    foreach ($r in $SteamRoots) { Say "  Steam library: $r" 'DarkGray' }
    Say ''
}

# ----------------------------------------------- checks 2+3+4: workshop maps

Say '  Checking your subscribed Workshop maps...' 'White'

$mapsSeen = 0
foreach ($root in $SteamRoots) {
    $content = Join-Path $root "steamapps\workshop\content\$AppId"
    if (-not (Test-Path -LiteralPath $content)) { continue }

    foreach ($item in (Get-ChildItem -LiteralPath $content -Directory -ErrorAction SilentlyContinue)) {
        $mapsSeen++

        # Check 2: known-bad Workshop ID
        if ($BadIds -contains $item.Name) {
            Add-Finding FOUND "Known malicious Workshop map is installed (ID $($item.Name))" $item.FullName
        }

        # Checks 3 and 4: hash and scan the Unreal asset containers
        $paks = Get-ChildItem -LiteralPath $item.FullName -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match '^\.(pak|utoc|ucas)$' }
        foreach ($pak in $paks) {
            try {
                $h = (Get-FileHash -LiteralPath $pak.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
                if ($BadHashes -contains $h) {
                    Add-Finding FOUND 'Map file matches a known malicious file exactly' $pak.FullName
                }
            } catch { }
            $hit = Test-ContainsMarker -Path $pak.FullName -Markers $BadStrings
            if ($hit) {
                Add-Finding SUSPICIOUS "Map file contains a known malware marker (`"$hit`")" $pak.FullName
            }
        }
    }
}

if ($mapsSeen -eq 0) { Say '  No Meccha Chameleon Workshop maps are installed.' 'Green' }
else                 { Say "  Examined $mapsSeen installed map(s)." 'DarkGray' }
Say ''

# ------------------------------------------------------ check 5: dropped s.bat

Say "  Checking for files the malware drops..." 'White'

$dropDirs = New-Object System.Collections.Generic.List[string]
if ($Synthetic) {
    $dropDirs.Add((Join-Path $HomeDir 'Documents'))
} else {
    # GetFolderPath follows OneDrive's Documents redirection; the literal
    # profile path is checked too in case only one of them exists.
    try { $dropDirs.Add([Environment]::GetFolderPath('MyDocuments')) } catch { }
    $dropDirs.Add("$env:USERPROFILE\Documents")
    $dropDirs.Add("$env:USERPROFILE\OneDrive\Documents")
    $dropDirs.Add($env:TEMP)
}
$dropDirs = @($dropDirs | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Sort-Object -Unique)

foreach ($d in $dropDirs) {
    foreach ($name in $DropNames) {
        $f = Join-Path $d $name
        if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { continue }
        $matched = $false
        try {
            $h = (Get-FileHash -LiteralPath $f -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
            if ($BadHashes -contains $h) {
                Add-Finding FOUND "The malware's dropper file is on this system" $f
                $matched = $true
            }
        } catch { }
        if (-not $matched) {
            Add-Finding SUSPICIOUS "A file named '$name' is here, where the malware drops its file" $f
        }
    }

    # Renamed variants: any .bat/.cmd carrying a known marker
    $scripts = Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue |
               Where-Object { $_.Extension -match '^\.(bat|cmd)$' -and $DropNames -notcontains $_.Name }
    foreach ($s in $scripts) {
        $hit = Test-ContainsMarker -Path $s.FullName -Markers $BadStrings
        if ($hit) {
            Add-Finding FOUND "A script here contains a known malware marker (`"$hit`")" $s.FullName
        }
    }
}
Say '  Checked your Documents folder (including OneDrive) and the temp folder.' 'DarkGray'
Say ''

# --------------------------------------------------------- check 6: persistence

Say '  Checking for leftover startup entries...' 'White'

$persistNeedles = @($DropNames) + @('steamb.bat') + @($BadStrings) | Sort-Object -Unique

if (-not $Synthetic) {
    foreach ($key in @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )) {
        try {
            $props = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
        } catch { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            foreach ($n in $persistNeedles) {
                if ([string]$p.Value -like "*$n*") {
                    Add-Finding FOUND "A startup entry refers to the malware (`"$n`")" "$key -> $($p.Name)"
                    break
                }
            }
        }
    }

    try {
        $tasks = schtasks /query /fo csv /v 2>$null
        foreach ($n in $persistNeedles) {
            if ($tasks -and ($tasks -join "`n") -like "*$n*") {
                Add-Finding FOUND "A scheduled task refers to the malware (`"$n`")" 'Windows Task Scheduler'
                break
            }
        }
    } catch { }
}

$startupDirs = if ($Synthetic) { @(Join-Path $HomeDir 'Startup') } else {
    @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
      "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
}
foreach ($sd in $startupDirs) {
    if (-not (Test-Path -LiteralPath $sd)) { continue }
    foreach ($f in (Get-ChildItem -LiteralPath $sd -File -ErrorAction SilentlyContinue)) {
        $hit = Test-ContainsMarker -Path $f.FullName -Markers $persistNeedles
        if ($hit) { Add-Finding FOUND "A startup file refers to the malware (`"$hit`")" $f.FullName }
        elseif ($DropNames -contains $f.Name) {
            Add-Finding FOUND "The malware's file is set to run at startup" $f.FullName
        }
    }
}
Say '  Checked startup entries, the Startup folder and scheduled tasks.' 'DarkGray'
Say ''

# ------------------------------------------------------------------- verdict

Say '  --------------------------------------------------------------' 'DarkGray'
Say ''

$exitCode = 0
if ($script:FoundCount -gt 0 -or $script:SuspectCount -gt 0) {
    $exitCode = 1
    Say '  Something was found. Please read this carefully.' 'Red'
    Say ''
    Say "  Confirmed indicators: $($script:FoundCount)      Suspicious: $($script:SuspectCount)"
    Say ''
    Say '  This tool has changed nothing. Nothing was deleted or moved.'
    Say ''
    Say '  What to do next, in this order:'
    Say ''
    Say '   1. Disconnect this computer from the internet.'
    Say '   2. Do NOT delete the files listed above yet. They are evidence, and'
    Say '      deleting them does not remove the second stage of this malware.'
    Say '   3. Run a full offline scan with Microsoft Defender or Malwarebytes.'
    Say '   4. From a DIFFERENT device, change your important passwords: email'
    Say '      first, then Steam, Discord, and anything reusing those passwords.'
    Say '   5. From that other device, sign out of all sessions on Steam and'
    Say '      Discord, then turn two-factor authentication off and back on.'
    Say '      The attackers behind this campaign bypassed a victim''s Discord 2FA.'
    Say '   6. Unsubscribe from the map in the Steam Workshop, and make sure'
    Say '      Meccha Chameleon is updated to version 3.2.0 or later.'
    Say ''
} else {
    Say '  No known indicators of this malware were found.' 'Green'
    Say ''
    Say '  What this DOES mean: none of the malicious maps, files or startup'
    Say '  entries that researchers have identified so far are on this system.'
    Say ''
    Say '  What this does NOT mean: it is not proof that you are clean. The'
    Say '  second stage of this attack was never captured by researchers, so'
    Say '  nobody publicly knows exactly what it installs or what traces it'
    Say '  leaves behind. This tool cannot look for something nobody has seen.'
    Say ''
    Say '  If you saw a black command window flash while loading a custom map,'
    Say '  treat this result with suspicion: run a full antivirus scan and change'
    Say '  your passwords from a different device anyway.'
    Say ''
}

# --------------------------------------------------------------- report file

$reportDir = $ScriptDir
try { [System.IO.File]::WriteAllText((Join-Path $reportDir '.wtest'), 'x'); Remove-Item (Join-Path $reportDir '.wtest') -Force }
catch { $reportDir = $env:USERPROFILE }

$reportFile = Join-Path $reportDir ("meccha-check-report-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$header = @(
    'Meccha Chameleon Workshop malware checker',
    "Scan date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
    "Host: $env:COMPUTERNAME",
    "Result: $(if ($exitCode -eq 0) { 'no known indicators found' } else { 'INDICATORS FOUND' })",
    ''
)
try {
    Set-Content -LiteralPath $reportFile -Value ($header + $script:ReportLines) -Encoding UTF8
    Write-Host "  A copy of this report was saved to:" -ForegroundColor DarkGray
    Write-Host "  $reportFile`n" -ForegroundColor DarkGray
} catch { }

exit $exitCode
