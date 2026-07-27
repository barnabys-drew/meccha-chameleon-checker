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
    [switch]$NoColor,
    [switch]$Deep
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Indicators) { $Indicators = Join-Path $ScriptDir 'indicators.json' }

$script:ReportLines  = New-Object System.Collections.Generic.List[string]
$script:FoundCount   = 0
$script:SuspectCount = 0
$script:NoteCount    = 0

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

# A third tier, used only by -Deep. These are behaviour patterns, not known
# indicators: they describe something that LOOKS like how this malware works,
# which an innocent file can also do. Kept separate from the Found/Suspect
# counts so behaviour alone never reads as "you are infected".
function Add-Note {
    param([string]$What, [string]$Where)
    $script:NoteCount++
    Say "  [WORTH A LOOK] $What" 'Cyan'
    Say "                 $Where" 'DarkGray'
}

# Observations too weak to alarm anyone with on their own -- "you have a .bat
# file in Documents" is true of plenty of innocent machines. Shown as context,
# deliberately NOT counted toward the verdict or the exit code: six cyan alerts
# on a clean PC teaches people to ignore the alerts that matter.
$script:InfoLines = New-Object System.Collections.Generic.List[string]
function Add-Info { param([string]$Path) $script:InfoLines.Add($Path) }

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

# -------------------------------------------------- -Deep: behaviour checks
#
# Everything above matches indicators researchers have published. Those are
# exact, but they are also the easiest thing in the world for the attacker to
# change -- a recompiled map with a new server address defeats all of it.
#
# The checks below describe how this malware BEHAVES instead, so they can catch
# a repackaged copy nobody has catalogued. The trade-off is that innocent files
# can behave the same way, which is why they report as "worth a look" and never
# as a confirmed finding.

if ($Deep) {
    Say '  Deep scan: looking for suspicious behaviour...' 'White'

    $BehavMinScore = 6       # total weight needed to report a file
    $BehavMinCats  = 2       # ...in at least this many different categories
    $BehavMaxBytes = 524288  # only analyse the first 512 KB of any script

    # Rules live in behaviour-rules.tsv so both scanners share one definition.
    # Losing them must not silently turn the deep scan into a no-op.
    $rulesFile = Join-Path $ScriptDir 'behaviour-rules.tsv'
    $BehavRules = @()
    if (Test-Path -LiteralPath $rulesFile) {
        foreach ($line in (Get-Content -LiteralPath $rulesFile -ErrorAction SilentlyContinue)) {
            if ($line -match '^\s*(#|$)') { continue }
            $parts = $line -split "`t"
            if ($parts.Count -lt 4) { continue }
            $BehavRules += [pscustomobject]@{
                Weight = [int]$parts[0]; Category = $parts[1]
                Regex  = $parts[2];      Description = $parts[3]
            }
        }
    }
    if ($BehavRules.Count -lt 5) {
        Write-Error "-Deep needs behaviour-rules.tsv, which is missing or unreadable: $rulesFile"
        Write-Error "Refusing to report 'nothing suspicious' from a scan that could not run."
        exit 2
    }

    $execExt = '^\.(bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|hta)$'
    $oddExt  = '^\.(bat|cmd|vbs|js|wsf|hta|scr|pif|lnk)$'
    $behavSeen = @{}

    # ---- de-obfuscation ---------------------------------------------------
    # Attackers break up their own command names so a literal search misses
    # them: caret escapes in batch, backticks in PowerShell, quote-splitting.
    # We score twice -- as written, and with the tricks undone -- and keep the
    # higher result. The obfuscation itself is scored too, since nothing
    # legitimate needs to disguise its own commands.
    function Get-Deobfuscated {
        param([string]$Text)
        ($Text -replace '\^','' -replace '`','' `
               -replace "'[ \t]*\+[ \t]*'",'' -replace '"[ \t]*\+[ \t]*"','' `
               -replace '[ \t]+',' ')
    }

    # PowerShell -EncodedCommand payloads are UTF-16LE base64. Decode any long
    # base64 run so a fully encoded dropper is scored on what it actually does,
    # not merely on the fact that it is encoded. Must run against the
    # case-preserved text: base64 is case-sensitive, and decoding lowercased
    # input silently yields nothing.
    function Get-DecodedBase64 {
        param([string]$Raw)
        $out = New-Object System.Text.StringBuilder
        $n = 0
        foreach ($m in [regex]::Matches($Raw, '[A-Za-z0-9+/]{40,}={0,2}')) {
            if ($n -ge 20) { break }
            $n++
            $s = $m.Value
            $s = $s.Substring(0, $s.Length - ($s.Length % 4))
            if ($s.Length -lt 4) { continue }
            try {
                $bytes = [Convert]::FromBase64String($s)
                [void]$out.AppendLine([System.Text.Encoding]::Unicode.GetString($bytes))
                [void]$out.AppendLine([System.Text.Encoding]::ASCII.GetString($bytes))
            } catch { }
        }
        $out.ToString()
    }

    # ---- scoring ----------------------------------------------------------
    function Get-BehaviourScore {
        param([string]$Text)
        $score = 0; $cats = @(); $why = @()
        foreach ($r in $BehavRules) {
            try { $hit = [regex]::IsMatch($Text, $r.Regex, 'IgnoreCase') } catch { continue }
            if ($hit) {
                $score += $r.Weight
                if ($cats -notcontains $r.Category)    { $cats += $r.Category }
                if ($why  -notcontains $r.Description) { $why  += $r.Description }
            }
        }
        # Count-based signals the rule table cannot express.
        $carets = ([regex]::Matches($Text, '\^')).Count
        $ticks  = ([regex]::Matches($Text, '`')).Count
        if ($carets -ge 4 -or $ticks -ge 4) {
            $score += $(if ($carets -ge 4) { 3 } else { 2 })
            if ($cats -notcontains 'obfuscation') { $cats += 'obfuscation' }
            $d = 'disguises its commands with escape characters'
            if ($why -notcontains $d) { $why += $d }
        }
        [pscustomobject]@{ Score = $score; Cats = $cats.Count; Why = ($why -join '; ') }
    }

    function Test-FileBehaviour {
        param([string]$Path)
        $raw = ''
        try {
            $fs  = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
            $buf = New-Object byte[] $BehavMaxBytes
            $n   = $fs.Read($buf, 0, $BehavMaxBytes)
            $fs.Dispose()
            $raw = [System.Text.Encoding]::GetEncoding(28591).GetString($buf, 0, $n) -replace "`0", ''
        } catch { return $null }

        $lower = $raw.ToLowerInvariant()
        $best  = Get-BehaviourScore -Text $lower

        $pass2 = (Get-Deobfuscated -Text $lower) + "`n" +
                 (Get-DecodedBase64 -Raw $raw).ToLowerInvariant()
        $alt = Get-BehaviourScore -Text $pass2
        if ($alt.Score -gt $best.Score) { $best = $alt }

        if ($best.Score -ge $BehavMinScore -and $best.Cats -ge $BehavMinCats) { return $best }
        return $null
    }

    # -- B1/B2: scripts near the drop location ------------------------------
    # Depth 3 because a dropper can just as easily write into a subfolder.
    foreach ($d in $dropDirs) {
        $files = Get-ChildItem -LiteralPath $d -File -Recurse -Depth 2 -ErrorAction SilentlyContinue
        foreach ($s in ($files | Where-Object { $_.Extension -match $execExt })) {
            if ($behavSeen.ContainsKey($s.FullName)) { continue }
            $r = Test-FileBehaviour -Path $s.FullName
            if ($r) {
                $behavSeen[$s.FullName] = $true
                Add-Note "This script behaves like the malware: $($r.Why)" $s.FullName
            }
        }
        foreach ($s in ($files | Where-Object { $_.Extension -match $oddExt })) {
            if ($behavSeen.ContainsKey($s.FullName)) { continue }
            $behavSeen[$s.FullName] = $true
            Add-Info $s.FullName
        }
    }

    # -- B3: Unreal capability abuse inside Workshop maps -------------------
    # A community map is scenery. It has no legitimate reason to reach for the
    # user's home directory or launch a process. Spotting the CAPABILITY rather
    # than the payload is what catches a malicious map nobody has reported yet.
    #
    # Two or more DISTINCT capabilities are required: one incidental match in a
    # large binary is not worth frightening anyone over, but writing a file AND
    # launching something is a different matter.
    $capMarkers = @('GetPlatformUserDir','SaveStringToFile','SaveStringArrayToFile',
                    'ExecuteConsoleCommand','LaunchURL','CreateProc','BP_RCE',
                    'WriteStringToFile','FileSaveDialog')
    foreach ($root in $SteamRoots) {
        $content = Join-Path $root "steamapps\workshop\content\$AppId"
        if (-not (Test-Path -LiteralPath $content)) { continue }
        $paks = Get-ChildItem -LiteralPath $content -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match '^\.(pak|utoc|ucas)$' }
        foreach ($pak in $paks) {
            $found = @()
            foreach ($m in $capMarkers) {
                if (Test-ContainsMarker -Path $pak.FullName -Markers @($m)) { $found += $m }
                if ($found.Count -ge 2) { break }
            }
            if ($found.Count -ge 2) {
                Add-Note "A map can write files or launch programs, which maps do not need ($($found -join ', '))" $pak.FullName
            }
        }
    }

    # -- B4: evidence that something already ran ----------------------------
    # The only checks that can still find anything after the files themselves
    # have been deleted.
    if (-not $Synthetic) {
        # Prefetch records which files a program touched. Paths are stored in
        # UTF-16 and upper-cased, so the markers are upper-cased to match.
        $pfDir = Join-Path $env:SystemRoot 'Prefetch'
        $upper = @($DropNames | ForEach-Object { $_.ToUpper() }) + @('STEAMB.BAT')
        if (Test-Path -LiteralPath $pfDir) {
            $pfFiles = $null
            try {
                $pfFiles = Get-ChildItem -LiteralPath $pfDir -Filter '*.pf' -ErrorAction Stop |
                           Where-Object { $_.Name -match '^(CMD|POWERSHELL)\.EXE' }
            } catch {
                Say '  (Prefetch needs Administrator to read -- skipped)' 'DarkGray'
            }
            foreach ($pf in @($pfFiles)) {
                $hit = Test-ContainsMarker -Path $pf.FullName -Markers $upper
                if ($hit) {
                    Add-Note "Windows recorded a command window opening the malware's file (`"$hit`")" $pf.FullName
                }
            }
        }

        # Defender may already have caught and quarantined it.
        try {
            $dets = Get-MpThreatDetection -ErrorAction Stop
            foreach ($det in @($dets)) {
                $res = ($det.Resources -join ' ')
                foreach ($n in @($DropNames) + @('steamb.bat')) {
                    if ($res -like "*$n*") {
                        Add-Note 'Microsoft Defender previously detected something matching this malware' $res
                        break
                    }
                }
            }
        } catch { }

        # PowerShell script-block logging, if it happens to be enabled.
        try {
            $evts = Get-WinEvent -FilterHashtable @{
                        LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104
                    } -MaxEvents 300 -ErrorAction Stop
            foreach ($e in $evts) {
                foreach ($n in $BadStrings) {
                    if ($e.Message -like "*$n*") {
                        Add-Note "A PowerShell log entry contains a known malware marker (`"$n`")" `
                                 "Event 4104 at $($e.TimeCreated)"
                        break
                    }
                }
            }
        } catch { }
    }

    if ($script:NoteCount -eq 0) { Say '  Nothing behaving suspiciously.' 'Green' }

    # Context, printed quietly and only if there is something to say.
    if ($script:InfoLines.Count -gt 0) {
        Say ''
        Say "  For reference, $($script:InfoLines.Count) program-type file(s) live in your documents" 'DarkGray'
        Say '  folders. That is normal on plenty of PCs and none of them behaved' 'DarkGray'
        Say '  suspiciously above -- listed only so you can recognise anything you' 'DarkGray'
        Say '  did not put there yourself:' 'DarkGray'
        $i = 0
        foreach ($l in $script:InfoLines) {
            $i++
            if ($i -gt 8) { Say "      ...and $($script:InfoLines.Count - 8) more" 'DarkGray'; break }
            Say "      $l" 'DarkGray'
        }
    }

    Say "  Applied $($BehavRules.Count) behaviour rules." 'DarkGray'
    Say ''
}

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
} elseif ($script:NoteCount -gt 0) {
    $exitCode = 3
    Say "  No known malware was found, but $($script:NoteCount) thing(s) are worth a look." 'Cyan'
    Say ''
    Say '  Do not panic. Nothing above matches this malware. The deep scan'
    Say '  flags anything that merely BEHAVES a bit like it, and ordinary files'
    Say '  can do that too -- a game launcher script, a modding tool, a backup'
    Say '  job. Most of the time this is a false alarm.'
    Say ''
    Say '  This tool has changed nothing. Nothing was deleted or moved.'
    Say ''
    Say '  If you want to be sure, run a full scan with Microsoft Defender or'
    Say '  Malwarebytes, and open the files listed above in Notepad to see what'
    Say '  they do. If a file downloads something from an address you do not'
    Say '  recognise and hides its window while doing it, treat it the way you'
    Say '  would a confirmed finding above.'
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
    if (-not $Deep) {
        Say '  Tip: this checked for the exact malware researchers have published.' 'DarkGray'
        Say '  To also look for files merely BEHAVING like it -- which can catch a' 'DarkGray'
        Say '  repackaged copy -- double-click check-my-pc-deep.bat instead.' 'DarkGray'
        Say ''
    }
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
