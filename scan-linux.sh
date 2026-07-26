#!/usr/bin/env bash
# Meccha Chameleon Workshop malware checker -- Linux scanner.
#
# Looks for the known indicators of the July 2026 Meccha Chameleon Steam
# Workshop dropper campaign. Read-only: this script never deletes, moves or
# modifies anything on your system.
#
# Exit codes:  0 = no known indicators found
#              1 = one or more indicators found
#              2 = the scan could not run properly

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INDICATORS="$SCRIPT_DIR/indicators.json"
SCAN_ROOT=""
USE_COLOR=1
DEEP=0
REPORT_LINES=()

# ---------------------------------------------------------------- arguments

usage() {
    cat <<'EOF'
Usage: ./scan-linux.sh [options]

  --deep             Also look for suspicious BEHAVIOUR, not just the exact
                     known indicators. Catches repackaged copies the
                     researchers have not catalogued yet, but can point at
                     innocent files. Anything it finds is worth a look, not
                     proof of infection.
  --scan-root DIR    Scan DIR as a synthetic root instead of the real system
                     (used by the test fixtures)
  --indicators FILE  Use an alternative indicators file
  --no-color         Disable coloured output
  -h, --help         Show this help

This tool only reports. It never changes anything on your computer.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --deep)        DEEP=1; shift ;;
        --scan-root)   SCAN_ROOT="${2:-}"; shift 2 ;;
        --indicators)  INDICATORS="${2:-}"; shift 2 ;;
        --no-color)    USE_COLOR=0; shift ;;
        -h|--help)     usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ ! -t 1 ] || [ -n "${NO_COLOR:-}" ]; then USE_COLOR=0; fi
if [ "$USE_COLOR" = 1 ]; then
    C_RED=$'\033[1;31m'; C_YEL=$'\033[1;33m'; C_GRN=$'\033[1;32m'
    C_CYA=$'\033[1;36m'
    C_DIM=$'\033[2m';    C_BLD=$'\033[1m';    C_OFF=$'\033[0m'
else
    C_RED=""; C_YEL=""; C_GRN=""; C_CYA=""; C_DIM=""; C_BLD=""; C_OFF=""
fi

# Print to the screen and capture for the report file.
say() { printf '%s\n' "$1"; REPORT_LINES+=("$(printf '%s' "$1" | sed 's/\x1b\[[0-9;]*m//g')"); }

# ------------------------------------------------------------- indicator load
#
# Parsed with grep rather than jq so the tool has zero dependencies. This
# expects the exact schema of indicators.json in this repo. If parsing yields
# nothing we abort with exit 2 -- a scanner that silently loses its indicators
# would report "nothing found" on an infected machine, which is the single
# worst thing this tool could do.

if [ ! -r "$INDICATORS" ]; then
    echo "ERROR: cannot read indicators file: $INDICATORS" >&2
    exit 2
fi

APPID=$(grep -oE '"steam_appid"[[:space:]]*:[[:space:]]*"[0-9]+"' "$INDICATORS" \
        | grep -oE '[0-9]+' | head -1)

mapfile -t BAD_IDS < <(grep -oE '"id"[[:space:]]*:[[:space:]]*"[0-9]+"' "$INDICATORS" \
                       | grep -oE '[0-9]+')

# Scoped to the file_hashes_sha256 block so a hash quoted anywhere else in the
# file -- in a provenance note, say -- can never become a live indicator.
mapfile -t BAD_HASHES < <(
    sed -n '/"file_hashes_sha256"/,/^[[:space:]]*}/p' "$INDICATORS" \
    | grep -oiE '"[a-f0-9]{64}"' | tr -d '"' | tr 'A-Z' 'a-z'
)

# Pull one JSON string array by key.
#
# Newlines are flattened first and the match is bounded to the first "]" after
# the key, so this works whether the array is on one line or many. Do not
# replace this with a sed line range: sed looks for the range end on the line
# AFTER the start, so a single-line array would silently swallow whichever key
# came next.
extract_array() {
    tr '\n' ' ' < "$INDICATORS" \
    | grep -oE "\"$1\"[[:space:]]*:[[:space:]]*\[[^]]*\]" \
    | sed 's/^[^[]*\[//; s/\]$//' \
    | grep -oE '"[^"]*"' | sed 's/^"//; s/"$//'
}

mapfile -t BAD_STRINGS < <(extract_array content_strings)
mapfile -t DROP_NAMES  < <(extract_array dropped_filenames)

if [ -z "$APPID" ] || [ "${#BAD_HASHES[@]}" -eq 0 ] || [ "${#BAD_STRINGS[@]}" -eq 0 ]; then
    echo "ERROR: could not parse indicators from $INDICATORS -- refusing to report a" >&2
    echo "       misleading 'clean' result. The file may be corrupt." >&2
    exit 2
fi

# Undocumented, for the test suite: prove exactly what was parsed. Indicator
# parsing bugs are invisible in normal output -- the scan still "works", it
# just quietly matches the wrong things.
if [ "${DUMP_INDICATORS:-0}" = "1" ]; then
    printf 'APPID=%s\n' "$APPID"
    for v in "${BAD_IDS[@]:-}";     do printf 'ID=%s\n' "$v"; done
    for v in "${BAD_HASHES[@]}";    do printf 'HASH=%s\n' "$v"; done
    for v in "${BAD_STRINGS[@]}";   do printf 'STRING=%s\n' "$v"; done
    for v in "${DROP_NAMES[@]:-}";  do printf 'DROP=%s\n' "$v"; done
    exit 0
fi

# ------------------------------------------------------------------ findings

FOUND_COUNT=0
SUSPECT_COUNT=0
NOTE_COUNT=0

# A third tier, used only by --deep. These are behaviour patterns, not known
# indicators: they describe something that LOOKS like how this malware works,
# which an innocent file can also do. Kept separate from FOUND/SUSPICIOUS
# counts so behaviour alone never reads as "you are infected".
note() {  # note <what> <where>
    NOTE_COUNT=$((NOTE_COUNT + 1))
    say "  ${C_CYA}[WORTH A LOOK]${C_OFF} $1"
    say "                 ${C_DIM}$2${C_OFF}"
}

finding() {  # finding <FOUND|SUSPICIOUS> <what> <where>
    local sev="$1" what="$2" where="$3"
    if [ "$sev" = "FOUND" ]; then
        FOUND_COUNT=$((FOUND_COUNT + 1))
        say "  ${C_RED}[FOUND]${C_OFF}      $what"
    else
        SUSPECT_COUNT=$((SUSPECT_COUNT + 1))
        say "  ${C_YEL}[SUSPICIOUS]${C_OFF} $what"
    fi
    say "               ${C_DIM}$where${C_OFF}"
}

# Does a binary file contain a needle, in either ASCII or UTF-16LE?
# Stripping NUL bytes turns UTF-16LE text into ASCII, so one pass covers both.
contains_string() {
    local file="$1" needle="$2"
    LC_ALL=C tr -d '\000' < "$file" 2>/dev/null | LC_ALL=C grep -qaF -- "$needle"
}

# --------------------------------------------------------------------- banner

say ""
say "${C_BLD}  Meccha Chameleon Workshop malware checker${C_OFF}"
say "  ${C_DIM}Read-only. This tool changes nothing on your computer.${C_OFF}"
say "  ${C_DIM}Indicators updated: $(grep -oE '"updated"[^,]*' "$INDICATORS" | grep -oE '[0-9-]{10}')${C_OFF}"
say ""

# ------------------------------------------------------- locate steam / homes

STEAM_ROOTS=()
HOME_DIR="$HOME"
SYNTHETIC=0

if [ -n "$SCAN_ROOT" ]; then
    SYNTHETIC=1
    HOME_DIR="$SCAN_ROOT/home"
    [ -d "$SCAN_ROOT/steamroot" ] && STEAM_ROOTS+=("$SCAN_ROOT/steamroot")
else
    # (a) The standard per-user install locations, including Flatpak.
    for cand in \
        "$HOME/.steam/steam" \
        "$HOME/.steam/root" \
        "$HOME/.local/share/Steam" \
        "$HOME/.var/app/com.valvesoftware.Steam/.local/share/Steam"
    do
        [ -d "$cand/steamapps" ] && STEAM_ROOTS+=("$cand")
    done

    # (b) Extra libraries on other drives, as declared by Steam itself.
    for root in "${STEAM_ROOTS[@]:-}"; do
        for vdf in "$root/steamapps/libraryfolders.vdf" "$root/config/libraryfolders.vdf"; do
            [ -r "$vdf" ] || continue
            while IFS= read -r extra; do
                [ -d "$extra/steamapps" ] && STEAM_ROOTS+=("$extra")
            done < <(grep -oE '"path"[[:space:]]+"[^"]+"' "$vdf" \
                     | sed 's/.*"path"[[:space:]]*"//; s/"$//' | sed 's/\\\\/\//g')
        done
    done

    # (c) Every mounted drive on the machine.
    #
    # libraryfolders.vdf only lists libraries Steam currently knows about. A
    # drive that was unplugged, re-mounted elsewhere, or whose library was
    # removed from Steam can still hold an infected map on disk, so we look at
    # the drives themselves rather than trusting Steam's own bookkeeping.
    MOUNTS=("/")
    while IFS= read -r mp; do MOUNTS+=("$mp"); done < <(
        awk '$3 ~ /^(ext2|ext3|ext4|btrfs|xfs|f2fs|zfs|ntfs|ntfs3|fuseblk|vfat|exfat|drvfs|9p|cifs|nfs|nfs4)$/ {print $2}' \
            /proc/mounts 2>/dev/null | sed 's/\\040/ /g'
    )
    for extra in /mnt/* /media/* /media/*/* /run/media/*/* /srv /opt; do
        [ -d "$extra" ] && MOUNTS+=("$extra")
    done
    mapfile -t MOUNTS < <(printf '%s\n' "${MOUNTS[@]}" | awk 'NF && !seen[$0]++')

    printf '  Searching all drives for Steam libraries...\n'
    for mp in "${MOUNTS[@]}"; do
        [ -d "$mp" ] || continue
        # Common library folder names sitting directly on a drive.
        for sub in "SteamLibrary" "Steam" "Games/SteamLibrary" "Games/Steam" "games/SteamLibrary" "SteamLibrary/Steam" "." ; do
            cand="$mp/$sub"
            [ -d "$cand/steamapps" ] && STEAM_ROOTS+=("$cand")
        done
        # Depth-limited sweep for anything we did not guess. Bounded, and with
        # the big system directories pruned, so the scan stays quick -- a full
        # disk walk would take far too long for a tool meant to be
        # double-clicked. Steam libraries do not live in any of these.
        while IFS= read -r hit; do
            STEAM_ROOTS+=("$(dirname "$hit")")
        done < <(find "$mp" -maxdepth 4 \
                      \( -iname 'Windows'     -o -iname '$Recycle.Bin' \
                      -o -iname 'System Volume Information'            \
                      -o -iname 'AppData'     -o -iname 'ProgramData'  \
                      -o -iname 'WindowsApps' -o -iname 'node_modules' \
                      -o -iname '.git'        -o -iname '.cache'       \
                      -o -iname 'proc'        -o -iname 'sys'          \
                      -o -iname 'MSOCache'    -o -iname 'PerfLogs' \) -prune \
                      -o -type d -name steamapps -print 2>/dev/null | head -40)
    done
fi

# de-duplicate
if [ "${#STEAM_ROOTS[@]}" -gt 0 ]; then
    mapfile -t STEAM_ROOTS < <(printf '%s\n' "${STEAM_ROOTS[@]}" | awk '!seen[$0]++')
fi

if [ "${#STEAM_ROOTS[@]}" -eq 0 ]; then
    say "  ${C_YEL}No Steam installation found.${C_OFF}"
    say "  ${C_DIM}Checked the usual locations including the Flatpak path.${C_OFF}"
    say "  ${C_DIM}If Steam is installed somewhere unusual, the Workshop checks below${C_OFF}"
    say "  ${C_DIM}were skipped -- this is not the same as a clean result.${C_OFF}"
    say ""
else
    for r in "${STEAM_ROOTS[@]}"; do say "  ${C_DIM}Steam library: $r${C_OFF}"; done
    say ""
fi

# ----------------------------------------------- checks 2+3+4: workshop maps

say "${C_BLD}  Checking your subscribed Workshop maps...${C_OFF}"

WORKSHOP_DIRS_SEEN=0
for root in "${STEAM_ROOTS[@]:-}"; do
    content="$root/steamapps/workshop/content/$APPID"
    [ -d "$content" ] || continue

    for item in "$content"/*/; do
        [ -d "$item" ] || continue
        WORKSHOP_DIRS_SEEN=$((WORKSHOP_DIRS_SEEN + 1))
        id="$(basename "$item")"

        # Check 2: known-bad Workshop ID
        for bad in "${BAD_IDS[@]:-}"; do
            if [ "$id" = "$bad" ]; then
                finding FOUND "Known malicious Workshop map is installed (ID $id)" "$item"
            fi
        done

        # Checks 3 and 4: hash and byte-scan the Unreal asset containers
        while IFS= read -r -d '' pak; do
            h="$(sha256sum "$pak" 2>/dev/null | cut -d' ' -f1 | tr 'A-Z' 'a-z')"
            for bad in "${BAD_HASHES[@]}"; do
                if [ -n "$h" ] && [ "$h" = "$bad" ]; then
                    finding FOUND "Map file matches a known malicious file exactly" "$pak"
                fi
            done
            for s in "${BAD_STRINGS[@]}"; do
                if contains_string "$pak" "$s"; then
                    finding SUSPICIOUS "Map file contains a known malware marker (\"$s\")" "$pak"
                    break
                fi
            done
        done < <(find "$item" -type f \( -iname '*.pak' -o -iname '*.utoc' -o -iname '*.ucas' \) -print0 2>/dev/null)
    done
done

if [ "$WORKSHOP_DIRS_SEEN" -eq 0 ]; then
    say "  ${C_GRN}No Meccha Chameleon Workshop maps are installed.${C_OFF}"
else
    say "  ${C_DIM}Examined $WORKSHOP_DIRS_SEEN installed map(s).${C_OFF}"
fi
say ""

# ------------------------------------------------- check 5: dropped s.bat

say "${C_BLD}  Checking for files the malware drops...${C_OFF}"

DROP_DIRS=("$HOME_DIR/Documents")
for root in "${STEAM_ROOTS[@]:-}"; do
    pfx="$root/steamapps/compatdata/$APPID/pfx/drive_c/users/steamuser"
    DROP_DIRS+=("$pfx/Documents" "$pfx/Temp" "$pfx/AppData/Local/Temp")
done

for d in "${DROP_DIRS[@]}"; do
    [ -d "$d" ] || continue

    for name in "${DROP_NAMES[@]:-}"; do
        f="$d/$name"
        [ -f "$f" ] || continue
        h="$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1 | tr 'A-Z' 'a-z')"
        matched=0
        for bad in "${BAD_HASHES[@]}"; do
            if [ "$h" = "$bad" ]; then
                finding FOUND "The malware's dropper file is on this system" "$f"
                matched=1
            fi
        done
        [ "$matched" = 0 ] && finding SUSPICIOUS "A file named '$name' is here, where the malware drops its file" "$f"
    done

    # Renamed variants: any .bat/.cmd carrying a known marker string
    while IFS= read -r -d '' f; do
        for s in "${BAD_STRINGS[@]}"; do
            if contains_string "$f" "$s"; then
                finding FOUND "A script here contains a known malware marker (\"$s\")" "$f"
                break
            fi
        done
    done < <(find "$d" -maxdepth 1 -type f \( -iname '*.bat' -o -iname '*.cmd' \) -print0 2>/dev/null)
done

say "  ${C_DIM}Checked your Documents folder and the Steam Play (Proton) prefix.${C_OFF}"
say ""

# --------------------------------------------------- check 6: persistence

say "${C_BLD}  Checking for leftover startup entries...${C_OFF}"

PERSIST_NEEDLES=("${DROP_NAMES[@]:-s.bat}" "steamb.bat")
for s in "${BAD_STRINGS[@]}"; do PERSIST_NEEDLES+=("$s"); done

scan_persist_file() {
    local f="$1" label="$2"
    [ -r "$f" ] || return 0
    for n in "${PERSIST_NEEDLES[@]}"; do
        if LC_ALL=C grep -qaF -- "$n" "$f" 2>/dev/null; then
            finding FOUND "$label refers to the malware (\"$n\")" "$f"
            return 0
        fi
    done
}

while IFS= read -r -d '' f; do
    scan_persist_file "$f" "A startup entry"
done < <(find "$HOME_DIR/.config/autostart" -maxdepth 1 -type f -name '*.desktop' -print0 2>/dev/null)

if [ "$SYNTHETIC" = 0 ]; then
    cron_tmp="$(mktemp)"
    if crontab -l >"$cron_tmp" 2>/dev/null; then
        scan_persist_file "$cron_tmp" "A scheduled cron job"
    fi
    rm -f "$cron_tmp"

    units_tmp="$(mktemp)"
    if systemctl --user list-unit-files --no-pager >"$units_tmp" 2>/dev/null; then
        scan_persist_file "$units_tmp" "A user service"
    fi
    rm -f "$units_tmp"
else
    say "  ${C_DIM}(cron and systemd checks skipped in test mode)${C_OFF}"
fi

say "  ${C_DIM}Checked autostart entries, cron jobs and user services.${C_OFF}"
say ""

# -------------------------------------------------- --deep: behaviour checks
#
# Everything above matches indicators researchers have published. Those are
# exact, but they are also the easiest thing in the world for the attacker to
# change -- a recompiled map with a new server address defeats all of it.
#
# The checks below describe how this malware BEHAVES instead, so they can catch
# a repackaged copy nobody has catalogued. The trade-off is that innocent files
# can behave the same way, which is why they report as "worth a look" and never
# as a confirmed finding.

if [ "$DEEP" = 1 ]; then
    say "${C_BLD}  Deep scan: looking for suspicious behaviour...${C_OFF}"

    # -- B1: batch files in Documents at all -------------------------------
    # Documents is a place for documents. A .bat or .cmd sitting there is not
    # where anything legitimate normally puts one, and it is exactly where this
    # malware writes its dropper -- no known indicator required to spot it.
    for d in "${DROP_DIRS[@]}"; do
        [ -d "$d" ] || continue
        while IFS= read -r -d '' f; do
            note "A batch file is sitting in a documents folder, which is unusual" "$f"
        done < <(find "$d" -maxdepth 1 -type f \( -iname '*.bat' -o -iname '*.cmd' \) -print0 2>/dev/null)
    done

    # -- B2: the dropper pattern -------------------------------------------
    # Not one string, but a combination: hide a PowerShell window, fetch
    # something from the internet, drop it in a temp folder and run it. Any one
    # of these alone is common enough in legitimate scripts; together they
    # describe this malware family regardless of which server it calls.
    HIDE_PAT='-w hidden|-windowstyle hidden|-ep bypass|-executionpolicy bypass|-nop |-noprofile|-enc |-encodedcommand'
    FETCH_PAT='iwr |invoke-webrequest|downloadstring|downloadfile|certutil|bitsadmin|curl |wget '
    EXEC_PAT='%temp%|\$env:temp|start /min|cmd /c|&exit'

    scan_script_behaviour() {
        local f="$1"
        local body cats=0 which=""
        body="$(LC_ALL=C tr -d '\000' < "$f" 2>/dev/null | tr 'A-Z' 'a-z')"
        # "--" is required: HIDE_PAT begins with a hyphen, which grep would
        # otherwise parse as its own options.
        if echo "$body" | grep -qE -- "$HIDE_PAT";  then cats=$((cats+1)); which="${which}hidden window, "; fi
        if echo "$body" | grep -qE -- "$FETCH_PAT"; then cats=$((cats+1)); which="${which}downloads from the internet, "; fi
        if echo "$body" | grep -qE -- "$EXEC_PAT";  then cats=$((cats+1)); which="${which}runs from a temp folder, "; fi
        if [ "$cats" -ge 2 ]; then
            note "A script here behaves like this malware (${which%, })" "$f"
        fi
    }

    for d in "${DROP_DIRS[@]}"; do
        [ -d "$d" ] || continue
        while IFS= read -r -d '' f; do
            scan_script_behaviour "$f"
        done < <(find "$d" -maxdepth 1 -type f \( -iname '*.bat' -o -iname '*.cmd' -o -iname '*.ps1' \) -print0 2>/dev/null)
    done

    # -- B3: Unreal capability abuse inside Workshop maps -------------------
    # A community map is scenery. It has no legitimate reason to reach for the
    # user's home directory or launch a process. Spotting the CAPABILITY rather
    # than the payload is what catches a malicious map nobody has reported yet.
    CAP_PAT='GetPlatformUserDir|SaveStringToFile|SaveStringArrayToFile|ExecuteConsoleCommand|LaunchURL|CreateProc|BP_RCE'
    for root in "${STEAM_ROOTS[@]:-}"; do
        content="$root/steamapps/workshop/content/$APPID"
        [ -d "$content" ] || continue
        while IFS= read -r -d '' pak; do
            hit="$(LC_ALL=C tr -d '\000' < "$pak" 2>/dev/null | grep -oiE "$CAP_PAT" | head -1)"
            if [ -n "$hit" ]; then
                note "A map can write files or launch programs, which maps do not need (\"$hit\")" "$pak"
            fi
        done < <(find "$content" -type f \( -iname '*.pak' -o -iname '*.utoc' -o -iname '*.ucas' \) -print0 2>/dev/null)
    done

    # -- B4: evidence that something already ran ----------------------------
    # The only checks here that can still find anything after the files have
    # been deleted. On Linux the game runs under Proton, so the Windows-side
    # traces live inside the Wine prefix registry rather than the real system.
    if [ "$SYNTHETIC" = 0 ]; then
        for root in "${STEAM_ROOTS[@]:-}"; do
            pfx="$root/steamapps/compatdata/$APPID/pfx"
            [ -d "$pfx" ] || continue
            for reg in "$pfx/user.reg" "$pfx/system.reg"; do
                [ -r "$reg" ] || continue
                while IFS= read -r line; do
                    note "The game's Windows environment has a startup entry that runs a script" "$reg"
                    break
                done < <(grep -iE '\\\\run\\\\|\.bat|\.cmd' "$reg" 2>/dev/null | head -1)
            done
            while IFS= read -r -d '' f; do
                note "A leftover script is inside the game's Windows environment" "$f"
            done < <(find "$pfx/drive_c" -maxdepth 6 -type f \( -iname '*.bat' -o -iname '*.cmd' \) -print0 2>/dev/null | head -c 100000)
        done
    fi

    if [ "$NOTE_COUNT" -eq 0 ]; then
        say "  ${C_GRN}Nothing behaving suspiciously.${C_OFF}"
    fi
    say ""
fi

# ----------------------------------------------------------------- verdict

say "  ${C_DIM}--------------------------------------------------------------${C_OFF}"
say ""

EXIT=0
if [ "$FOUND_COUNT" -gt 0 ] || [ "$SUSPECT_COUNT" -gt 0 ]; then
    EXIT=1
    say "  ${C_RED}${C_BLD}Something was found. Please read this carefully.${C_OFF}"
    say ""
    say "  Confirmed indicators: $FOUND_COUNT      Suspicious: $SUSPECT_COUNT"
    say ""
    say "  ${C_BLD}This tool has changed nothing.${C_OFF} Nothing was deleted or moved."
    say ""
    say "  What to do next, in this order:"
    say ""
    say "   1. Disconnect this computer from the internet."
    say "   2. Do NOT delete the files listed above yet. They are evidence, and"
    say "      deleting them does not remove the second stage of this malware."
    say "   3. Run a full offline scan with Microsoft Defender or Malwarebytes."
    say "   4. From a DIFFERENT device, change your important passwords: email"
    say "      first, then Steam, Discord, and anything reusing those passwords."
    say "   5. From that other device, sign out of all sessions on Steam and"
    say "      Discord, then turn two-factor authentication off and back on."
    say "      ${C_DIM}The attackers behind this campaign bypassed a victim's Discord 2FA.${C_OFF}"
    say "   6. Unsubscribe from the map in the Steam Workshop, and make sure"
    say "      Meccha Chameleon is updated to version 3.2.0 or later."
    say ""
elif [ "$NOTE_COUNT" -gt 0 ]; then
    EXIT=3
    say "  ${C_CYA}${C_BLD}No known malware was found, but $NOTE_COUNT thing(s) are worth a look.${C_OFF}"
    say ""
    say "  ${C_BLD}Do not panic.${C_OFF} Nothing above matches this malware. The deep scan"
    say "  flags anything that merely BEHAVES a bit like it, and ordinary files"
    say "  can do that too -- a game launcher script, a modding tool, a backup"
    say "  job. Most of the time this is a false alarm."
    say ""
    say "  ${C_BLD}This tool has changed nothing.${C_OFF} Nothing was deleted or moved."
    say ""
    say "  If you want to be sure, run a full scan with Microsoft Defender or"
    say "  Malwarebytes, and open the files listed above in Notepad or a text"
    say "  editor to see what they do. If a file downloads something from an"
    say "  address you do not recognise and hides its window while doing it,"
    say "  treat it the way you would a confirmed finding above."
    say ""
else
    say "  ${C_GRN}${C_BLD}No known indicators of this malware were found.${C_OFF}"
    say ""
    say "  ${C_BLD}What this DOES mean:${C_OFF} none of the malicious maps, files or startup"
    say "  entries that researchers have identified so far are on this system."
    say ""
    say "  ${C_BLD}What this does NOT mean:${C_OFF} it is not proof that you are clean. The"
    say "  second stage of this attack was never captured by researchers, so"
    say "  nobody publicly knows exactly what it installs or what traces it"
    say "  leaves behind. This tool cannot look for something nobody has seen."
    say ""
    say "  If you saw a black command window flash while loading a custom map,"
    say "  treat this result with suspicion: run a full antivirus scan and change"
    say "  your passwords from a different device anyway."
    say ""
    if [ "$DEEP" = 0 ]; then
        say "  ${C_DIM}Tip: this checked for the exact malware researchers have published.${C_OFF}"
        say "  ${C_DIM}To also look for files merely BEHAVING like it -- which can catch a${C_OFF}"
        say "  ${C_DIM}repackaged copy -- run:  ./check-my-pc.sh --deep${C_OFF}"
        say ""
    fi
fi

# ------------------------------------------------------------- report file

REPORT_DIR="$SCRIPT_DIR"
[ -w "$REPORT_DIR" ] || REPORT_DIR="$HOME"
REPORT_FILE="$REPORT_DIR/meccha-check-report-$(date +%Y%m%d-%H%M%S).txt"

{
    printf 'Meccha Chameleon Workshop malware checker\n'
    printf 'Scan date: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    printf 'Host: %s\n' "$(uname -sr 2>/dev/null)"
    printf 'Result: %s\n\n' "$([ "$EXIT" = 0 ] && echo 'no known indicators found' || echo 'INDICATORS FOUND')"
    printf '%s\n' "${REPORT_LINES[@]}"
} >"$REPORT_FILE" 2>/dev/null \
    && printf '  %sA copy of this report was saved to:%s\n  %s\n\n' "$C_DIM" "$C_OFF" "$REPORT_FILE"

exit "$EXIT"
