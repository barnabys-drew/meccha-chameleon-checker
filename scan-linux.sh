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
JSON=0
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
  --json             Print one machine-readable JSON result on stdout, for
                     checking many computers at once. The normal report
                     still appears, on stderr.
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
        --json)        JSON=1; shift ;;
        --no-color)    USE_COLOR=0; shift ;;
        -h|--help)     usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

# Everything a person reads goes to fd 3. Normally that is stdout; with --json
# it is stderr, so stdout carries exactly one JSON document and nothing else --
# a stray progress line would make every result unparseable.
if [ "$JSON" = 1 ]; then exec 3>&2; else exec 3>&1; fi

# A JSON string literal. Paths are the only untrusted text here, and a
# filename can legally contain quotes, backslashes and control characters.
json_str() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"; s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"
    printf '"%s"' "$(printf '%s' "$s" | LC_ALL=C tr -d '\000-\010\013\014\016-\037')"
}

# Exit 2 -- the scan could not run. Under --json this still prints a result, so
# a sweep of many machines records "failed" rather than silently skipping one.
abort() {  # abort <line>...
    local l
    for l in "$@"; do printf '%s\n' "$l" >&2; done
    if [ "$JSON" = 1 ]; then
        printf '{"schema":1,"tool":"meccha-chameleon-checker","platform":"linux","host":%s,"exit_code":2,"verdict":"scan_failed","error":%s}\n' \
            "$(json_str "$(uname -n 2>/dev/null)")" "$(json_str "$1")"
    fi
    exit 2
}

if [ ! -t 3 ] || [ -n "${NO_COLOR:-}" ]; then USE_COLOR=0; fi
if [ "$USE_COLOR" = 1 ]; then
    C_RED=$'\033[1;31m'; C_YEL=$'\033[1;33m'; C_GRN=$'\033[1;32m'
    C_CYA=$'\033[1;36m'
    C_DIM=$'\033[2m';    C_BLD=$'\033[1m';    C_OFF=$'\033[0m'
else
    C_RED=""; C_YEL=""; C_GRN=""; C_CYA=""; C_DIM=""; C_BLD=""; C_OFF=""
fi

# Print to the screen and capture for the report file.
say() { printf '%s\n' "$1" >&3; REPORT_LINES+=("$(printf '%s' "$1" | sed 's/\x1b\[[0-9;]*m//g')"); }

# ------------------------------------------------------------- indicator load
#
# Parsed with grep rather than jq so the tool has zero dependencies. This
# expects the exact schema of indicators.json in this repo. If parsing yields
# nothing we abort with exit 2 -- a scanner that silently loses its indicators
# would report "nothing found" on an infected machine, which is the single
# worst thing this tool could do.

if [ ! -r "$INDICATORS" ]; then
    abort "ERROR: cannot read indicators file: $INDICATORS"
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
    abort "ERROR: could not parse indicators from $INDICATORS -- refusing to report a" \
          "       misleading 'clean' result. The file may be corrupt."
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
FINDINGS_JSON=()   # one JSON object per finding, in report order, for --json

record() {  # record <severity> <what> <where>
    FINDINGS_JSON+=("{\"severity\":\"$1\",\"what\":$(json_str "$2"),\"where\":$(json_str "$3")}")
}

# A third tier, used only by --deep. These are behaviour patterns, not known
# indicators: they describe something that LOOKS like how this malware works,
# which an innocent file can also do. Kept separate from FOUND/SUSPICIOUS
# counts so behaviour alone never reads as "you are infected".
note() {  # note <what> <where>
    NOTE_COUNT=$((NOTE_COUNT + 1))
    record WORTH_A_LOOK "$1" "$2"
    say "  ${C_CYA}[WORTH A LOOK]${C_OFF} $1"
    say "                 ${C_DIM}$2${C_OFF}"
}

# Observations too weak to alarm anyone with on their own -- "you have a .bat
# file in Documents" is true of plenty of innocent machines. Shown as context,
# deliberately NOT counted toward the verdict or the exit code: six cyan alerts
# on a clean PC teaches people to ignore the alerts that matter.
INFO_LINES=()
info() { INFO_LINES+=("$1"); }

finding() {  # finding <FOUND|SUSPICIOUS> <what> <where>
    local sev="$1" what="$2" where="$3"
    record "$sev" "$what" "$where"
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

# ------------------------------------------------ what a byte search can't see
#
# Checks 4 and B3 search a map file's raw bytes. That only works when the data
# is stored as-is. Unreal usually compresses it -- UE5 defaults to Oodle, which
# is proprietary and compiled into each game, so no zero-dependency tool can
# undo it -- and can encrypt it with a key only the game has. In either case a
# marker inside is invisible, and the search would quietly say "not found".
#
# This reads only the container's header or footer and never decompresses
# anything. It prints why the raw bytes cannot be searched, or nothing if they
# can. The layouts below were checked against shipping UE5 games.

u8_at()  { od -An -t u1 -j "$2" -N 1 "$1" 2>/dev/null | tr -d ' \n'; }
u32_at() { od -An -t u4 --endian=little -j "$2" -N 4 "$1" 2>/dev/null | tr -d ' \n'; }

# A run of fixed-width, NUL-padded compression method names, joined by ", ".
method_names() {  # method_names <file> <offset> <count> <width>
    local i n out=""
    for (( i = 0; i < $3 && i < 8; i++ )); do
        n="$(LC_ALL=C tail -c +$(( $2 + i * $4 + 1 )) "$1" 2>/dev/null | head -c "$4" \
             | LC_ALL=C tr -d '\000' | LC_ALL=C tr -cd 'A-Za-z0-9_')"
        [ -n "$n" ] && out="${out:+$out, }$n"
    done
    printf '%s' "$out"
}

container_blind_reason() {  # container_blind_reason <.pak|.utoc|.ucas>
    local f="$1" size ver flags hdr entries blocks bsize nmeth nlen seeds nophash off names pos
    case "${f,,}" in
        # A .ucas holds the data; its .utoc next to it says how it is stored.
        *.ucas) f="${f%.*}.utoc"; [ -r "$f" ] || return 0 ;;
    esac
    size="$(stat -c %s "$f" 2>/dev/null)" || return 0

    case "${f,,}" in
    *.utoc)
        # FIoStoreTocHeader, 144 bytes, starting with a 16-byte magic.
        [ "$size" -ge 144 ] || return 0
        [ "$(LC_ALL=C head -c 16 "$f")" = "-==--==--==--==-" ] || return 0
        flags="$(u8_at "$f" 80)"
        if (( flags & 2 )); then echo "encrypted"; return 0; fi
        nmeth="$(u32_at "$f" 36)"
        [ "${nmeth:-0}" -gt 0 ] || return 0
        # Method names follow the header, the chunk ID (12 bytes) and offset
        # (10 bytes) tables, the perfect-hash tables and the block table.
        hdr="$(u32_at "$f" 20)";    entries="$(u32_at "$f" 24)"
        blocks="$(u32_at "$f" 28)"; bsize="$(u32_at "$f" 32)"; nlen="$(u32_at "$f" 40)"
        seeds="$(u32_at "$f" 84)";  nophash="$(u32_at "$f" 96)"
        off=$(( hdr + entries * 22 + seeds * 4 + nophash * 4 + blocks * bsize ))
        names=""
        [ "$nlen" = 32 ] && [ $(( off + nmeth * nlen )) -le "$size" ] \
            && names="$(method_names "$f" "$off" "$nmeth" 32)"
        echo "compressed${names:+ with $names}"
        ;;
    *.pak)
        # FPakInfo footer: magic E1 12 6F 5A, a fixed distance from the end
        # that depends on the pak version, then compression method names
        # running to end of file. The byte before the magic flags an
        # encrypted index.
        for pos in 204 205 172 44; do
            [ "$size" -ge "$pos" ] || continue
            [ "$(od -An -t x1 -j $(( size - pos )) -N 4 "$f" 2>/dev/null | tr -d ' \n')" = "e1126f5a" ] || continue
            ver="$(u32_at "$f" $(( size - pos + 4 )))"
            if [ "$pos" != 44 ] && [ "$(u8_at "$f" $(( size - pos - 1 )))" = 1 ]; then
                echo "encrypted"; return 0
            fi
            off=$(( size - pos + 44 )); [ "$ver" = 9 ] && off=$(( off + 1 ))
            names="$(method_names "$f" "$off" $(( (size - off) / 32 )) 32)"
            [ -n "$names" ] && echo "compressed with $names"
            return 0
        done
        ;;
    esac
    return 0
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
    # (a) The standard per-user install locations, including Flatpak, and
    #     ~/Steam, where steamcmd installs by default.
    for cand in \
        "$HOME/.steam/steam" \
        "$HOME/.steam/root" \
        "$HOME/.local/share/Steam" \
        "$HOME/.var/app/com.valvesoftware.Steam/.local/share/Steam" \
        "$HOME/Steam"
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

    printf '  Searching all drives for Steam libraries...\n' >&3
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

# Every place a map can sit on disk, gathered once so the IOC checks and the
# --deep capability check always examine the same set.
#
#   ITEM_DIRS  one folder per Workshop item, named by its Workshop ID. Both the
#              finished install (content/) and Steam's staging area for an
#              interrupted or in-progress download (downloads/) -- a partial
#              download is still a malicious file on disk.
#   MOD_DIRS   folders of loose map files with no Workshop ID: maps a player
#              copied into the game's own mod folders by hand, outside Steam.
ITEM_DIRS=()
MOD_DIRS=()
for root in "${STEAM_ROOTS[@]:-}"; do
    [ -n "$root" ] || continue
    for base in "$root/steamapps/workshop/content/$APPID" \
                "$root/steamapps/workshop/downloads/$APPID"; do
        [ -d "$base" ] || continue
        for item in "$base"/*/; do
            [ -d "$item" ] && ITEM_DIRS+=("${item%/}")
        done
    done

    # The game's install folder name comes from Steam's own manifest rather
    # than being guessed, so a rename by the developer does not break this.
    game=""
    manifest="$root/steamapps/appmanifest_$APPID.acf"
    if [ -r "$manifest" ]; then
        installdir="$(grep -oE '"installdir"[[:space:]]+"[^"]+"' "$manifest" \
                      | sed 's/.*"installdir"[[:space:]]*"//; s/"$//' | head -1)"
        [ -n "$installdir" ] && game="$root/steamapps/common/$installdir"
    fi
    [ -d "$game" ] || continue
    # Unreal loads mod paks from Content/Paks/~mods, and UE4SS-style loaders
    # from Content/Paks/LogicMods. Depth 5 covers <Project>/Content/Paks/<dir>.
    while IFS= read -r -d '' m; do
        MOD_DIRS+=("$m")
    done < <(find "$game" -maxdepth 5 -type d \( -iname '~mods' -o -iname 'LogicMods' \) -print0 2>/dev/null)
done

say "${C_BLD}  Checking your Workshop maps...${C_OFF}"

# Map files whose contents a byte search cannot see, and why. Reported, so a
# "nothing found" never silently includes files that were not really examined.
BLIND_FILES=()
BLIND_REASONS=()

# Checks 3 and 4: hash and byte-scan the Unreal asset containers under a folder.
scan_map_files() {  # scan_map_files <dir>
    local pak h bad s hit reason
    while IFS= read -r -d '' pak; do
        h="$(sha256sum "$pak" 2>/dev/null | cut -d' ' -f1 | tr 'A-Z' 'a-z')"
        for bad in "${BAD_HASHES[@]}"; do
            if [ -n "$h" ] && [ "$h" = "$bad" ]; then
                finding FOUND "Map file matches a known malicious file exactly" "$pak"
            fi
        done
        hit=0
        for s in "${BAD_STRINGS[@]}"; do
            if contains_string "$pak" "$s"; then
                finding SUSPICIOUS "Map file contains a known malware marker (\"$s\")" "$pak"
                hit=1
                break
            fi
        done
        if [ "$hit" = 0 ]; then
            reason="$(container_blind_reason "$pak")"
            if [ -n "$reason" ]; then
                BLIND_FILES+=("$pak"); BLIND_REASONS+=("$reason")
            fi
        fi
    done < <(find "$1" -type f \( -iname '*.pak' -o -iname '*.utoc' -o -iname '*.ucas' \) -print0 2>/dev/null)
}

for item in "${ITEM_DIRS[@]:-}"; do
    [ -n "$item" ] || continue
    id="$(basename "$item")"

    # Check 2: known-bad Workshop ID
    for bad in "${BAD_IDS[@]:-}"; do
        if [ "$id" = "$bad" ]; then
            finding FOUND "Known malicious Workshop map is installed (ID $id)" "$item"
        fi
    done

    scan_map_files "$item"
done

for m in "${MOD_DIRS[@]:-}"; do
    [ -n "$m" ] && scan_map_files "$m"
done

if [ "${#ITEM_DIRS[@]}" -eq 0 ] && [ "${#MOD_DIRS[@]}" -eq 0 ]; then
    say "  ${C_GRN}No Meccha Chameleon Workshop maps are installed.${C_OFF}"
else
    say "  ${C_DIM}Examined ${#ITEM_DIRS[@]} Workshop map(s) and ${#MOD_DIRS[@]} mod folder(s).${C_OFF}"
fi
if [ "${#BLIND_FILES[@]}" -gt 0 ]; then
    # Deliberately quiet: this is normal for most Unreal maps, not a warning
    # sign. It is here so the result is honest about what was examined.
    say "  ${C_DIM}Could not look inside ${#BLIND_FILES[@]} map file(s) because they are compressed or${C_OFF}"
    say "  ${C_DIM}encrypted -- normal for Unreal maps, but a malware marker inside them${C_OFF}"
    say "  ${C_DIM}would not be seen. The map ID and file fingerprint checks still apply.${C_OFF}"
    for (( i = 0; i < ${#BLIND_FILES[@]}; i++ )); do
        if [ "$i" -ge 5 ]; then
            say "  ${C_DIM}    ...and $(( ${#BLIND_FILES[@]} - 5 )) more${C_OFF}"
            break
        fi
        say "  ${C_DIM}    ${BLIND_FILES[$i]} (${BLIND_REASONS[$i]})${C_OFF}"
    done
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

    BEHAV_MIN_SCORE=6      # total weight needed to report a file
    BEHAV_MIN_CATS=2       # ...in at least this many different categories
    BEHAV_MAX_BYTES=524288 # only analyse the first 512 KB of any script

    # Rules live in behaviour-rules.tsv so both scanners share one definition.
    # Losing them must not silently turn the deep scan into a no-op, so a
    # missing or empty rule file disables --deep loudly instead of quietly
    # reporting "nothing behaving suspiciously".
    BEHAV_RULES_FILE="$SCRIPT_DIR/behaviour-rules.tsv"
    BEHAV_RULE_COUNT=0
    if [ -r "$BEHAV_RULES_FILE" ]; then
        BEHAV_RULE_COUNT=$(grep -cvE '^[[:space:]]*(#|$)' "$BEHAV_RULES_FILE" 2>/dev/null || echo 0)
    fi
    if [ "$BEHAV_RULE_COUNT" -lt 5 ]; then
        abort "ERROR: --deep needs behaviour-rules.tsv, which is missing or unreadable:" \
              "       $BEHAV_RULES_FILE" \
              "       Re-download the tool and keep all files together in one folder." \
              "       Refusing to report 'nothing suspicious' from a scan that could not run."
    fi

    # Files worth analysing, and files merely worth noticing by location.
    #
    # These MUST be arrays. As a plain string the unquoted "*.bat" is glob
    # expanded against the current directory before find ever sees it, which
    # silently corrupts the expression and makes the whole deep scan match
    # nothing -- it looks like a clean result rather than a broken one.
    BEHAV_EXEC_EXT=( -iname '*.bat' -o -iname '*.cmd' -o -iname '*.ps1' -o -iname '*.psm1'
                     -o -iname '*.vbs' -o -iname '*.vbe' -o -iname '*.js' -o -iname '*.jse'
                     -o -iname '*.wsf' -o -iname '*.hta' )
    ODD_IN_DOCS_EXT=( -iname '*.bat' -o -iname '*.cmd' -o -iname '*.vbs' -o -iname '*.js'
                      -o -iname '*.wsf' -o -iname '*.hta' -o -iname '*.scr'
                      -o -iname '*.pif' -o -iname '*.lnk' )

    declare -A BEHAV_SEEN   # dedupe: a file reachable by two paths reports once

    # ---- de-obfuscation -----------------------------------------------------
    #
    # Attackers break up their own command names so a literal search misses
    # them: caret escapes in batch (p^o^w^e^r^s^h^e^l^l), backticks in
    # PowerShell (i`w`r), and quote-splitting ('i'+'wr'). We score the file
    # twice -- once as written, once with those tricks undone -- and keep the
    # higher result. The obfuscation itself is also scored, since nothing
    # legitimate needs to disguise its own commands.
    behav_deobfuscate() {
        sed -e 's/\^//g' -e 's/`//g' \
            -e "s/'[ \t]*+[ \t]*'//g" -e 's/"[ \t]*+[ \t]*"//g' \
            -e 's/[ \t][ \t]*/ /g'
    }

    # PowerShell -EncodedCommand payloads are UTF-16LE base64. Decode any long
    # base64 run and append the plaintext, so a fully encoded dropper is scored
    # on what it actually does rather than on the single fact that it is
    # encoded. This is the difference between catching and missing the most
    # obvious evasion available.
    behav_decode_b64() {
        local blob decoded
        while IFS= read -r blob; do
            decoded="$(printf '%s' "$blob" | base64 -d 2>/dev/null | LC_ALL=C tr -d '\000' | tr 'A-Z' 'a-z')"
            [ -n "$decoded" ] && printf '%s\n' "$decoded"
        done < <(grep -oE '[A-Za-z0-9+/]{40,}={0,2}' 2>/dev/null | head -20)
    }

    # ---- scoring ------------------------------------------------------------
    behav_score() {  # behav_score <text-file>; sets B_SCORE, B_CATS, B_WHY
        local hay="$1" w cat rx desc cats="" why="" n
        B_SCORE=0; B_CATS=0; B_WHY=""

        while IFS=$'\t' read -r w cat rx desc; do
            case "$w" in ''|'#'*) continue ;; esac
            [ -n "$rx" ] || continue
            if LC_ALL=C grep -qiE -- "$rx" "$hay" 2>/dev/null; then
                B_SCORE=$((B_SCORE + w))
                case " $cats " in *" $cat "*) ;; *) cats="$cats $cat" ;; esac
                case "$why" in *"$desc"*) ;; *) why="${why}${desc}; " ;; esac
            fi
        done < <(grep -vE '^[[:space:]]*(#|$)' "$BEHAV_RULES_FILE")

        # Count-based signals the rule table cannot express: heavy caret or
        # backtick use is obfuscation regardless of what is being hidden.
        n=$(LC_ALL=C grep -oE '\^' "$hay" 2>/dev/null | wc -l)
        if [ "$n" -ge 4 ]; then
            B_SCORE=$((B_SCORE + 3))
            case " $cats " in *" obfuscation "*) ;; *) cats="$cats obfuscation" ;; esac
            why="${why}disguises its commands with escape characters; "
        fi
        n=$(LC_ALL=C grep -oE '`' "$hay" 2>/dev/null | wc -l)
        if [ "$n" -ge 4 ]; then
            B_SCORE=$((B_SCORE + 2))
            case " $cats " in *" obfuscation "*) ;; *) cats="$cats obfuscation" ;; esac
            why="${why}disguises its commands with escape characters; "
        fi

        B_CATS=$(printf '%s' "$cats" | wc -w)
        B_WHY="${why%; }"
    }

    behav_analyse_file() {  # returns 0 and sets B_* if the file should be reported
        local f="$1" raw tmp best_score=0 best_cats=0 best_why=""
        [ -r "$f" ] || return 1
        raw="$(mktemp)" || return 1
        tmp="$(mktemp)" || { rm -f "$raw"; return 1; }

        # Keep a case-preserved copy. Base64 is case-sensitive, so decoding has
        # to read this rather than the lowercased text used for matching --
        # decoding a lowercased payload silently yields nothing, which looks
        # exactly like "the file was not obfuscated".
        LC_ALL=C head -c "$BEHAV_MAX_BYTES" "$f" 2>/dev/null \
            | LC_ALL=C tr -d '\000' > "$raw"

        # Pass 1: as written.
        tr 'A-Z' 'a-z' < "$raw" > "$tmp"
        behav_score "$tmp"
        best_score=$B_SCORE; best_cats=$B_CATS; best_why=$B_WHY

        # Pass 2: obfuscation undone, plus whatever the base64 decodes to.
        {
            behav_deobfuscate < "$tmp"
            behav_decode_b64  < "$raw"
        } > "${tmp}.d" 2>/dev/null
        behav_score "${tmp}.d"
        if [ "$B_SCORE" -gt "$best_score" ]; then
            best_score=$B_SCORE; best_cats=$B_CATS; best_why=$B_WHY
        fi

        rm -f "$raw" "$tmp" "${tmp}.d"
        B_SCORE=$best_score; B_CATS=$best_cats; B_WHY=$best_why
        [ "$B_SCORE" -ge "$BEHAV_MIN_SCORE" ] && [ "$B_CATS" -ge "$BEHAV_MIN_CATS" ]
    }

    # -- B1/B2: scripts near the drop location ------------------------------
    # Documents is a place for documents. A script sitting there is already
    # odd; a script sitting there that hides itself and downloads something is
    # the thing we are actually looking for. Depth 3 because a dropper can just
    # as easily write into a subfolder.
    for d in "${DROP_DIRS[@]}"; do
        [ -d "$d" ] || continue
        while IFS= read -r -d '' f; do
            [ -n "${BEHAV_SEEN[$f]:-}" ] && continue
            if behav_analyse_file "$f"; then
                BEHAV_SEEN[$f]=1
                note "This script behaves like the malware: $B_WHY" "$f"
            fi
        done < <(find "$d" -maxdepth 3 -type f \( "${BEHAV_EXEC_EXT[@]}" \) -print0 2>/dev/null)

        # Anything left over merely sits somewhere slightly odd. Collected as
        # context rather than reported as a finding.
        while IFS= read -r -d '' f; do
            [ -n "${BEHAV_SEEN[$f]:-}" ] && continue
            BEHAV_SEEN[$f]=1
            info "$f"
        done < <(find "$d" -maxdepth 3 -type f \( "${ODD_IN_DOCS_EXT[@]}" \) -print0 2>/dev/null)
    done

    # -- B3: Unreal capability abuse inside Workshop maps -------------------
    # A community map is scenery. It has no legitimate reason to reach for the
    # user's home directory or launch a process. Spotting the CAPABILITY rather
    # than the payload is what catches a malicious map nobody has reported yet.
    #
    # Two or more distinct capability strings are required. A single incidental
    # match inside a large binary is not worth frightening anyone over; writing
    # a file AND launching something is a different matter.
    CAP_PAT='getplatformuserdir|savestringtofile|savestringarraytofile|executeconsolecommand|launchurl|createproc|bp_rce|filesavedialog|writestringtofile'
    for mapdir in "${ITEM_DIRS[@]:-}" "${MOD_DIRS[@]:-}"; do
        [ -n "$mapdir" ] || continue
        while IFS= read -r -d '' pak; do
            [ -n "${BEHAV_SEEN[$pak]:-}" ] && continue
            hits="$(LC_ALL=C tr -d '\000' < "$pak" 2>/dev/null | tr 'A-Z' 'a-z' \
                    | grep -oE "$CAP_PAT" 2>/dev/null | sort -u | head -4)"
            hitcount=$(printf '%s' "$hits" | grep -c . || true)
            if [ "${hitcount:-0}" -ge 2 ]; then
                BEHAV_SEEN[$pak]=1
                note "A map can write files or launch programs, which maps do not need ($(printf '%s' "$hits" | tr '\n' ' '))" "$pak"
            fi
        done < <(find "$mapdir" -type f \( -iname '*.pak' -o -iname '*.utoc' -o -iname '*.ucas' \) -print0 2>/dev/null)
    done

    # -- B4: evidence that something already ran ----------------------------
    # The only checks here that can still find anything after the files have
    # been deleted. On Linux the game runs under Proton, so the Windows-side
    # traces live inside the Wine prefix registry rather than the real system.
    if [ "$SYNTHETIC" = 0 ]; then
        for root in "${STEAM_ROOTS[@]:-}"; do
            pfx="$root/steamapps/compatdata/$APPID/pfx"
            [ -d "$pfx" ] || continue

            # Only Run-key entries that actually invoke a script. Matching any
            # mention of .bat anywhere in the registry was far too noisy.
            for reg in "$pfx/user.reg" "$pfx/system.reg"; do
                [ -r "$reg" ] || continue
                while IFS= read -r hit; do
                    note "The game's Windows environment runs a script at startup" "$reg: $(printf '%.90s' "$hit")"
                done < <(grep -iE '\\run\\|\\runonce\\' -A 12 "$reg" 2>/dev/null \
                         | grep -iE '\.(bat|cmd|vbs|js|hta)\b|powershell' | head -3)
            done

            while IFS= read -r -d '' f; do
                [ -n "${BEHAV_SEEN[$f]:-}" ] && continue
                BEHAV_SEEN[$f]=1
                if behav_analyse_file "$f"; then
                    note "A script inside the game's Windows environment behaves like the malware: $B_WHY" "$f"
                else
                    note "A leftover script is inside the game's Windows environment" "$f"
                fi
            done < <(find "$pfx/drive_c" -maxdepth 6 -type f \( -iname '*.bat' -o -iname '*.cmd' \) -print0 2>/dev/null)
        done
    fi

    if [ "$NOTE_COUNT" -eq 0 ]; then
        say "  ${C_GRN}Nothing behaving suspiciously.${C_OFF}"
    fi

    # Context, printed quietly and only if there is something to say.
    if [ "${#INFO_LINES[@]}" -gt 0 ]; then
        say ""
        say "  ${C_DIM}For reference, ${#INFO_LINES[@]} program-type file(s) live in your documents"
        say "  folders. That is normal on plenty of PCs and none of them behaved"
        say "  suspiciously above -- listed only so you can recognise anything you"
        say "  did not put there yourself:${C_OFF}"
        local_n=0
        for l in "${INFO_LINES[@]}"; do
            local_n=$((local_n + 1))
            [ "$local_n" -gt 8 ] && { say "  ${C_DIM}    ...and $(( ${#INFO_LINES[@]} - 8 )) more${C_OFF}"; break; }
            say "  ${C_DIM}    $l${C_OFF}"
        done
    fi

    say "  ${C_DIM}Applied $BEHAV_RULE_COUNT behaviour rules.${C_OFF}"
    say ""
fi

# ----------------------------------------------------------------- verdict

say "  ${C_DIM}--------------------------------------------------------------${C_OFF}"
say ""

EXIT=0
VERDICT="no_known_indicators"; RESULT_TEXT="no known indicators found"
# Carried in --json output on every verdict, so a fleet dashboard that shows
# only the verdict still cannot present "no findings" as "clean".
CAVEAT="No known indicators is not proof a system is clean. The second stage of this attack was never captured, so what it leaves behind is unknown."
if [ "$FOUND_COUNT" -gt 0 ] || [ "$SUSPECT_COUNT" -gt 0 ]; then
    EXIT=1
    VERDICT="indicators_found"; RESULT_TEXT="INDICATORS FOUND"
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
    VERDICT="worth_a_look"; RESULT_TEXT="no known indicators found; behaviour worth a look"
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
    printf 'Result: %s\n\n' "$RESULT_TEXT"
    printf '%s\n' "${REPORT_LINES[@]}"
} >"$REPORT_FILE" 2>/dev/null \
    && printf '  %sA copy of this report was saved to:%s\n  %s\n\n' "$C_DIM" "$C_OFF" "$REPORT_FILE" >&3 \
    || REPORT_FILE=""

# ------------------------------------------------------------ --json result
#
# The schema is documented in docs/HOW-IT-WORKS.md and is a promise: fleet
# scripts parse it. Add fields freely; renaming or removing one means bumping
# "schema".

if [ "$JSON" = 1 ]; then
    join_json() { local IFS=,; printf '%s' "$*"; }
    libs=(); for r in "${STEAM_ROOTS[@]:-}"; do [ -n "$r" ] && libs+=("$(json_str "$r")"); done
    ctx=();  for c in "${INFO_LINES[@]:-}";  do [ -n "$c" ] && ctx+=("$(json_str "$c")"); done
    blind=()
    for (( i = 0; i < ${#BLIND_FILES[@]}; i++ )); do
        blind+=("{\"path\":$(json_str "${BLIND_FILES[$i]}"),\"reason\":$(json_str "${BLIND_REASONS[$i]}")}")
    done
    printf '{"schema":1,"tool":"meccha-chameleon-checker","platform":"linux"'
    printf ',"host":%s'               "$(json_str "$(uname -n 2>/dev/null)")"
    printf ',"scan_date":%s'          "$(json_str "$(date -u +%Y-%m-%dT%H:%M:%SZ)")"
    printf ',"indicators_updated":%s' "$(json_str "$(grep -oE '"updated"[^,]*' "$INDICATORS" | grep -oE '[0-9-]{10}')")"
    printf ',"deep":%s'               "$([ "$DEEP" = 1 ] && echo true || echo false)"
    printf ',"exit_code":%s,"verdict":"%s"' "$EXIT" "$VERDICT"
    printf ',"counts":{"found":%s,"suspicious":%s,"worth_a_look":%s}' \
        "$FOUND_COUNT" "$SUSPECT_COUNT" "$NOTE_COUNT"
    printf ',"findings":[%s]'         "$(join_json "${FINDINGS_JSON[@]:-}")"
    printf ',"context_files":[%s]'    "$(join_json "${ctx[@]:-}")"
    printf ',"uninspected_files":[%s]' "$(join_json "${blind[@]:-}")"
    printf ',"steam_libraries":[%s]'  "$(join_json "${libs[@]:-}")"
    printf ',"report_file":%s'        "$([ -n "$REPORT_FILE" ] && json_str "$REPORT_FILE" || echo null)"
    printf ',"caveat":%s}\n'          "$(json_str "$CAVEAT")"
fi

exit "$EXIT"
