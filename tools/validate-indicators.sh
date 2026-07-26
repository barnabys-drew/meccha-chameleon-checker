#!/usr/bin/env bash
# Validates indicators.json before it can reach main.
#
# This is the gate on the IOC update process. A bad indicator in a public
# malware checker is not a cosmetic bug -- it tells innocent people they are
# infected, or worse, quietly stops matching a real one. Every rule below
# exists to catch a specific way that can happen.
#
# Usage:  bash tools/validate-indicators.sh [path-to-indicators.json]
# Exit:   0 valid, 1 invalid

set -uo pipefail

FILE="${1:-$(dirname "$(dirname "$(readlink -f "$0")")")/indicators.json}"
ERRORS=0
WARNINGS=0

err()  { printf '  \033[1;31mERROR\033[0m    %s\n' "$1"; ERRORS=$((ERRORS+1)); }
warn() { printf '  \033[1;33mWARN\033[0m     %s\n' "$1"; WARNINGS=$((WARNINGS+1)); }
ok()   { printf '  \033[1;32mOK\033[0m       %s\n' "$1"; }

echo
echo "  Validating: $FILE"
echo "  ------------------------------------------------------------"

[ -r "$FILE" ] || { err "file not readable"; echo; exit 1; }

# --- 1. Must be parseable by both scanners -----------------------------------
# The Windows scanner uses ConvertFrom-Json, which is strict. Catch the common
# hand-edit mistakes that would make it throw.

if grep -qE ',[[:space:]]*[}\]]' "$FILE"; then
    err "trailing comma before a closing brace or bracket -- PowerShell's ConvertFrom-Json will reject this"
else
    ok "no trailing commas"
fi

braces=$(tr -cd '{' < "$FILE" | wc -c); close=$(tr -cd '}' < "$FILE" | wc -c)
brack=$(tr -cd '[' < "$FILE" | wc -c);  cbrack=$(tr -cd ']' < "$FILE" | wc -c)
if [ "$braces" -ne "$close" ] || [ "$brack" -ne "$cbrack" ]; then
    err "unbalanced braces/brackets ({ $braces } $close  [ $brack ] $cbrack)"
else
    ok "braces and brackets balanced"
fi

# --- 2. Required fields the scanners depend on -------------------------------

for field in steam_appid malicious_workshop_ids file_hashes_sha256 content_strings dropped_filenames updated; do
    grep -q "\"$field\"" "$FILE" || err "missing required field: $field"
done
[ "$ERRORS" -eq 0 ] && ok "all required fields present"

appid=$(grep -oE '"steam_appid"[[:space:]]*:[[:space:]]*"[0-9]+"' "$FILE" | grep -oE '[0-9]+' | head -1)
if [ -z "$appid" ]; then
    err "steam_appid missing or not a quoted number"
elif [ "$appid" != "4704690" ]; then
    warn "steam_appid is $appid, expected 4704690 (Meccha Chameleon)"
else
    ok "steam_appid correct ($appid)"
fi

# --- 3. Hashes must be real SHA256 values ------------------------------------
# A truncated or uppercase hash silently never matches. The scanners lowercase
# what they compute, so anything not 64 lowercase hex chars is dead weight.

hash_block=$(sed -n '/"file_hashes_sha256"/,/^[[:space:]]*}/p' "$FILE")
mapfile -t hashes < <(echo "$hash_block" | grep -oE '"[^"]+"[[:space:]]*:' | tr -d '":' | tr -d ' ' | grep -v '^file_hashes_sha256$')

bad_hash=0
for h in "${hashes[@]:-}"; do
    if ! echo "$h" | grep -qE '^[a-f0-9]{64}$'; then
        err "not a valid lowercase SHA256: '$h' (${#h} chars)"
        bad_hash=1
    fi
done
if [ "${#hashes[@]}" -eq 0 ]; then
    err "no file hashes defined -- the scanners would lose their most reliable check"
elif [ "$bad_hash" -eq 0 ]; then
    ok "${#hashes[@]} hashes, all valid lowercase SHA256"
fi

dupes=$(printf '%s\n' "${hashes[@]:-}" | sort | uniq -d)
[ -n "$dupes" ] && err "duplicate hash entries: $dupes" || ok "no duplicate hashes"

# --- 4. Workshop IDs ---------------------------------------------------------
# Steam Workshop IDs are numeric. A name accidentally placed in the id field
# would silently never match a real directory.

mapfile -t ids < <(grep -oE '"id"[[:space:]]*:[[:space:]]*"[^"]*"' "$FILE" | sed 's/.*:[[:space:]]*"//; s/"$//')
bad_id=0
for i in "${ids[@]:-}"; do
    echo "$i" | grep -qE '^[0-9]+$' || { err "Workshop id is not numeric: '$i'"; bad_id=1; }
done
if [ "${#ids[@]}" -eq 0 ]; then
    warn "no Workshop IDs listed -- check 2 will never fire"
elif [ "$bad_id" -eq 0 ]; then
    ok "${#ids[@]} Workshop ID(s), all numeric"
fi

iddupes=$(printf '%s\n' "${ids[@]:-}" | sort | uniq -d)
[ -n "$iddupes" ] && err "duplicate Workshop IDs: $iddupes" || ok "no duplicate Workshop IDs"

# --- 5. Provenance -----------------------------------------------------------
# Every ID should say where it came from. This is what stops an unsourced
# rumour from becoming an indicator that accuses real users.

id_entries=$(grep -c '"id"[[:space:]]*:' "$FILE")
sourced=$(grep -c '"source"[[:space:]]*:' "$FILE")
if [ "$id_entries" -gt "$sourced" ]; then
    warn "$id_entries Workshop ID(s) but only $sourced source link(s) -- every indicator should cite where it came from"
else
    ok "every Workshop ID cites a source"
fi

# --- 6. Content strings must be specific enough ------------------------------
# A short or generic marker (".bat", "powershell") would match innocent files
# and accuse clean users. This is the single most dangerous kind of bad IOC.

# Bounded to the first "]" after the key. A sed line range would look for the
# range end on the line AFTER the start, so a single-line array would swallow
# the next key's values -- exactly the bug this check caught in the scanner.
mapfile -t strings < <(
    tr '\n' ' ' < "$FILE" \
    | grep -oE '"content_strings"[[:space:]]*:[[:space:]]*\[[^]]*\]' \
    | sed 's/^[^[]*\[//; s/\]$//' \
    | grep -oE '"[^"]*"' | sed 's/^"//; s/"$//'
)
generic_hits=0
for s in "${strings[@]:-}"; do
    if [ "${#s}" -lt 6 ]; then
        err "content string '$s' is only ${#s} chars -- too generic, would cause false positives"
        generic_hits=1
    fi
    case "${s,,}" in
        powershell|cmd.exe|.bat|.cmd|http://|iwr|invoke-webrequest)
            err "content string '$s' is a common legitimate term -- would flag innocent files"
            generic_hits=1 ;;
    esac
done
if [ "${#strings[@]}" -eq 0 ]; then
    err "no content strings defined"
elif [ "$generic_hits" -eq 0 ]; then
    ok "${#strings[@]} content strings, all specific enough"
fi

# --- 7. Freshness ------------------------------------------------------------

updated=$(grep -oE '"updated"[[:space:]]*:[[:space:]]*"[0-9-]{10}"' "$FILE" | grep -oE '[0-9-]{10}')
if [ -z "$updated" ]; then
    err "updated field missing or not YYYY-MM-DD"
else
    age=$(( ( $(date +%s) - $(date -d "$updated" +%s 2>/dev/null || echo 0) ) / 86400 ))
    if [ "$age" -gt 90 ]; then
        warn "indicators last updated $age days ago ($updated)"
    else
        ok "updated $age day(s) ago ($updated)"
    fi
fi

# --- summary -----------------------------------------------------------------

echo "  ------------------------------------------------------------"
printf '  %d error(s), %d warning(s)\n' "$ERRORS" "$WARNINGS"
echo
[ "$ERRORS" -eq 0 ]
