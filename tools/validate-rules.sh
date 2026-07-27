#!/usr/bin/env bash
# Validates behaviour-rules.tsv before it can reach main.
#
# Both scanners read this one file, so a bad rule breaks detection on two
# platforms at once -- and does it quietly. A rule that fails to compile is
# skipped at runtime, which looks exactly like "nothing suspicious found".
#
# Usage:  bash tools/validate-rules.sh [path]
# Exit:   0 valid, 1 invalid

set -uo pipefail

FILE="${1:-$(dirname "$(dirname "$(readlink -f "$0")")")/behaviour-rules.tsv}"
ERRORS=0
WARNINGS=0

err()  { printf '  \033[1;31mERROR\033[0m    %s\n' "$1"; ERRORS=$((ERRORS+1)); }
warn() { printf '  \033[1;33mWARN\033[0m     %s\n' "$1"; WARNINGS=$((WARNINGS+1)); }
ok()   { printf '  \033[1;32mOK\033[0m       %s\n' "$1"; }

echo
echo "  Validating: $FILE"
echo "  ------------------------------------------------------------"

[ -r "$FILE" ] || { err "file not readable"; echo; exit 1; }

TOTAL=0; LINENO_=0
declare -A SEEN_RX
BADFIELDS=0; BADWEIGHT=0; BADRX=0; POSIX=0; DUPES=0

while IFS= read -r line; do
    LINENO_=$((LINENO_ + 1))
    case "$line" in ''|'#'*) continue ;; esac

    # Exactly four tab-separated fields.
    nf=$(printf '%s' "$line" | awk -F'\t' '{print NF}')
    if [ "$nf" -ne 4 ]; then
        err "line $LINENO_: expected 4 tab-separated fields, found $nf"
        BADFIELDS=1
        continue
    fi
    TOTAL=$((TOTAL + 1))

    w=$(printf '%s' "$line"   | cut -f1)
    cat_=$(printf '%s' "$line"| cut -f2)
    rx=$(printf '%s' "$line"  | cut -f3)
    desc=$(printf '%s' "$line"| cut -f4)

    # Weight must be a small positive integer.
    if ! printf '%s' "$w" | grep -qE '^[1-5]$'; then
        err "line $LINENO_: weight '$w' should be 1-5"; BADWEIGHT=1
    fi

    # Category must be a simple lowercase token.
    if ! printf '%s' "$cat_" | grep -qE '^[a-z][a-z_]*$'; then
        err "line $LINENO_: category '$cat_' should be lowercase letters/underscores"
    fi

    # POSIX bracket classes work in grep but NOT in .NET. A rule using one
    # matches on Linux and silently never fires on Windows -- the two scanners
    # would disagree and nobody would notice.
    if printf '%s' "$rx" | grep -qE '\[\[:[a-z]+:\]\]'; then
        err "line $LINENO_: regex uses a POSIX class ([[:space:]] etc), which .NET cannot parse -- use [ \\t] or [a-z0-9]"
        POSIX=1
    fi

    # The regex must actually compile, or it is silently skipped at runtime.
    if ! printf '' | grep -qE -- "$rx" 2>/dev/null; then
        if ! echo "test" | grep -qE -- "$rx" >/dev/null 2>&1; then
            if ! printf 'x' | grep -E -- "$rx" >/dev/null 2>&1; then
                # grep returns 1 for "no match" and 2 for "bad regex"; only 2 is fatal
                printf 'x' | grep -E -- "$rx" >/dev/null 2>&1
                [ $? -ge 2 ] && { err "line $LINENO_: regex does not compile: $rx"; BADRX=1; }
            fi
        fi
    fi

    # Duplicate regexes double-count a signal and skew the score.
    if [ -n "${SEEN_RX[$rx]:-}" ]; then
        err "line $LINENO_: duplicate regex also on line ${SEEN_RX[$rx]}"; DUPES=1
    else
        SEEN_RX[$rx]=$LINENO_
    fi

    # Descriptions are read by frightened non-technical people.
    [ -n "$desc" ] || err "line $LINENO_: description is empty"
    if printf '%s' "$desc" | grep -qiE 'regex|payload|c2|exfil|lolbin|ttp'; then
        warn "line $LINENO_: description uses jargon a non-technical user will not know: '$desc'"
    fi
done < "$FILE"

[ "$BADFIELDS" = 0 ] && ok "every rule has 4 tab-separated fields"
[ "$BADWEIGHT" = 0 ] && ok "all weights are 1-5"
[ "$POSIX"     = 0 ] && ok "no POSIX classes (Windows/.NET compatible)"
[ "$BADRX"     = 0 ] && ok "all regexes compile"
[ "$DUPES"     = 0 ] && ok "no duplicate regexes"

if [ "$TOTAL" -lt 20 ]; then
    err "only $TOTAL rules -- the deep scan needs a meaningful rule set to be worth running"
else
    ok "$TOTAL rules loaded"
fi

# Every category the scanners score against should exist, or the two-category
# threshold becomes impossible to reach in that dimension.
for c in concealment download staging obfuscation persistence self_relaunch lolbin; do
    if ! cut -f2 "$FILE" 2>/dev/null | grep -qx "$c"; then
        warn "no rules in category '$c'"
    fi
done
ok "category coverage checked"

echo "  ------------------------------------------------------------"
printf '  %d error(s), %d warning(s)\n' "$ERRORS" "$WARNINGS"
echo
[ "$ERRORS" -eq 0 ]
