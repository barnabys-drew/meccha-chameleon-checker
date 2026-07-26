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

# ------------------------------------------------------------------ summary

rm -f "$REPO"/meccha-check-report-*.txt 2>/dev/null

echo
echo "  ============================================"
printf '   %d passed, %d failed\n' "$PASS" "$FAIL"
echo "  ============================================"
echo
[ "$FAIL" -eq 0 ] || exit 1
