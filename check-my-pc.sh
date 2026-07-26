#!/usr/bin/env bash
# ===================================================================
#  Meccha Chameleon Workshop malware checker
#
#  Run this to check your PC:   ./check-my-pc.sh
#
#  This only LOOKS at your computer and tells you what it finds.
#  It never deletes, moves or changes anything.
#
#  All it does is start scan-linux.sh, which sits next to this file
#  and which you are welcome to read first.
# ===================================================================

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$HERE/scan-linux.sh" ]; then
    echo
    echo "  ERROR: scan-linux.sh was not found next to this file."
    echo "  Please keep all the downloaded files together in one folder."
    echo
    exit 2
fi

bash "$HERE/scan-linux.sh" "$@"
RESULT=$?

# Keep the window open when launched by double-clicking from a file manager.
if [ ! -t 0 ]; then
    echo
    echo "  Press Enter to close this window."
    read -r _ || true
fi

exit "$RESULT"
