# Meccha Chameleon Workshop Malware Checker

A small, free tool that checks whether your PC shows any of the **known** signs of the malware that
was distributed through Meccha Chameleon Steam Workshop maps in July 2026.

It only looks and tells you what it finds. **It never deletes, moves or changes anything.**

## What happened

In July 2026, several community-made maps for **Meccha Chameleon** on the Steam Workshop turned out
to be malware droppers. Loading an infected map would:

1. Silently write a file called `s.bat` into your **Documents** folder.
2. Briefly flash a black command-prompt window — the thing players noticed.
3. Quietly run PowerShell in a hidden window to download a second program from an attacker's server.

Independent researcher **Feint** published the technical breakdown on 24 July 2026. The game's
developer patched the underlying issue in version **3.2.0**, and Valve removed the maps that were
reported — but replacement malicious maps appeared within hours of each takedown.

**You may be affected if you subscribed to any custom Meccha Chameleon map before the 3.2.0 update.**
The base game itself was never infected.

## How to use it

Download this folder ([**Code → Download ZIP**](../../archive/refs/heads/main.zip)), unzip it, and
keep the files together in one folder.

**Windows** — double-click **`check-my-pc.bat`**. Nothing to install.

**Linux** — open a terminal in the folder and run:

```bash
chmod +x check-my-pc.sh
./check-my-pc.sh
```

A typical scan takes a few seconds. When it finishes it saves a copy of the results as
`meccha-check-report-<date>.txt` next to the tool, which you can paste into a help thread if you
need to ask someone for advice.

### How to read the result

**If it finds nothing** — that means none of the known indicators are on your system. It does
**not** mean you are definitely clean. The second-stage program this malware downloaded was never
captured by researchers, so nobody publicly knows exactly what it installs or what traces it leaves.
This tool cannot look for something nobody has seen.

If you saw a command window flash while loading a custom map, treat a clean result with suspicion:
run a full antivirus scan and change your passwords from a different device anyway.

**If it finds something** — the tool prints step-by-step instructions. The short version: disconnect
from the internet, do not delete anything yet (it is evidence, and deleting it does not remove the
second stage), run a full Defender or Malwarebytes scan, and change your passwords and re-set your
two-factor authentication **from a different device**.

## What it checks

| # | Check |
|---|---|
| 1 | Finds your Steam libraries **on every drive**, not just the default folder |
| 2 | Looks for known malicious Workshop map IDs |
| 3 | Compares map files (`.pak`, `.utoc`, `.ucas`) against known malicious file fingerprints |
| 4 | Scans inside map files for known malware markers, in both plain text and UTF-16 |
| 5 | Looks for the dropped `s.bat` file, and renamed copies of it |
| 6 | Looks for startup entries, scheduled tasks and cron jobs that refer to the malware |

Drive detection does not rely on Steam's own `libraryfolders.vdf` alone. A drive that was
disconnected, re-lettered or removed from Steam's library list can still hold an infected map on
disk, so the tool enumerates the drives themselves. On Linux it also looks inside the **Proton
prefix**, which is where the dropped file actually lands when you play through Steam Play — ordinary
Linux antivirus will not look there.

### Limitations, stated plainly

- It detects the **dropper**, not the second stage. The second stage was never publicly analysed.
- The search for Steam libraries is depth-limited and skips system folders, so a library buried
  somewhere very unusual could be missed. Any library the tool did find is listed in the output.
- Scanning inside map files can miss a marker if the map's data is compressed. Checks 2 and 3 are
  the reliable ones; check 4 is a bonus.
- It is not an antivirus and is no substitute for one.

## Indicators

All indicators live in [`indicators.json`](indicators.json) so they can be audited and updated
independently of the scanning code, and so both scanners always agree. If the file is missing or
corrupt, the scanners exit with an error rather than report a misleading "clean" result.

## Testing

The test suites build a throwaway fixture tree — an infected one and a clean one — and assert that
every check fires, that an innocent map is *not* flagged, and that the caveat text survives:

```bash
bash tests/make-fixtures.sh                                              # Linux
powershell -NoProfile -ExecutionPolicy Bypass -File tests\make-fixtures.ps1   # Windows
```

Fixtures are generated at runtime and never committed: a repo containing a `.bat` with the real
payload string would be flagged by antivirus and by GitHub. The generated fixtures are inert — echo
statements only — and the marker strings are assembled from fragments at runtime.

Exit codes: `0` nothing found, `1` indicators found, `2` the scan could not run.

## Credits and disclaimer

- Malware analysis and all indicators: [Feint — *Workshop map for MECCHA CHAMELEON is a malware dropper (full breakdown)*](https://medium.com/@FeintBE/workshop-map-for-meccha-chameleon-is-a-malware-dropper-full-breakdown-d1ac29565265)
- Background reporting: [Kotaku](https://kotaku.com/multiple-meccha-chameleon-steam-workshop-maps-got-infected-with-malware-and-its-discord-server-was-hacked-2000719315), [Windows Central](https://www.windowscentral.com/gaming/pc-gaming/meccha-chameleon-steam-workshop-malware)

This project is **unofficial** and is not affiliated with, endorsed by, or connected to Lemorion or
Valve. It is provided as-is, without warranty of any kind. See [LICENSE](LICENSE).
