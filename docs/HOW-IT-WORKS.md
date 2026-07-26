# How it works, and what it can't do yet

Technical notes for developers and security folk. If you just want to check your PC, the
[README](../README.md) is what you want instead.

The second half of this document — [**What it doesn't do**](#what-it-doesnt-do-yet) — is the useful
part if you're looking for somewhere to contribute.

---

## Design constraints

Four decisions shape everything else. Please don't quietly reverse them in a PR.

**1. Read-only. Always.**
The scanners never delete, move, quarantine or modify anything. Deleting the dropped `s.bat`
destroys evidence and does not remove the second stage, so a "clean-up" feature would make users
*less* safe while feeling more helpful.

**2. A clean result is never phrased as "you are safe."**
Stage 2 was never captured by researchers, so nobody knows what it leaves behind. Every
no-findings path says *"no known indicators were found"* and then explains what that does and
doesn't rule out. **Wording that implies a clean bill of health is a bug**, and the test suite
asserts the caveat text survives.

**3. Precision over recall, by default.**
The people running this can't triage a false positive. A scary wrong answer sends someone
wiping a drive they didn't need to wipe. IOC checks run by default; anything heuristic lives
behind `--deep` and reports in a separate tier that never claims infection.

**4. Losing the indicators must fail loudly.**
If `indicators.json` is missing, corrupt, or parses to nothing, the scanners exit `2` rather than
run with an empty indicator set. An empty set would produce a confident "nothing found" on an
infected machine — the worst possible output.

---

## Layout

| File | Role |
|---|---|
| `indicators.json` | Single source of truth. Both scanners read it; neither hardcodes an indicator. |
| `scan-windows.ps1` | Windows scanner. PowerShell 5.1, stock on Win10/11. No modules. |
| `scan-linux.sh` | Linux scanner. bash 4+, coreutils. No jq. |
| `check-my-pc.bat` / `.sh` | Double-clickable wrappers. Deliberately tiny so they can be read. |
| `check-my-pc-deep.bat` | Same, with `-Deep`. |
| `tools/validate-indicators.sh` | The gate. Runs in CI on every PR. |
| `tests/make-fixtures.*` | Generate fixture trees, run the scanners, assert behaviour. |

**Zero dependencies is a hard requirement.** The audience is a panicking teenager who just wants to
know if their PC is infected. "First install Python" loses most of them. That's why there are two
native scanners rather than one cross-platform program, and why the bash side parses JSON with
`grep`/`sed` instead of `jq`.

---

## The checks

### IOC checks (default)

| # | Check | Mechanism |
|---|---|---|
| 1 | Locate Steam | Registry / known paths → `libraryfolders.vdf` → **enumerate every drive** |
| 2 | Known-bad Workshop IDs | Directory-name match under `steamapps/workshop/content/4704690/` |
| 3 | File hashes | SHA256 of every `.pak`/`.utoc`/`.ucas` |
| 4 | Markers inside archives | Byte scan, ASCII **and** UTF-16LE |
| 5 | Dropped file | `s.bat` by hash and name, plus renamed `.bat`/`.cmd` carrying a marker |
| 6 | Persistence | Run keys, Startup, scheduled tasks / autostart, cron, systemd — **only** where the value references a known marker |

Check 1 doesn't trust `libraryfolders.vdf` alone: a drive that was disconnected, re-lettered, or
removed from Steam's library list still holds the map files. The sweep is depth-limited (3–4) and
prunes `Windows`, `AppData`, `$Recycle.Bin`, `node_modules` and friends. Without that pruning a
whole-machine scan took **64 seconds**; with it, **~3 seconds**.

Check 4 strips `NUL` bytes before matching, which turns UTF-16LE into ASCII, so one pass covers both
encodings — Unreal string literals are commonly UTF-16.

### Behaviour checks (`--deep`)

The IOC checks sit at the bottom of the Pyramid of Pain — a hash, an IP, a map ID. The attackers
re-uploaded replacement maps within hours of each takedown, so IOC-only matching is permanently one
step behind. `--deep` targets behaviour instead:

| Check | Catches | False-positive risk |
|---|---|---|
| `.bat`/`.cmd` present in Documents at all | The drop location itself | Low |
| Hidden-window **AND** fetch **AND** temp-execute | Recompiled droppers, new C2 | Low — needs 2 of 3 categories |
| Workshop pak referencing file-write / process-launch capability | Unreported malicious maps | Medium |
| Prefetch, Defender history, PowerShell 4104 | Infection whose files were deleted | Low, but needs admin |

Results report as `WORTH A LOOK` and set **exit 3**, distinct from a confirmed finding. The verdict
text opens with "Do not panic" and explains that ordinary files behave this way too.

The test suite asserts this gap rather than describing it: a fixture representing a repackaged
variant — new map ID, new hash, new C2 — is **missed by the IOC checks and caught by `--deep`**,
while a clean tree stays silent in both modes.

### Exit codes

| Code | Meaning |
|:--:|---|
| `0` | No known indicators found |
| `1` | Known indicators found |
| `2` | Scan could not run (bad/missing indicators) |
| `3` | `--deep` only: behaviour worth a look, no known indicators |

---

## Platform details worth knowing

**Linux checks the Proton prefix.** Under Steam Play, `GetPlatformUserDir()` resolves inside the
Wine prefix, so the drop lands at
`steamapps/compatdata/4704690/pfx/drive_c/users/steamuser/Documents/s.bat`. Ordinary Linux
antivirus doesn't look there. This is most of why a Linux build exists at all.

**Windows follows OneDrive redirection.** `[Environment]::GetFolderPath('MyDocuments')` returns the
redirected path on machines with OneDrive Known Folder Move — very common, and `%USERPROFILE%\Documents`
would be the wrong place to look. Both are checked.

**Indicator parsing is hand-rolled and has bitten us once.** A `sed` line range looked for its end
pattern on the line *after* the start, so with single-line JSON arrays `content_strings` silently
swallowed `dropped_filenames`. The scan still ran and still reported — it just matched the wrong
things, which normal output can't show. Hence `DUMP_INDICATORS=1`:

```bash
DUMP_INDICATORS=1 bash scan-linux.sh    # print exactly what was parsed, then exit
```

The Windows side uses `ConvertFrom-Json` and was never affected.

---

## Working on it

```bash
bash tools/validate-indicators.sh                                            # gate any indicator edit
bash tests/make-fixtures.sh                                                  # Linux suite
powershell -NoProfile -ExecutionPolicy Bypass -File tests\make-fixtures.ps1   # Windows suite
```

CI runs both suites (Linux and a real `windows-latest` runner), the validator, a JSON parse, and
shellcheck.

Fixtures are generated at runtime and gitignored. **Never commit a file containing the real payload
string** — antivirus and GitHub will flag the repo. Fixture scripts assemble markers from fragments
at runtime and everything they write is inert `echo` statements.

Testing against fixtures alone is not enough. Two bugs — the 64-second scan and a wrong-path
`dirname` — only appeared when running against a real machine with a real Steam install.

---

## What it doesn't do yet

Honest list of gaps. Several are good contributions if you have the relevant expertise; the
difficulty ratings are rough.

### 1. It cannot detect stage 2 at all — *blocked, not hard*

`steamb.bat` was never captured by any researcher. Nobody publicly knows what it installs, what it
persists as, or what it steals. Every check here targets the **dropper**. If you have a sample, or
sandbox telemetry from one, that is by far the most valuable thing you could contribute — it's the
reason the tool refuses to tell anyone they're clean.

### 2. No real `.pak` parsing — *hard, highest technical value*

Check 4 does a raw byte scan. If a map's data is compressed (Oodle/Zlib inside a UE4 pak or UE5
IoStore container), embedded strings are invisible and the check silently misses them. Proper
support means parsing the pak/utoc/ucas index and decompressing entries before scanning.

This would upgrade check 4 and the `--deep` capability check from best-effort to reliable, and it's
the single biggest detection improvement available. Needs someone comfortable with Unreal container
formats.

### 3. No Blueprint graph analysis — *hard, follows from #2*

Even with decompression, we'd be string-matching. Real detection would parse the `.uasset` Blueprint
bytecode and look for the actual node pattern: *on BeginPlay → build a path from `GetPlatformUserDir`
→ write a file → launch it.* That's a behavioural signature no amount of renaming defeats, and it
would catch malicious maps for **any** Unreal game, not just this one.

### 4. No Steam Web API integration — *medium, needs an API key*

Feint noted the malicious uploads shared metadata tells: brand-new uploader account, comments and
ratings disabled. We can't see any of that from disk. A `--online` mode could query the Workshop API
for item publish date, uploader account age and comment settings, and flag combinations. Would need
to be opt-in and key-gated, and must degrade cleanly when offline.

### 5. No fuzzy hashing — *easy-to-medium*

Exact SHA256 breaks on any recompile. ssdeep or TLSH over `.pak` files would survive minor
repackaging and cluster related samples. Adds a dependency, so it'd need to be optional — which cuts
against the zero-dependency rule, hence not done yet.

### 6. Workshop content only in the subscribed path — *easy*

Only `steamapps/workshop/content/<appid>/` is examined. Not covered: `workshop/downloads/` (partial
downloads), legacy `ugc/` paths, `steamcmd`-based installs, and manually extracted maps sitting in
the game's own `Content/Paks/~mods` folder. Straightforward to add; just needs someone with those
setups to confirm the real paths.

### 7. Thin Windows execution evidence — *medium, needs Windows internals knowledge*

Prefetch requires admin and is disabled on some systems. PowerShell 4104 script-block logging is off
by default. Not touched at all: Sysmon, ETW, `Amcache`, `ShimCache`, BAM/DAM, or `UserAssist` — any
of which could show the dropper ran after the files were deleted. Also worth adding: a short guide
telling users how to *enable* script-block logging before they need it.

### 8. No machine-readable output — *easy, good first issue*

There's no `--json`. An internet café, school lab or LAN-party organiser wanting to sweep 40
machines has to read 40 terminal windows. A stable JSON schema on stdout (with the human text on
stderr) would make fleet use practical.

### 9. No evidence-collection mode — *medium, needs care*

Deliberately no quarantine. But a `--collect` that copies the flagged files into a password-protected
zip, with hashes and a manifest, would help users hand something to a responder or AV vendor without
mailing live malware around. Must never auto-upload anywhere.

### 10. English only — *easy, high reach*

Meccha Chameleon sold 15M+ copies worldwide; the malicious maps didn't care what language anyone
speaks. All user-facing strings are inline in both scanners. Extracting them into a simple message
table and accepting community translations would widen who this can actually help.

### 11. No macOS — *unclear whether it's needed*

There's no macOS scanner. If the game ships or gains a native macOS build, or people play it through
Crossover/Whisky, the same Wine-prefix logic as Linux would mostly apply. Worth doing only if someone
confirms real users in that situation.

### 12. Unsigned scripts — *easy to describe, costs money to fix*

Windows shows a SmartScreen warning because nothing here is code-signed. A certificate costs real
money, and an unsigned binary from a security repo is arguably worse optics than a readable script,
so this is documented rather than solved.

---

## Contributing an indicator

See [IOC-PROCESS.md](IOC-PROCESS.md). Short version: every indicator cites a source, one source is a
lead rather than an indicator, the validator rejects over-generic strings, and **nothing reaches
`main` without a human approving it**. A weekly scheduled agent proposes updates as pull requests; it
is not permitted to merge them.
