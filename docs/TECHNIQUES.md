# Techniques this campaign can use that we cannot yet see

`indicators.json` holds what researchers published about the *observed* July 2026 dropper: a
Blueprint, an `s.bat`, one IP, four hashes. This file holds the layer above that — the
**capabilities a malicious Meccha Chameleon map has been shown to have**, whether or not anyone has
caught a map using them yet.

It exists because the two are maintained differently. An indicator is dead the moment the attacker
changes a byte. A capability stays true until the engine or the game removes it, and it tells us
*where to look* even for a map nobody has catalogued.

Nothing in this file is a detection. Nothing here matched a user's PC. Each entry says plainly what
is established, what is inferred, and what the scanners would have to do to cover it.

---

## T1 — Arbitrary file write via audio submix output recording

**Status:** disclosed publicly 2026-09-03, reported patched in game version 4.0.0 (2026-08-20).
**Seen in the wild:** no. No malicious map is known to have used this.
**Priority:** 1 (new Unreal capability abuse + a new persistence path).

Unreal's submix output recording is exposed to Blueprints, and the node that finishes a recording
takes both an output directory and a filename from whoever calls it. A map author controls both.

Reported details:

- The default output directory is `%LOCALAPPDATA%\Chameleon\Saved\BouncedWavFiles`.
- An absolute path, or `../` traversal, escapes that directory and writes anywhere the user can
  write.
- Unreal appends `.wav` to the supplied name, so Windows would treat the result as audio. The
  reported bypass is an embedded NUL (`\u0000`) in the filename: lower-level APIs truncate at the
  NUL and discard the appended extension, leaving the attacker in control of the real one.
- The payoff target is the per-user Startup folder,
  `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, whose contents Windows runs at logon.

Net effect: a map that only *loads* can drop an executable that runs at the next restart. That is
why the sources call it a delayed RCE — nothing suspicious happens while the game is running.

**Why the current scanners miss it.** Check 6 looks at startup locations, but it only reports an
entry that *refers to a known indicator* (`s.bat`, `steamb.bat`, a `content_strings` entry). A
payload dropped here under a fresh name contains none of those. `--deep` does not help either: it
scores script text against `behaviour-rules.tsv`, and the dropped file is a binary with no script
content to score. The existing `\\start menu\\programs\\startup` persistence rule matches a *script
that mentions* the Startup folder, not a file sitting in it.

**Proposed `--deep` coverage.** Three filesystem checks, none of which can be written as a
`behaviour-rules.tsv` regex, because the signal is a file's location and type rather than its text:

1. **A `.wav` in the Startup folder.** Nothing legitimate autostarts an audio file. If the NUL
   trick fails, or a map author does not bother with it, this is exactly what the write leaves
   behind. Essentially zero false-positive risk.
2. **Any file in the Startup folder whose magic bytes are `RIFF....WAVE`, whatever its
   extension.** This is the case where the NUL trick worked and the file is named `update.exe` but
   is still really the recorded submix output. Cheap to check, and a RIFF/WAVE file masquerading
   under an executable extension in Startup has no innocent explanation.
3. **Non-`.wav` files in `%LOCALAPPDATA%\Chameleon\Saved\BouncedWavFiles`, or names in it
   containing `..`.** This directory is a legitimate game path — its *existence* means nothing and
   must not be reported. Only unexpected contents are interesting.

Report all three as "worth a look", never as a confirmed finding: a user who genuinely recorded game
audio will have real `.wav` files in the bounced-files directory, and check 3 could see an odd name
for dull reasons.

---

## T2 — Code execution via the `LaunchURL` Blueprint node

**Status:** disclosed alongside T1; also covered independently in an earlier writeup
("2-Click Remote Code Execution in Meccha Chameleon").
**Seen in the wild:** no.
**Priority:** 1 (capability abuse, and it survives any repackaging of the July dropper).

`LaunchURL` reads as a node for opening a web page. Underneath it calls

```
ShellExecuteW(NULL, "open", URL, NULL, NULL, SW_SHOWNORMAL)
```

The `"open"` verb is not restricted to URLs. Handed a local path, it does what double-clicking that
path does — including running an executable. A map's Blueprint runs automatically on `BeginPlay`
when the map loads on every client in the lobby, so a map that ships a binary inside its own
Workshop item and then points `LaunchURL` at it executes code on load.

This matters even though T2 is patched: it is a second, independent route to the same outcome as the
July dropper, and it needs no `s.bat`, no PowerShell, and no C2 address. Every indicator in
`indicators.json` would miss it.

**Why the current scanners miss it.** Checks 2–4 hash map files and search them for known strings.
A map item carrying a plain `payload.exe` alongside its `.pak`/`.utoc`/`.ucas` trips none of that —
the executable is not a known hash and the Blueprint call is compiled into the container.

**Proposed coverage.** Flag an executable file type inside any Workshop item directory under
`steamapps/workshop/content/4704690/`. A Meccha Chameleon map item should contain map containers and
metadata; `.exe`, `.dll`, `.scr`, `.bat`, `.cmd`, `.ps1` and `.lnk` have no business in one. This
sits naturally beside the existing map checks and should be a high-signal, low-false-positive
check — but it is a new check rather than a new rule line, so it belongs in a reviewed change of its
own, with fixtures, not in a rules file.

---

## Remediation advice may now be stale

Both scanners and the README tell the user:

> Meccha Chameleon is updated to version **3.2.0 or later**.

`scan-linux.sh:850`, `scan-windows.ps1:865`, `README.md:153`.

If 4.0.0 is genuinely the release that fixes T1 and T2, then 3.2.0 is no longer a sufficient
version to name — a user sitting on exactly 3.2.0 reads that line as "you are fine" while the
delayed-RCE path is still open. "or later" saves anyone who simply updates to current, so this is
misleading rather than harmful.

**Not changed in this PR on purpose.** Naming a version the user cannot find is its own harm, and
the version number could not be confirmed against Steam's own patch notes from the research
environment (see below). A reviewer who can open the store page should confirm 4.0.0 exists and is
the security release, then update all three places together.

---

## Verification status — read this before trusting anything above

The research environment's network policy allowed `WebSearch` but blocked outbound fetches to every
source domain involved (`medium.com`, `aikido.dev`, `khaelkugler.com`, `cyberinsider.com`,
`socradar.io`, `steamcommunity.com`, `store.steampowered.com` and the rest; only GitHub hosts and
package registries resolved). **No primary source for T1 or T2 was read directly.** Every technical
detail above comes from search-result summaries of those pages, corroborated across several
independent queries and several named outlets, but not quoted from the page itself.

That is why this file contains no hashes, no addresses and no new entries in `indicators.json`.
Search summaries are good enough to tell a reviewer where to look and specific enough to be checked;
they are not good enough to put a matching rule in front of 15 million players. Treat T1 and T2 as
well-corroborated leads pending a read of:

- <https://www.aikido.dev/blog/meccha-chameleon-rce>
- <https://khaelkugler.com/blogs/meccha_chameleon.html>
- <https://cyberpress.org/meccha-chameleon-flaw/>
