<div align="center">

# 🦎 Meccha Chameleon Malware Checker

### Downloaded a custom map? Find out in 3 seconds if it infected your PC.

**Free · No install · Nothing to sign up for · Takes about 3 seconds**

![Windows](https://img.shields.io/badge/Windows-works-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-works-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Read only](https://img.shields.io/badge/Read--only-changes%20nothing-2EA043?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

</div>

---

## 😰 Wait — am I affected?

Answer these:

| | Question |
|:--:|:--|
| ✅ | Do you play **Meccha Chameleon**? |
| ✅ | Did you ever download a **custom map** from the Steam Workshop? |
| ✅ | Was that **before the 3.2.0 update** (July 2026)? |

**Three yeses? Run the checker below.** Even one "not sure" is a good reason to run it.

> [!NOTE]
> **The game itself was never infected.** If you only ever played the normal game and never
> downloaded a community-made map, you were not exposed to this.

---

## ⬇️ Step 1 — Download it

### [**📦 Click here to download**](../../archive/refs/heads/main.zip)

Then **right-click the downloaded ZIP → Extract All**. Keep all the files together in one folder.

---

## ▶️ Step 2 — Run it

<table>
<tr>
<td width="50%" valign="top">

### 🪟 Windows

**Double-click `check-my-pc.bat`**

That's it. A black window opens, does its thing, and tells you the result.

</td>
<td width="50%" valign="top">

### 🐧 Linux

Open a terminal in the folder and paste:

```bash
chmod +x check-my-pc.sh
./check-my-pc.sh
```

</td>
</tr>
</table>

> [!TIP]
> Windows may say **"Windows protected your PC"** — that is just because the file came from the
> internet. Click **More info → Run anyway**. You can read every line of what it does first:
> [`check-my-pc.bat`](check-my-pc.bat) is 20 lines long.

---

## 📖 Step 3 — Read your result

You will get one of these two answers.

<table>
<tr>
<td width="50%" valign="top">

### 🟢 "No known indicators found"

Nothing from this malware was found on your PC.

**Read the yellow box below before you relax.**

</td>
<td width="50%" valign="top">

### 🔴 "Something was found"

The tool prints numbered steps to follow.

**Do not delete anything yet.** Scroll down to 🆘.

</td>
</tr>
</table>

> [!IMPORTANT]
> ### 🟢 does not mean "you are 100% safe"
>
> It means **none of the signs researchers currently know about** are on your PC.
>
> The second half of this malware — the part it downloaded from the attacker — was **never
> captured by researchers**. Nobody publicly knows what it installs or what traces it leaves.
> This tool cannot search for something nobody has ever seen.
>
> **If you saw a black window flash open while a custom map was loading,** treat a green result
> with suspicion: run a full antivirus scan and change your passwords from a different device
> anyway.

---

## 🆘 It found something. What now?

Do these **in this order**:

1. **🔌 Disconnect from the internet.**
2. **🛑 Do not delete the files it listed.** They are evidence — and deleting them does **not**
   remove the second half of the malware.
3. **🛡️ Run a full offline scan** with Microsoft Defender or Malwarebytes.
4. **🔑 Change your passwords from a *different* device** — phone or another computer. Email first,
   then Steam, Discord, and anything sharing those passwords.
5. **📱 Sign out everywhere** on Steam and Discord, then turn two-factor authentication **off and
   back on**.
   > The attackers in this campaign got past a victim's Discord 2FA. Re-enrolling kicks them out.
6. **🗑️ Unsubscribe from the map** in the Steam Workshop, and update the game to **3.2.0 or later**.

---

## 🤔 What actually happened?

<details>
<summary><b>Click for the story</b></summary>

<br>

In July 2026, several community-made maps for **Meccha Chameleon** on the Steam Workshop turned
out to be malware droppers. Loading an infected map would:

1. Silently write a file called `s.bat` into your **Documents** folder.
2. Briefly flash a black command-prompt window — the thing players noticed.
3. Quietly run PowerShell in a hidden window to download a second program from an attacker's server.

Independent researcher **Feint** published the technical breakdown on 24 July 2026. The developer
patched the underlying issue in version **3.2.0**, and Valve removed the maps that were reported —
but replacement malicious maps appeared within hours of each takedown.

</details>

## 🔍 What does the checker actually look at?

<details>
<summary><b>Click for the technical detail</b></summary>

<br>

| # | Check |
|---|---|
| 1 | Finds your Steam libraries **on every drive**, not just the default folder |
| 2 | Looks for known malicious Workshop map IDs |
| 3 | Compares map files (`.pak`, `.utoc`, `.ucas`) against known malicious fingerprints |
| 4 | Scans inside map files for malware markers, in both plain text and UTF-16 |
| 5 | Looks for the dropped `s.bat`, and renamed copies of it |
| 6 | Looks for startup entries, scheduled tasks and cron jobs referring to the malware |

Drive detection does not rely on Steam's own `libraryfolders.vdf` alone. A drive that was
disconnected, re-lettered or removed from Steam's library list can still hold an infected map, so
the tool enumerates the drives themselves. On Linux it also looks inside the **Proton prefix**,
where the dropped file actually lands under Steam Play — ordinary Linux antivirus will not look
there.

**Limitations, stated plainly:**

- It detects the **dropper**, not the second stage. The second stage was never publicly analysed.
- The library search is depth-limited and skips system folders, so a library buried somewhere very
  unusual could be missed. Every library it *did* find is listed in the output.
- Scanning inside map files can miss a marker if the map data is compressed. Checks 2 and 3 are the
  reliable ones; check 4 is a bonus.
- **It is not an antivirus** and is no substitute for one.

All indicators live in [`indicators.json`](indicators.json), so they can be audited and updated
without touching the scanning code. If that file is missing or corrupt, the scanners **exit with an
error rather than report a misleading "clean" result**.

</details>

## 🧪 For developers

<details>
<summary><b>Tests, exit codes, contributing</b></summary>

<br>

The suites build a throwaway fixture tree — one infected, one clean — and assert that every check
fires, that an innocent map is *not* flagged, and that the caveat text survives:

```bash
bash tests/make-fixtures.sh                                                   # Linux
powershell -NoProfile -ExecutionPolicy Bypass -File tests\make-fixtures.ps1    # Windows
```

Both report **13 passed, 0 failed**.

Fixtures are generated at runtime and never committed: a repo containing a `.bat` with the real
payload string would be flagged by antivirus and by GitHub. Generated fixtures are inert — `echo`
statements only — and marker strings are assembled from fragments at runtime.

| Exit code | Meaning |
|:--:|---|
| `0` | No known indicators found |
| `1` | Indicators found |
| `2` | The scan could not run |

**Know of another malicious map ID?** Please open an issue — `indicators.json` currently carries
only one confirmed ID, and replacement maps kept appearing after each takedown.

</details>

---

<div align="center">

### 🙏 Credits

Malware analysis and all indicators by **Feint** —
[read the full breakdown](https://medium.com/@FeintBE/workshop-map-for-meccha-chameleon-is-a-malware-dropper-full-breakdown-d1ac29565265)

Reporting: [Kotaku](https://kotaku.com/multiple-meccha-chameleon-steam-workshop-maps-got-infected-with-malware-and-its-discord-server-was-hacked-2000719315) ·
[Windows Central](https://www.windowscentral.com/gaming/pc-gaming/meccha-chameleon-steam-workshop-malware)

<br>

**Unofficial.** Not affiliated with, endorsed by, or connected to Lemorion or Valve.
Provided as-is, without warranty. [MIT licensed](LICENSE).

</div>
