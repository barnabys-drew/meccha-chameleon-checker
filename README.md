# Meccha Chameleon Workshop Malware Checker

A small, free tool that checks whether your PC shows any of the **known** signs of the malware that
was distributed through Meccha Chameleon Steam Workshop maps in July 2026.

> **Status: in development.** The scanners are not written yet. Right now this repo contains the
> indicator list (`indicators.json`) and this README. Do not rely on it for a real check yet.

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

## What this tool is, and is not

**It is** a checker for the specific indicators researchers have published about this one campaign:
the known bad map IDs, the known file hashes, the attacker's server address, and the malicious
Blueprint asset.

**It is not** an antivirus, and **it is not** a cleaner. It only looks and reports. It never deletes,
moves, or changes anything on your computer.

### How to read a "nothing found" result

This matters, so it is worth being blunt about it.

If the tool finds nothing, that means **none of the known indicators are on your system**. It does
**not** mean you are definitely clean. The second-stage program this malware downloaded was never
captured by researchers, so nobody publicly knows exactly what it installs or what traces it leaves.

If you saw a command window flash while loading a custom map, treat a clean result with suspicion,
run a full Microsoft Defender or Malwarebytes scan, and change your important passwords from a
different device.

## Usage

Coming once the scanners land. Planned:

- **Windows** — double-click `check-my-pc.bat`. No install required.
- **Linux** — run `./check-my-pc.sh`. Also checks inside the Proton prefix, where the dropped file
  actually lands when you play through Steam Play; ordinary Linux antivirus will not look there.

## Indicators

All indicators live in [`indicators.json`](indicators.json) so they can be audited and updated
independently of the scanning code. Source: Feint's writeup, linked below.

## Credits and disclaimer

- Malware analysis and all indicators: [Feint — *Workshop map for MECCHA CHAMELEON is a malware dropper (full breakdown)*](https://medium.com/@FeintBE/workshop-map-for-meccha-chameleon-is-a-malware-dropper-full-breakdown-d1ac29565265)
- Background reporting: [Kotaku](https://kotaku.com/multiple-meccha-chameleon-steam-workshop-maps-got-infected-with-malware-and-its-discord-server-was-hacked-2000719315), [Windows Central](https://www.windowscentral.com/gaming/pc-gaming/meccha-chameleon-steam-workshop-malware)

This project is **unofficial** and is not affiliated with, endorsed by, or connected to Lemorion or
Valve. It is provided as-is, without warranty of any kind. See [LICENSE](LICENSE).
