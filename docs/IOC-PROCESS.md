# How indicators get into this tool

This is the process that keeps the checker useful after the campaign moves on. It exists because
the alternative — updating indicators by hand whenever someone notices a news article — stops
happening within about two weeks of a project starting.

## The rule everything else follows

**No indicator reaches `main` without a human approving it and a source backing it.**

This tool tells ordinary players whether their computer is infected. Both failure directions are
harmful, and they are not symmetrical:

- A **false positive** tells someone who did nothing wrong that they are compromised. They will
  panic, wipe a drive, or change every password they own. This is the worse outcome.
- A **false negative** leaves someone infected while believing they are fine.

An automated pipeline that merges its own findings optimises for speed and gets the first one
wrong eventually. So the loop below is automated right up to the point of judgement, and stops.

## The loop

```
  ┌──────────────────────────────────────────────────────────────┐
  │  1. RESEARCH   scheduled agent, weekly                        │
  │     searches for new maps, hashes, C2s, technique writeups    │
  └───────────────────────────┬──────────────────────────────────┘
                              ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  2. VALIDATE   tools/validate-indicators.sh                   │
  │     format, duplicates, over-generic strings, provenance      │
  └───────────────────────────┬──────────────────────────────────┘
                              ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  3. PROPOSE    a pull request, one indicator per line,        │
  │                each citing where it came from                 │
  └───────────────────────────┬──────────────────────────────────┘
                              ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  4. REVIEW     a human reads the sources and merges           │  ← stops here without you
  └──────────────────────────────────────────────────────────────┘
```

Community reports enter at step 2 through the
[indicator issue template](../.github/ISSUE_TEMPLATE/new-indicator.yml).

## What the research step looks for

Not just atomic indicators. The published IOCs for this campaign sit at the bottom of the Pyramid
of Pain — a hash, an IP, a map ID — and the attackers demonstrably re-uploaded replacement maps
within hours of each takedown. Anything that only tracks atomic IOCs is permanently one step
behind.

So the agent hunts, in descending order of durability:

| Priority | What | Why it matters |
|---|---|---|
| 1 | **Techniques** — how droppers are hidden in Workshop content, new Unreal capability abuse, new persistence | Survives repackaging. Feeds the `--deep` behaviour checks. |
| 2 | **Toolmarks** — debug class names, sentinel variables, build artefacts the author forgot to strip | Survives a recompile. `BP_RCE_Test_C_0` is one of these. |
| 3 | **Infrastructure** — new C2 addresses, hosting patterns | Changes often, but cheap to add. |
| 4 | **Atomic** — new map IDs, file hashes | Exact and safe, but obsolete fastest. |

A finding at priority 1 or 2 is worth more than ten at priority 4.

## Sources the agent checks

- The original analysis: [Feint's writeup](https://medium.com/@FeintBE/workshop-map-for-meccha-chameleon-is-a-malware-dropper-full-breakdown-d1ac29565265)
- Security press and gaming press covering the campaign
- Malware sandbox and threat-intel write-ups mentioning the game or the C2 infrastructure
- The game's own Steam Workshop, community hub and Discord for newly reported maps
- Vendor detection names, once AV products start naming this family

## Rules the agent must follow

1. **Never invent an indicator.** If a source describes malware but publishes no hash, ID or
   address, the finding is "no new indicators", not a plausible-looking guess. A fabricated hash
   is worse than no hash: it looks authoritative and it never matches anything.
2. **Cite every entry.** Each new indicator carries a `source` URL and an `added` date.
3. **One source is a lead; two make it an indicator.** A single unverified forum post goes in the
   PR description as a lead for a human to check, not into `indicators.json`.
4. **Never widen a content string.** Short or common strings (`.bat`, `powershell`, `http://`)
   match innocent files. The validator rejects these, and it should not be "fixed" to allow them.
5. **Report an empty week as an empty week.** Most weeks there will be nothing. That is a valid,
   expected result and must not be padded.

## Running it by hand

```bash
bash tools/validate-indicators.sh          # gate any edit
bash tests/make-fixtures.sh                # prove the scanners still work
DUMP_INDICATORS=1 bash scan-linux.sh       # show exactly what got parsed
```

`DUMP_INDICATORS=1` exists because indicator parsing bugs are invisible in normal output — the
scan still runs and still reports, it just quietly matches the wrong things. That happened once
already: a `sed` line range made `content_strings` swallow the next key's values.

## When the campaign is over

When maps stop appearing and the indicators stop changing, drop the schedule to monthly, then
archive it. Leave the issue template open — that costs nothing and still catches a resurgence.
