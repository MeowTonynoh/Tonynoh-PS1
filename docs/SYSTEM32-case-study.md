# Case Study: `SYSTEM32.jar` — a cracked premium client hiding as a mod

*Detected by JVM Inspector v2 (disguise detection + crack-marker scan) — 2026-10-31*

## Summary

A routine JVM Inspector scan of a Modrinth App profile flagged a single jar.
Manual forensics confirmed it is a **cracked, paid Minecraft cheat client**
camouflaged behind **four layers of fake identity**. Verdict from the tool:
`SUSPICIOUS`.

## File

| Field | Value |
|---|---|
| Path | `%APPDATA%\ModrinthApp\profiles\Fabric 26.3\mods\SYSTEM32.jar` |
| Size | 2054 KB — 675 zip entries |
| SHA256 | `B56FDB0FDB73F4D481FE9FF80524CF2FE50BEC7322385EAA5472179BEDCEEEF9` |

## Four layers of disguise

| Layer | Claim | Reality |
|---|---|---|
| 1. File name | `SYSTEM32.jar` | mimics a Windows system file |
| 2. `fabric.mod.json` | `id=clumps`, name "Clumps" v29.0.0.1 | fake — the 16 real Clumps classes inside are decoys |
| 3. Class packages | `net.caffeinemc.mods.lithium.*` | fake — real Lithium 0.21.3 contains only `lithium.mixin` (445), `lithium.common` (212), `lithium.fabric` (18), `lithium.api` (4). The packages `lithium.lattice` (461 classes) and `lithium.binder` (40) **do not exist upstream** |
| 4. Hidden containers | `mc-bootstrap` ("MC Bootstrap", *All Rights Reserved*) + `optlib-core-0836` ("OptLib Core") | nested-mod descriptors (Jar-in-Jar). `fabric_loader.json` declares `META-INF/jars/mc-core.jar`, which is absent |

## Evidence

**Crack signature strings** in class constant-pools (found automatically by
the marker scan):

```
'cracked by'  <- net/caffeinemc/mods/lithium/lattice/bundle/pipeline/element/LoaderDelegate.class
'648k'        <- net/caffeinemc/mods/lithium/lattice/bundle/pipeline/channel/ConfigBridge.class
```

`ConfigBridge.class` also contains the literal `648k.exe` next to
`java/security/MessageDigest` references (HWID / auth-bypass logic).

**Client-side behaviour indicators:**

- Entrypoint is **client-only**: `net.caffeinemc.mods.lithium.lattice.bundle.pipeline.RenderController`
  (a real optimization mod registers a `main` entrypoint)
- 58 custom GUI fonts under `assets/lithium/font/` (legit Lithium ships only an icon)
- HUD/overlay mixins via `clumps.compat.json` into
  `net.caffeinemc.mods.lithium.lattice.bundle.overlay` — classes such as
  `RenderEnhancer`, `SwingAnimator`, `RenderShader`, `EntityLabelCache`,
  `PlayerListCache`, `CameraStateCache`
- Auth/token-adjacent class names: `TokenExtractor`, `SlotInspector`, `QueryZone`

## Attribution

`Cracked by 648k.exe` matches a known cracker active on Trillium Solutions who
publishes cracked paid Minecraft clients (Temple, Clarity, Berlin, Noir,
Prestige, …). Public comments on those releases report
`getAccessToken` / `credential.minecraft_session` handling — i.e. **session
token theft is a realistic risk** with this family. Treat as malware until
proven otherwise.

## Verdict

**Cracked premium cheat client — not a legitimate mod.** Remove it from the
instance. If it was ever executed, consider rotating the Microsoft/Minecraft
session and checking for persistence (JVM Inspector's startup & environment
checks cover the common vectors).

## How JVM Inspector catches this automatically

1. **Disguise detection** — file name matches a system/process name → `[!]`
2. **Crack-marker scan** (runs on *every* mod jar's class strings) →
   `[CRITICAL] crack/cheat marker(s): 'cracked by', '648k'`
3. **Identity check** (flagged jars) — reads `fabric.mod.json`:
   - claims `id=clumps` while file is `SYSTEM32.jar` → `FILE NAME DOES NOT MATCH MOD ID`
   - exposes hidden nested containers (`MC Bootstrap`, `OptLib Core`)
4. **Verdict** → `SUSPICIOUS` with `Critical: 1`

Manual step that closed the case: diffing the jar's class tree against a known
good Lithium jar (ground truth on the same machine) proved the
`lattice`/`binder` tree was foreign.
