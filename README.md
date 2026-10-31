# JVM Inspector — Minecraft Screenshare Forensics

PowerShell tool for Minecraft screenshare (SS) checks: scans every running
`javaw.exe` / `java.exe` process for suspicious JVM launch flags, injected
agents, redirected game jars, external DLLs and hidden mods.

> Original script by **Tonynoh** — discord.gg/ssa
> This fork adds deep analysis, validation and reporting — by **ItzMeow80**

## What's new in v2

| Check | Details |
|---|---|
| **Deep `-javaagent` analysis** | Reads `MANIFEST.MF` (Premain-Class) and class packages directly from the jar and matches them against known legitimate launcher agents (e.g. **Modrinth App "Theseus"**) → no more false alarms |
| **Path validation** | Every value of `addMods`, `gameJarPath`, `java.library.path`, `jna.boot.library.path`… is checked: does it exist? Is it inside a known launcher folder? TEMP? Downloads? |
| **Parent process check** | Who spawned `javaw.exe`? A launcher = OK, an unknown exe from TEMP/Downloads = injection suspect |
| **Loaded-DLL check** | Lists DLLs of the JVM process; flags anything loaded from TEMP/Downloads (classic injection) |
| **Environment persistence** | Detects `JAVA_TOOL_OPTIONS` / `_JAVA_OPTIONS` / `JDK_JAVA_OPTIONS` containing agents (affects every JVM on the machine) |
| **Launch profile detection** | Shows Vanilla / Fabric / Quilt / Forge-NeoForge from the command line |
| **Mods inventory** | Scans all known launcher instances (Modrinth, CurseForge, Prism, MultiMC, ATLauncher, .minecraft…) with per-jar SHA256 |
| **Disguise detection** | Flags jars named like system files (`SYSTEM32.jar`, `svchost.jar`…) |
| **Cheat keyword scan** | Names of known clients/features in args, classpath and mod filenames (a hit = *verify*, never proof) |
| **Risk verdict** | `CLEAN` / `REVIEW` / `SUSPICIOUS` with critical/warning/info counters |
| **Report export** | `-OutFile report.txt` saves the full output as screenshare evidence |

## Usage

```powershell
# basic scan
.\JVM-Inspector.ps1

# full scan with SHA256 hashes + save evidence report
.\JVM-Inspector.ps1 -Hash -OutFile .\ss-report.txt

# check a mods folder that is not in a known launcher path
.\JVM-Inspector.ps1 -ModsPath "C:\path\to\mods"

# skip heavy sections
.\JVM-Inspector.ps1 -SkipMods -SkipModules
```

Run **as Administrator** for the parent-process and loaded-DLL checks.

## Reading the output

- **Red (Critical)** — needs explanation: unknown java agent, self-attach enabled, missing/Downloads path, injected DLL…
- **Yellow (Warning)** — verify by hand: custom mod paths, tweaked game jar, keyword hits, disguised jar names
- **Cyan (Info)** — normal but documented: launcher-owned native paths, launch target
- **Green (OK)** — validated as legitimate (known launcher agent/folder)

A keyword or a red flag is **never proof by itself** — it only tells the
reviewer where to look. Always open the jar / check the folder to conclude.

## Notes

- Only processes running **at scan time** are inspected.
- Cheat loaders that inject after launch (external DLL) are caught by the
  DLL check, not by the command-line flags — a full SS should combine this
  with the mods inventory.
- Original script: [`MeowTonynoh/Tonynoh-PS1`](https://github.com/MeowTonynoh/Tonynoh-PS1)
