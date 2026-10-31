# JVM Inspector v3 — Minecraft Screenshare Forensics

PowerShell tool for Minecraft screenshare (SS) checks: scans every running
`javaw.exe` / `java.exe` process for suspicious JVM launch flags, injected
agents, redirected game jars, external DLLs and hidden mods.

> Original script by **Tonynoh** — discord.gg/ssa
> This fork adds deep analysis, validation and reporting — by **ItzMeow80**

Full version history: [CHANGELOG.md](CHANGELOG.md)

## What's new in v3

| Check | Details |
|---|---|
| **Generic cheat flags** | The class strings of **every** mod jar are matched against ~90 cheat module/feature names (Kill Aura, Auto Crystal, Auto Totem, Chest Stealer, Player ESP, X-Ray, Ping Spoof, USN Journal Cleaner…) **regardless of the client** — works on unknown/private clients too. Case-insensitive, tolerates `Kill Aura` / `killaura` / `kill-aura`. Hits print the class + surrounding string as evidence → **`[ WARNING ]`** (*verify, never proof*) |
| **String dump** | `-DumpStrings <jar>` exports every readable string of a jar (`entry<TAB>string` per line) to `%TEMP%\<name>.strings.txt` for manual analysis |
| **MEOW-style output** | Numbered section banners `[ 01 ] … [ 05 ]`, `[ TAG ]` severity labels (`[ CRITICAL ]`, `[ REVIEW ]`, `[ MISMATCH ]`, `[ OK ]`), box separators and a final `[ VERDICT ]` box — HTML report restyled with the MEOW accent `#00FFB3` |

## What's new in v2

| Check | Details |
|---|---|
| **Deep `-javaagent` analysis** | Reads `MANIFEST.MF` (Premain-Class) and class packages directly from the jar and matches them against known legitimate launcher agents (e.g. **Modrinth App "Theseus"**) → no more false alarms |
| **Path validation** | Every value of `addMods`, `gameJarPath`, `java.library.path`, `jna.boot.library.path`… is checked: does it exist? Is it inside a known launcher folder? TEMP? Downloads? |
| **Parent process check** | Who spawned `javaw.exe`? A launcher = OK, an unknown exe from TEMP/Downloads = injection suspect |
| **Loaded-DLL check** | Lists DLLs of the JVM process; flags anything loaded from TEMP/Downloads (classic injection) and marks every external DLL as **signed / unsigned**. Known false positives are filtered: natives extracted to TEMP by **Simple Voice Chat** (`libopus4j`, `librnnoise4j`, `libspeex4j`, `liblame4j`) and **JNA** (`jnidispatch`) are reported as normal |
| **Startup persistence** | Flags Run-key / Startup-folder entries that auto-launch `java`/`javaw`/agents or point into TEMP |
| **Attach tool detection** | Warns when `jcmd`/`jdb`/`jattach`/`jconsole` are running — they can inject agents into a live JVM |
| **Environment persistence** | Detects `JAVA_TOOL_OPTIONS` / `_JAVA_OPTIONS` / `JDK_JAVA_OPTIONS` containing agents (affects every JVM on the machine) |
| **Launch profile detection** | Shows Vanilla / Fabric / Quilt / Forge-NeoForge from the command line |
| **Mods inventory** | Scans all known launcher instances (Modrinth, CurseForge, Prism, MultiMC, ATLauncher, .minecraft…) with per-jar SHA256 |
| **Disguise detection** | Flags jars named like system files (`SYSTEM32.jar`, `svchost.jar`…) |
| **Known cheat-client ID** | Recognizes cheat clients even when repackaged under fake names — matched on branding assets/class strings (e.g. `SYSTEM32.jar` hiding **Bloom Client** via `bloom_logo.png` inside a fake *lithium* layout) → **`[ CRITICAL ] CHEAT CLIENT detected`** |
| **Crack/cheat marker scan** | Scans the class strings of **every** mod jar for cheat scaffolding (`cracked by`, `648k`, `license key`, `hwid`, `keyauth`) with word boundaries → **CRITICAL** (count only, no raw strings printed) |
| **Mod identity check** | For flagged jars reads `fabric.mod.json`: shows what the jar *claims* to be (id/name/version/entrypoints), flags **file-name ↔ mod-id mismatch** and hidden nested containers (`MC Bootstrap`, `OptLib Core`…) |
| **Cheat keyword scan** | Names of known clients/features in args, classpath and mod filenames (a hit = *verify*, never proof) |
| **Risk verdict** | `CLEAN` / `REVIEW` / `SUSPICIOUS` with critical/warning/info counters |
| **Report export** | `-OutFile report.txt` (plain) or `-OutFile report.html` (styled standalone HTML, colors preserved) |

## Usage

```powershell
# basic scan
.\JVM-Inspector.ps1

# full scan with SHA256 hashes + styled HTML evidence report
.\JVM-Inspector.ps1 -Hash -OutFile .\ss-report.html

# check a mods folder that is not in a known launcher path
.\JVM-Inspector.ps1 -ModsPath "C:\path\to\mods"

# dump all readable strings of a suspect jar for manual analysis
.\JVM-Inspector.ps1 -DumpStrings "C:\path\to\suspect.jar"

# skip heavy sections
.\JVM-Inspector.ps1 -SkipMods -SkipModules
```

Run **as Administrator** for the parent-process and loaded-DLL checks.

## Reading the output

Sections are numbered `[ 01 ] … [ 05 ]` and every finding carries a tag:

- **`[ CRITICAL ]` (Red)** — needs explanation: unknown java agent, self-attach enabled, missing/Downloads path, injected DLL, crack marker…
- **`[ WARNING ]` / `[ REVIEW ]` / `[ MISMATCH ]` / `[ ! ]` (Yellow)** — verify by hand: custom mod paths, tweaked game jar, keyword hits, disguised jar names, generic cheat flags
- **`[ INFO ]` (Cyan)** — normal but documented: launcher-owned native paths, launch target
- **`[ OK ]` (Green)** — validated as legitimate (known launcher agent/folder, clean env, clean persistence)
- **`[ VERDICT ]` box** — final call: `CLEAN` / `REVIEW` / `SUSPICIOUS` with the counters

A keyword or a red flag is **never proof by itself** — it only tells the
reviewer where to look. Always open the jar / check the folder to conclude.

## Notes

- Only processes running **at scan time** are inspected.
- Cheat loaders that inject after launch (external DLL) are caught by the
  DLL check, not by the command-line flags — a full SS should combine this
  with the mods inventory.
- Original script: [`MeowTonynoh/Tonynoh-PS1`](https://github.com/MeowTonynoh/Tonynoh-PS1)
