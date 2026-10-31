# Changelog

All notable changes to **JVM Inspector** — Minecraft Screenshare Forensics.
Original script by **Tonynoh** (discord.gg/ssa) · fork & improvements by **ItzMeow80**.

## v3.1

| Change | Details |
|---|---|
| **Known cheat-client ID** | Recognizes cheat clients even when repackaged under fake names — `SYSTEM32.jar` hiding **Bloom Client** (`bloom_logo.png` inside a fake *lithium* layout) → `[ CRITICAL ] CHEAT CLIENT detected: Bloom Client`. Token list is extensible (`$script:ClientTokens`): entry paths + class strings |
| **Cleaner findings** | Raw marker strings (`cracked by`, `648k`…) no longer printed — the tool reports the count and the verdict instead, cheat-module hits print `name -> class` only |
| **Red jar lines** | The string scan now runs **before** the jar line is printed: any jar with a cheat client or cheat strings has its name printed in **RED** with `[ ! ]` (yellow kept for keyword/disguised-only jars) |
| **Trusted parents** | Parent line now labels `Modrinth App.exe` / real launchers as `( trusted launcher )` and shells as `( trusted console )` |
| **Header** | `Tool / Elevation : [ ADMIN ]` block, `Vectors` line removed |

## v3

| Change | Details |
|---|---|
| **Generic cheat flags** | ~90 cheat module/feature names matched against the class strings of **every** mod jar, regardless of client (works on private/unknown clients) → `[ WARNING ]` with `class` evidence |
| **`-DumpStrings <jar>`** | Full printable-string export (`entry<TAB>string` per line) to `%TEMP%\<name>.strings.txt` for manual analysis |
| **MEOW-style output** | Numbered section banners `[ 01 ] … [ 05 ]`, `[ TAG ]` severity labels, box separators, final `[ VERDICT ]` box — HTML report restyled with the MEOW accent `#00FFB3` |

## v2

| Change | Details |
|---|---|
| **Deep `-javaagent` analysis** | Reads `MANIFEST.MF` (Premain-Class) + class packages from the jar, matches them against known legitimate launcher agents (Modrinth *Theseus*) → no false alarms on normal launchers |
| **Path validation** | Every suspicious value (`addMods`, `gameJarPath`, `java.library.path`, `jna.boot.library.path`…) checked: exists? launcher folder? TEMP/Downloads? keyword? |
| **Parent process check** | Who spawned `javaw.exe`? Unknown parent from TEMP/Downloads = injection suspect |
| **Loaded-DLL check** | Flags DLLs loaded from TEMP/Downloads (classic injection), unsigned external modules |
| **Persistence checks** | `JAVA_TOOL_OPTIONS` / `_JAVA_OPTIONS` / `JDK_JAVA_OPTIONS` + Java-related auto-start entries |
| **Launch profile + mods inventory** | Vanilla / Fabric / Quilt / Forge-NeoForge detection, inventory of every known launcher instance (+ optional SHA256), crack marker scan with word boundaries, mod identity check (`fabric.mod.json` mismatch, hidden nested containers) |
| **Risk scoring + reports** | Final verdict `CLEAN / REVIEW / SUSPICIOUS`, `-OutFile report.txt` / `report.html` |
