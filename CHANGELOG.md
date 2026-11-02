# Changelog

All notable changes to **JVM Inspector** — Minecraft Screenshare Forensics.
Original script by **Tonynoh** (discord.gg/ssa) · fork & improvements by **ItzMeow80**.

## v3.2

| Change | Details |
|---|---|
| **Multi-path values fixed** | `-Djava.library.path="dirA;dirB"` was tested as a single path → always `PATH DOES NOT EXIST` false CRITICAL. Now every `;` segment is checked: all exist → `[ OK ] [ multi-path: 2/2 exist ]`, some missing → `[ REVIEW ] stale entry` (Warning, not Critical) |
| **Temp DLL whitelist** | `Temp\jna\jna<random>.dll` and `Temp\liblz4-java-<random>.so` are normal self-extractions → moved to `[ DLLS ] TEMP-extracted natives from KNOWN components ( normal )`. Unknown DLLs from TEMP/Downloads (e.g. `Vape421Native.dll`) stay **CRITICAL** |
| **Trusted clients** | Lunar Client, Badlion Client, Feather, LabyMod added as trusted launchers: parent line → `( trusted launcher )`, their native folders (`badlion_js.dll`…) no longer listed as external DLLs |
| **%TEMP% on-disk scan** | Always runs (no admin, no live game needed): scans the `%TEMP%` root for binary injection artifacts — random-named unsigned PEs (`.tmp` with an `MZ` header) → `[ CRITICAL ] injection droppings`. Cross-checks the live Java module index: each artifact is marked **`[ INJECTED: javaw.exe PID x ]`** (active injection) or the block states `ON DISK ONLY` / `UNKNOWN (run as Administrator)`. Known self-extractions (jna / lz4 / grpc) are grouped as OK |
| **Trusted vendor folders** | DLLs loaded from `ProgramData\Microsoft` (e.g. Windows Defender's `MpOav.dll`) are Microsoft-signed system components → no longer listed in the external-DLLs group (`$script:TrustedVendorRoots`, extensible) |
| **Automatic class analysis** | Every `-javaagent` jar now gets a "decompiler pass" without JD-GUI: `Get-AgentClassScan` parses the constant pool of each class (big-endian bytecode) and reports referenced `net.minecraft`/`com.mojang` classes + `Instrumentation.retransform/redefine` APIs, combined with the full string scan (cheat clients/markers/modules). Unknown agents print evidence lines — `[ CRITICAL ] cheat client: Bloom Client + markers: 2` + `[ REWRITE ] net.minecraft refs: 245` — known agents only a neutral `[ BYTECODE ]` info line (no false alarms on Theseus/Spark) |
| **Every string checked, hits printed in red** | `Find-JarStringHits -Full` (used for agents): every string of **every entry** (classes + resources, no early exit) is checked for cheat traces and **each hit is printed in red** under the finding: `'cracked by' in net/caffeinemc/.../LoaderDelegate.class`. The mods inventory prints marker strings the same way |
| **Real decompiler pass** | Unknown agents are automatically decompiled with CFR → plain `.java` sources (JD-GUI compatible, https://java-decompiler.github.io/) in `%TEMP%\jvi-decompile-*`; every source line is scanned and traces print in red as `file.java:line 'string'`. Requires any JRE (auto-discovered, CFR cached once in `%TEMP%\jvi-cfr.jar`, needs internet on first use); disable with `-NoDecompile`. New standalone mode: `JVM-Inspector.ps1 -Decompile <jar>` with source-context evidence |
| **Readable output pass** | Global decluttering: args print as `[ TAG ] arg` + one summary line (dropped duplicate `//` and `-> path` lines, javaagent shows only what matters), DLL groups state `modules LOADED in javaw.exe ( PID x )`, TEMP block shortens its status lines, flagged jars compress to 4 lines: jar, `[ CRITICAL ] cheat client/strings`, `[ REVIEW ] keyword/disguised`, `[ MISMATCH/INFO ] id=… name=… v… ( nested: … )` |

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
