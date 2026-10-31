<#
.SYNOPSIS
    JVM Inspector v3 - Minecraft Screenshare Forensics
.DESCRIPTION
    Improved fork of the original JVM Inspector by Tonynoh (discord.gg/ssa).

    What's new in v3:
      * Generic cheat-flag scan: ~90 cheat module/feature names matched against
        the class strings of EVERY mod jar, regardless of the client
        (works on unknown/private clients) -> class + context evidence
      * -DumpStrings <jar>: full printable-string export for manual analysis
      * MEOW-style output: numbered sections, [ TAG ] severity labels,
        separators and verdict box
    What's new in v2:
      * Deep -javaagent analysis: reads MANIFEST.MF (Premain-Class) and class
        packages straight from the jar and matches them against known
        legitimate launcher agents (e.g. Modrinth App "Theseus") -> no more
        false alarms on normal launchers
      * Automatic path validation for every suspicious value (addMods,
        gameJarPath, java.library.path, jna.boot.library.path, ...):
        exists? inside a known launcher folder? inside TEMP/Downloads?
        cheat keyword match?
      * Parent process check (who spawned javaw.exe?)
      * Loaded-DLL check (external / injected modules of the JVM process)
      * JAVA_TOOL_OPTIONS / _JAVA_OPTIONS / JDK_JAVA_OPTIONS persistence check
        (classic "flag every JVM on the machine" injection vector)
      * Launch profile detection (Vanilla / Fabric / Quilt / Forge-NeoForge)
      * Mods inventory of every known launcher instance (+ optional SHA256)
      * Risk scoring with a final verdict: CLEAN / REVIEW / SUSPICIOUS
      * Optional text report export (-OutFile) for screenshare evidence
.PARAMETER OutFile
    Save the full console output as evidence. ".txt" = plain text,
    ".html" = styled standalone HTML report (colors preserved).
.PARAMETER ModsPath
    Extra folder to scan for mods (instances not stored in a known launcher path).
.PARAMETER SkipMods
    Skip the mods folder inventory.
.PARAMETER SkipModules
    Skip the loaded-DLL check.
.PARAMETER Hash
    Add short SHA256 hashes to the mods inventory (proves which jar was there).
.EXAMPLE
    .\JVM-Inspector.ps1 -OutFile .\ss-report.txt -Hash
.EXAMPLE
    .\JVM-Inspector.ps1 -DumpStrings "C:\path\to\suspect.jar"
    Dump every readable string of a jar to %TEMP%\<name>.strings.txt for manual analysis.
.NOTES
    Original by Tonynoh - discord.gg/ssa
    Fork + improvements by ItzMeow80
    Windows PowerShell 5.1+ / PowerShell 7+ - run as Administrator for best results
#>
[CmdletBinding()]
param(
    [string]$OutFile,
    [string]$ModsPath,
    [switch]$SkipMods,
    [switch]$SkipModules,
    [switch]$Hash,
    [string]$DumpStrings
)

# ----------------------------------------------------------------------
# State
# ----------------------------------------------------------------------
$script:Report        = [System.Collections.Generic.List[object]]::new()
$script:Critical      = 0
$script:WarningCount  = 0
$script:InfoCount     = 0
$script:TotalRelevant = 0

try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }

# Known legitimate java agents (match against Premain-Class + class packages)
$script:KnownAgents = @(
    @{ Token = 'com.modrinth.theseus'; Name = 'Modrinth App - Theseus launcher agent' }
    @{ Token = 'me.lucko.spark';       Name = 'Spark profiler agent' }
)

# Roots owned by known Minecraft launchers (paths inside these are "normal")
$script:KnownRoots = @(
    "$env:APPDATA\ModrinthApp"
    "$env:APPDATA\.minecraft"
    "$env:APPDATA\PrismLauncher"
    "$env:APPDATA\MultiMC"
    "$env:APPDATA\ATLauncher"
    "$env:APPDATA\gdlauncher"
    "$env:APPDATA\CurseForge"
    "$env:USERPROFILE\curseforge"
    "$env:APPDATA\.techniclauncher"
    "$env:LOCALAPPDATA\Packages\Microsoft.4297127D64EC6_8wekyb3d8bbwe"
)

$script:TempRoots     = @($env:TEMP, $env:TMP) | Where-Object { $_ }
$script:DownloadRoots = @("$env:USERPROFILE\Downloads")

# Keyword scan: names of known cheat clients / cheat features.
# A hit is NEVER proof - it only means "open this jar and verify".
$script:BadKeywords = @(
    'wurst', 'impact', 'vape', 'konas', 'gamesense', 'earthhack',
    'liquidbounce', 'fdpclient', 'novoline', 'aristois', 'wolfram',
    'meteor', 'baritone', 'rise client', 'future client', 'sigma client',
    'killaura', 'aimbot', 'triggerbot', 'autoclicker', 'xray', 'scaffold'
)

# Mod jars named exactly like system/process files (disguise trick):
# e.g. "SYSTEM32.jar" inside the mods folder is NOT normal.
$script:DisguisedNames = @(
    'system32', 'system', 'svchost', 'csrss', 'lsass', 'ntoskrnl',
    'kernel32', 'user32', 'explorer', 'wininit', 'winlogon', 'services',
    'smss', 'conhost', 'dwm', 'taskmgr', 'registry', 'java', 'javaw',
    'javaw64', 'csrss64', 'minecraft', 'launcher'
)

# DLLs extracted to %TEMP% by KNOWN components (false-positive filter):
# mods/libraries that legitimately extract natives with hashed folder names.
$script:KnownTempNatives = @{
    'libopus4j'    = 'Simple Voice Chat native (Opus codec)'
    'librnnoise4j' = 'Simple Voice Chat native (noise suppression)'
    'libspeex4j'   = 'Simple Voice Chat native (Speex codec)'
    'liblame4j'    = 'Simple Voice Chat native (MP3 encoder)'
    'jnidispatch'  = 'JNA runtime extraction'
}

function Get-TempNativeLabel {
    param([string]$DllPath)
    $name = [System.IO.Path]::GetFileNameWithoutExtension($DllPath)
    if ([string]::IsNullOrEmpty($name)) { return $null }
    if ($script:KnownTempNatives.ContainsKey($name)) { return $script:KnownTempNatives[$name] }
    return $null
}

# System properties whose VALUE is a filesystem path we can validate
$script:PathKeys = @(
    'fabric.addMods'
    'loader.addMods'
    'fabric.gameJarPath'
    'loader.gameJarPath'
    'java.library.path'
    'org.lwjgl.librarypath'
    'jna.boot.library.path'
)

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
function Write-Result {
    param([string]$Text = '', $Color = 'Gray')
    if ($Text -eq '') { Write-Host '' } else { Write-Host $Text -ForegroundColor $Color }
    $script:Report.Add([pscustomobject]@{ Text = $Text; Color = "$Color" })
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsWithin {
    param([string]$Path, [string]$Root)
    if ([string]::IsNullOrEmpty($Path) -or [string]::IsNullOrEmpty($Root)) { return $false }
    $p = $Path.TrimEnd('\')
    $r = $Root.TrimEnd('\')
    return ($p -ieq $r -or $p.StartsWith($r + '\', [StringComparison]::OrdinalIgnoreCase))
}

function Find-BadKeyword {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $t = $Text.ToLowerInvariant()
    foreach ($k in $script:BadKeywords) {
        if ($t.Contains($k)) { return $k }
    }
    return $null
}

function Get-LevelColor {
    param([string]$Level)
    switch ($Level) {
        'Critical' { return 'Red' }
        'Warning'  { return 'Yellow' }
        'Info'     { return 'Cyan' }
        'OK'       { return 'Green' }
        default    { return 'Gray' }
    }
}

function Add-Hit {
    param([string]$Level)
    switch ($Level) {
        'Critical' { $script:Critical++ }
        'Warning'  { $script:WarningCount++ }
        'Info'     { $script:InfoCount++ }
    }
}

function New-Severity {
    param([string]$Level, [string]$Text)
    return @{ Level = $Level; Text = $Text }
}

# ----------------------------------------------------------------------
# Command line parsing
# ----------------------------------------------------------------------
function Get-JvmArgTokens {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return @() }
    $rest = $CommandLine
    if ($rest.StartsWith('"')) {
        $end = $rest.IndexOf('"', 1)
        if ($end -gt 0) { $rest = $rest.Substring($end + 1) }
    }
    else {
        $sp = $rest.IndexOf(' ')
        if ($sp -ge 0) { $rest = $rest.Substring($sp + 1) }
    }
    $tokens = @()
    foreach ($t in ($rest -split '\s+(?=-{1,2})')) {
        $t = $t.Trim()
        if ($t.Length -gt 2 -and $t.StartsWith('"') -and $t.EndsWith('"')) {
            $t = $t.Substring(1, $t.Length - 2)
        }
        if ($t -ne '') { $tokens += $t }
    }
    return $tokens
}

function Get-RelevantArgs {
    param([string[]]$ArgList)
    $relevantPatterns = @(
        '-javaagent*'
        '-agentpath*'
        '-agentlib*'
        '-Xbootclasspath*'
        '-Dfabric.addMods*'
        '-Dloader.addMods*'
        '-Dfabric.gameJarPath*'
        '-Dloader.gameJarPath*'
        '-Djava.library.path*'
        '-Dorg.lwjgl.librarypath*'
        '-Djna.boot.library.path*'
        '-Djdk.attach.allowAttachSelf*'
        '-Dfml.coreMods.load*'
        '--tweakClass*'
        '--launchTarget*'
    )
    $excludedPatterns = @('-cp*', '-classpath*')
    $out = @()
    foreach ($arg in $ArgList) {
        $isRelevant = $false
        foreach ($pat in $relevantPatterns) { if ($arg -like $pat) { $isRelevant = $true; break } }
        if (-not $isRelevant) { continue }
        $isExcluded = $false
        foreach ($pat in $excludedPatterns) { if ($arg -like $pat) { $isExcluded = $true; break } }
        if (-not $isExcluded) { $out += $arg }
    }
    return $out
}

function Get-ArgSeverity {
    param([string]$Arg)
    switch -Wildcard ($Arg) {
        '-javaagent*'                   { return (New-Severity 'Critical' 'Java agent injected into the JVM') }
        '-agentpath*'                   { return (New-Severity 'Critical' 'Native agent loaded (-agentpath)') }
        '-agentlib:jdwp*'               { return (New-Severity 'Warning'  'Debug agent active (jdwp)') }
        '-agentlib*'                    { return (New-Severity 'Critical' 'Native agent library loaded (-agentlib)') }
        '-Xbootclasspath*'              { return (New-Severity 'Critical' 'Boot classpath override - can replace core JVM classes') }
        '-Djdk.attach.allowAttachSelf*' {
            if ($Arg -match '(?i)false') { return (New-Severity 'Info' 'JVM self-attach disabled ( OK )') }
            return (New-Severity 'Critical' 'JVM self-attach enabled - allows late agent injection')
        }
        '-Dfabric.addMods*'             { return (New-Severity 'Warning' 'Fabric: extra mod files loaded from a custom path') }
        '-Dloader.addMods*'             { return (New-Severity 'Warning' 'Loader: extra mod files loaded from a custom path') }
        '-Dfabric.gameJarPath*'         { return (New-Severity 'Warning' 'Game jar redirected to a custom file') }
        '-Dloader.gameJarPath*'         { return (New-Severity 'Warning' 'Game jar redirected to a custom file') }
        '-Dfml.coreMods.load*'          { return (New-Severity 'Critical' 'Forge coremod injection') }
        '-Djava.library.path*'          { return (New-Severity 'Info' 'Native library path override') }
        '-Dorg.lwjgl.librarypath*'      { return (New-Severity 'Info' 'LWJGL native path override') }
        '-Djna.boot.library.path*'      { return (New-Severity 'Info' 'JNA boot library path override') }
        '--tweakClass*'                 { return (New-Severity 'Warning' 'Loader tweak class (legacy Forge/Fabric - verify)') }
        '--launchTarget*'               { return (New-Severity 'Info' 'Launcher target name') }
        default                         { return (New-Severity 'Info' '') }
    }
}

# ----------------------------------------------------------------------
# Path validation
# ----------------------------------------------------------------------
function Get-PathInfo {
    param([string]$RawPath)
    $p = [Environment]::ExpandEnvironmentVariables($RawPath.Trim().Trim('"'))
    $info = [pscustomobject]@{
        Path     = $p
        Exists   = $false
        Category = 'Other'
        Label    = ''
        Color    = 'Gray'
        Severity = 'Warning'
    }
    if ([string]::IsNullOrWhiteSpace($p)) {
        $info.Category = 'Missing'; $info.Label = 'EMPTY PATH'; $info.Color = 'Red'; $info.Severity = 'Critical'
        return $info
    }
    if (-not (Test-Path -LiteralPath $p)) {
        $info.Category = 'Missing'; $info.Label = 'PATH DOES NOT EXIST (while process is running!)'
        $info.Color = 'Red'; $info.Severity = 'Critical'
        return $info
    }
    $info.Exists = $true
    try { $info.Path = (Get-Item -LiteralPath $p).FullName } catch { }

    foreach ($r in $script:TempRoots) {
        if (Test-IsWithin $info.Path $r) {
            $info.Category = 'Temp'
            $info.Label    = 'inside TEMP - launchers do extract files here, verify the source'
            $info.Color    = 'Yellow'; $info.Severity = 'Warning'
            return $info
        }
    }
    foreach ($r in $script:DownloadRoots) {
        if (Test-IsWithin $info.Path $r) {
            $info.Category = 'Downloads'
            $info.Label    = 'inside Downloads - very unusual for a running game'
            $info.Color    = 'Red'; $info.Severity = 'Critical'
            return $info
        }
    }
    foreach ($r in $script:KnownRoots) {
        if (Test-IsWithin $info.Path $r) {
            $info.Category = 'Launcher'
            $info.Label    = 'inside known launcher folder ( OK )'
            $info.Color    = 'Green'; $info.Severity = 'OK'
            return $info
        }
    }
    $info.Category = 'Other'
    $info.Label    = 'custom location outside known launchers - verify'
    $info.Color    = 'Yellow'; $info.Severity = 'Warning'
    return $info
}

# ----------------------------------------------------------------------
# Java agent jar analysis
# ----------------------------------------------------------------------
function Get-AgentInfo {
    param([string]$RawPath)
    $result = [pscustomobject]@{
        Path      = [Environment]::ExpandEnvironmentVariables($RawPath.Trim().Trim('"'))
        Exists    = $false
        SizeKB    = 0
        Premain   = ''
        Packages  = @()
        IsKnown   = $false
        KnownName = ''
        Error     = ''
    }
    if ([string]::IsNullOrWhiteSpace($result.Path)) {
        $result.Error = 'empty -javaagent path'
        return $result
    }
    if (-not (Test-Path -LiteralPath $result.Path)) {
        $result.Error = 'jar NOT FOUND on disk (deleted or fake path)'
        return $result
    }
    $result.Exists = $true
    try { $result.SizeKB = [int]((Get-Item -LiteralPath $result.Path).Length / 1KB) } catch { }

    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($result.Path)
        try {
            $mf = $zip.GetEntry('META-INF/MANIFEST.MF')
            if ($mf) {
                $sr = New-Object System.IO.StreamReader($mf.Open())
                $manifest = $sr.ReadToEnd()
                $sr.Close()
                foreach ($line in ($manifest -split "`r?`n")) {
                    if ($line -match '^Premain-Class:\s*(.+)$') { $result.Premain = $Matches[1].Trim() }
                }
            }
            $pkgSet = @{}
            foreach ($entry in $zip.Entries) {
                $n = $entry.FullName
                if ($n -notlike '*.class') { continue }
                if ($n -like 'META-INF/*') { continue }
                $slash = $n.LastIndexOf('/')
                if ($slash -lt 1) { continue }
                $dirs = @($n.Substring(0, $slash) -split '/')
                $depth = [Math]::Min(3, $dirs.Count)
                $key = ($dirs[0..($depth - 1)] -join '.').ToLowerInvariant()
                $pkgSet[$key] = $true
                if ($pkgSet.Count -ge 8) { break }
            }
            $result.Packages = @($pkgSet.Keys | Sort-Object)
        }
        finally { $zip.Dispose() }
    }
    catch {
        $result.Error = 'cannot read jar: ' + $_.Exception.Message
    }

    $haystack = ($result.Premain + ' ' + ($result.Packages -join ' ')).ToLowerInvariant()
    foreach ($known in $script:KnownAgents) {
        if ($haystack.Contains($known.Token)) {
            $result.IsKnown   = $true
            $result.KnownName = $known.Name
            break
        }
    }
    return $result
}

# ----------------------------------------------------------------------
# Parent process + launch profile + DLLs
# ----------------------------------------------------------------------
function Get-ParentInfo {
    param($Process)
    $info = [pscustomobject]@{
        Pid        = $Process.ParentProcessId
        Name       = ''
        Path       = ''
        IsKnown    = $false
        Kind       = ''
        Suspicious = $false
        Note       = ''
    }
    if (-not $info.Pid -or $info.Pid -le 0) { $info.Note = 'no parent recorded'; return $info }
    try {
        $parent = Get-CimInstance Win32_Process -Filter "ProcessId = $($info.Pid)" -ErrorAction Stop
    }
    catch { $parent = $null }
    if (-not $parent) { $info.Note = "parent process already exited (PID $($info.Pid))"; return $info }

    $info.Name = $parent.Name
    $info.Path = $parent.ExecutablePath
    $launcherParents = @(
        'modrinth app.exe', 'curseforge.exe', 'minecraftlauncher.exe', 'minecraft.exe',
        'prismlauncher.exe', 'multimc.exe', 'atlauncher.exe', 'gdlauncher.exe',
        'techniclauncher.exe', 'serverlauncher.exe', 'steam.exe', 'javaw.exe', 'java.exe'
    )
    $consoleParents = @(
        'explorer.exe', 'powershell.exe', 'pwsh.exe', 'cmd.exe',
        'windowsterminal.exe', 'openconsole.exe', 'conhost.exe'
    )
    $lowerName = "$($info.Name)".ToLowerInvariant()
    if ($launcherParents -contains $lowerName) { $info.IsKnown = $true; $info.Kind = 'launcher' }
    elseif ($consoleParents -contains $lowerName) { $info.IsKnown = $true; $info.Kind = 'console' }
    if ($info.Path) {
        foreach ($r in ($script:TempRoots + $script:DownloadRoots)) {
            if (Test-IsWithin $info.Path $r) { $info.Suspicious = $true }
        }
    }
    return $info
}

function Get-LaunchProfile {
    param([string]$CommandLine)
    $c = $CommandLine
    if ($c -match '(?i)org\.quiltmc\.loader\.impl\.launch\.knot')      { return 'Quilt Loader (Knot)' }
    if ($c -match '(?i)net\.fabricmc\.loader\.impl\.launch\.knot')     { return 'Fabric Loader (Knot)' }
    if ($c -match '(?i)cpw\.mods\.bootstraplauncher')                  { return 'Forge / NeoForge (BootstrapLauncher)' }
    if ($c -match '(?i)net\.minecraft\.launchwrapper')                 { return 'Legacy launchwrapper (old Forge)' }
    if ($c -match '(?i)net\.minecraft\.client\.main\.Main')            { return 'Vanilla Minecraft' }
    if ($c -match '(?i)net\.minecraft\.client\.Main')                  { return 'Vanilla Minecraft' }
    return ''
}

function Show-ProcessModules {
    param($Process, [string]$JavaDir, [string]$NativeDir)
    if ($SkipModules) { return }
    $modules = @()
    try {
        $netProc = [System.Diagnostics.Process]::GetProcessById($Process.ProcessId)
        $modules = @($netProc.Modules)
    }
    catch {
        Write-Result '  [ DLLS ] cannot read the module list ( try running as Administrator )' DarkYellow
        return
    }
    $tempHits  = New-Object System.Collections.Generic.List[string]
    $extHits   = New-Object System.Collections.Generic.List[string]
    $knownTemp = New-Object System.Collections.Generic.List[object]
    $seenTemp  = @{}
    $seenExt   = @{}
    $seenKnown = @{}
    $seenExt   = @{}
    foreach ($m in $modules) {
        $mp = $m.FileName
        if ([string]::IsNullOrWhiteSpace($mp)) { continue }
        $skip = $false
        if (Test-IsWithin $mp $env:windir) { $skip = $true }
        if (-not $skip -and $JavaDir -and (Test-IsWithin $mp $JavaDir)) { $skip = $true }
        if (-not $skip -and $NativeDir -and (Test-IsWithin $mp $NativeDir)) { $skip = $true }
        if (-not $skip) {
            foreach ($r in $script:KnownRoots) { if (Test-IsWithin $mp $r) { $skip = $true; break } }
        }
        if ($skip) { continue }

        $isBad = $false
        foreach ($r in ($script:TempRoots + $script:DownloadRoots)) {
            if (Test-IsWithin $mp $r) { $isBad = $true; break }
        }
        if ($isBad) {
            $label = Get-TempNativeLabel -DllPath $mp
            if ($label) {
                if (-not $seenKnown.ContainsKey($mp.ToLowerInvariant())) {
                    $seenKnown[$mp.ToLowerInvariant()] = $true
                    $knownTemp.Add([pscustomobject]@{ Path = $mp; Label = $label })
                }
            }
            elseif (-not $seenTemp.ContainsKey($mp.ToLowerInvariant())) {
                $seenTemp[$mp.ToLowerInvariant()] = $true
                $tempHits.Add($mp)
            }
        }
        else {
            if (-not $seenExt.ContainsKey($mp.ToLowerInvariant())) {
                $seenExt[$mp.ToLowerInvariant()] = $true
                $extHits.Add($mp)
            }
        }
    }

    if ($knownTemp.Count -gt 0) {
        Write-Result "  [ DLLS ] TEMP-extracted natives from KNOWN components ( normal ): $($knownTemp.Count)" DarkCyan
        foreach ($k in $knownTemp) { Write-Result "      $($k.Path)   ( $($k.Label) )" DarkGray }
    }
    if ($tempHits.Count -gt 0) {
        $script:Critical++
        Write-Result "  [ CRITICAL ] $($tempHits.Count) UNKNOWN DLL(s) loaded from TEMP/DOWNLOADS - INJECTION SUSPECT:" Red
        foreach ($t in $tempHits) {
            $sig = 'UnknownError'
            try { $sig = (Get-AuthenticodeSignature -LiteralPath $t -ErrorAction Stop).Status.ToString() } catch { }
            Write-Result "      $t   [ $sig ]" Red
        }
    }
    if ($extHits.Count -gt 0) {
        Write-Result "  [ DLLS ] outside Java/Windows/launcher folders: $($extHits.Count) ( overlays, vendors - verify )" DarkCyan
        $shown    = 0
        $unsigned = 0
        foreach ($e in $extHits) {
            if ($shown -ge 20) { Write-Result "      ... +$($extHits.Count - $shown) more" DarkGray; break }
            $sig = 'UnknownError'
            try { $sig = (Get-AuthenticodeSignature -LiteralPath $e -ErrorAction Stop).Status.ToString() } catch { }
            if ($sig -eq 'Valid') {
                Write-Result "      $e   [ SIGNED ]" DarkGray
            }
            else {
                $unsigned++
                Write-Result "      $e   [ $sig - NOT VALIDLY SIGNED ]" Yellow
            }
            $shown++
        }
        if ($unsigned -gt 0) {
            $script:WarningCount++
            Write-Result "  [ REVIEW ] $unsigned unsigned/untrusted external DLL(s) loaded in the JVM process" Yellow
        }
    }
}

# ----------------------------------------------------------------------
# Environment persistence check
# ----------------------------------------------------------------------
function Show-EnvFlags {
    Write-Result '[ 01 ] ============ MACHINE-WIDE JVM VECTORS ( affect every Java process ) ============' Green
    Write-Result '  [ ENV ] Environment variables' DarkCyan
    $any = $false
    foreach ($name in @('JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS')) {
        foreach ($scope in @('Machine', 'User', 'Process')) {
            try { $v = [Environment]::GetEnvironmentVariable($name, $scope) } catch { $v = $null }
            if ([string]::IsNullOrWhiteSpace($v)) { continue }
            $any = $true
            $vShow = $v.Trim()
            if ($vShow.Length -gt 160) { $vShow = $vShow.Substring(0, 160) + ' ...' }
            if ($vShow -match '(?i)(-javaagent|-agentpath|-agentlib|-Xbootclasspath)') {
                $script:Critical++
                Write-Result "  [ CRITICAL ] $name ( $scope ) = $vShow" Red
                Write-Result '               -> persistent agent/classpath injection vector - not normal' Red
            }
            else {
                $script:WarningCount++
                Write-Result "  [ REVIEW ]   $name ( $scope ) = $vShow" Yellow
            }
        }
    }
    if (-not $any) { Write-Result '  [ OK ] none set ( machine, user, process )' DarkGray }
    Show-AttachTools
    Show-PersistenceCheck
    Write-Result ''
}

function Show-AttachTools {
    $toolNames = @('jcmd', 'jdb', 'jhsdb', 'jattach', 'jconsole', 'jvisualvm', 'visualvm')
    $running = @()
    foreach ($n in $toolNames) {
        $p = Get-Process -Name $n -ErrorAction SilentlyContinue
        if ($p) { $running += $p }
    }
    if ($running.Count -eq 0) { return }
    $script:WarningCount++
    $names = (@($running | ForEach-Object { $_.ProcessName }) | Sort-Object -Unique) -join ', '
    Write-Result "  [ REVIEW ] JVM attach/diagnostic tool(s) running: $names" Yellow
    Write-Result '             -> these can inject agents into a LIVE JVM - check what they are attached to' Yellow
}

function Show-PersistenceCheck {
    $entries = @()
    try { $entries = @(Get-CimInstance Win32_StartupCommand -ErrorAction Stop) } catch { }
    $flagged = 0
    foreach ($e in $entries) {
        $cmd = "$($e.Command)"
        if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
        $cmd = [Environment]::ExpandEnvironmentVariables($cmd)
        $lvl = $null
        if ($cmd -match '(?i)(-javaagent|-agentpath|-agentlib|-Xbootclasspath)') { $lvl = 'Critical' }
        elseif ($cmd -match '(?i)(javaw?\.exe|\.jar\b)')                          { $lvl = 'Warning' }
        elseif ($cmd -match [regex]::Escape($env:TEMP))                          { $lvl = 'Critical' }
        if (-not $lvl) { continue }
        $flagged++
        Add-Hit $lvl
        $cShow = $cmd
        if ($cShow.Length -gt 160) { $cShow = $cShow.Substring(0, 160) + ' ...' }
        Write-Result "  [ $($lvl.ToUpper()) ] Startup entry: $($e.Name)   ( $($e.Location) )" (Get-LevelColor $lvl)
        Write-Result "             $cShow" DarkGray
    }
    if ($flagged -eq 0) {
        Write-Result '  [ OK ] startup persistence: no Java/agent-related auto-start entries' DarkGray
    }
}

# ----------------------------------------------------------------------
# Mods inventory
# ----------------------------------------------------------------------
function Get-ModsDirectories {
    $found = @{}
    $searchRoots = @(
        "$env:APPDATA\ModrinthApp\instances"   # Modrinth App (older builds)
        "$env:APPDATA\ModrinthApp\profiles"    # Modrinth App (current builds)
        "$env:APPDATA\.minecraft"
        "$env:USERPROFILE\curseforge\minecraft\Instances"
        "$env:APPDATA\CurseForge\Instances"
        "$env:APPDATA\PrismLauncher\instances"
        "$env:APPDATA\MultiMC\instances"
        "$env:APPDATA\ATLauncher"
        "$env:APPDATA\.techniclauncher"
        "$env:APPDATA\gdlauncher"
    )
    if ($ModsPath) {
        if (Test-Path -LiteralPath $ModsPath) {
            $item = Get-Item -LiteralPath $ModsPath
            if ($item.PSIsContainer -and ((Split-Path -Leaf $item.FullName) -ieq 'mods')) {
                $found[$item.FullName.ToLowerInvariant()] = $item.FullName
            }
            elseif ($item.PSIsContainer) {
                foreach ($d in @(Get-ChildItem -LiteralPath $item.FullName -Directory -Recurse -Depth 3 -Filter 'mods' -ErrorAction SilentlyContinue)) {
                    $found[$d.FullName.ToLowerInvariant()] = $d.FullName
                }
            }
        }
    }
    foreach ($r in $searchRoots) {
        if (-not (Test-Path -LiteralPath $r)) { continue }
        if ((Split-Path -Leaf $r) -ieq 'mods') { $found[$r.ToLowerInvariant()] = $r }
        foreach ($d in @(Get-ChildItem -LiteralPath $r -Directory -Recurse -Depth 3 -Filter 'mods' -ErrorAction SilentlyContinue)) {
            $found[$d.FullName.ToLowerInvariant()] = $d.FullName
        }
    }
    return @($found.Values | Sort-Object)
}

# String scan inside class constant-pools (single pass over every jar):
#  - Crack markers  -> Critical   ("Cracked by <cracker>", license/HWID scaffolding)
#  - Cheat strings  -> Warning    (module/feature names typical of cheat clients,
#                                  generic flags that work on ANY client - private
#                                  ones included. Verify, never proof.)
function Find-JarStringHits {
    param([string]$JarPath)

    # Regexes built once (script scope) for speed:
    #  - markers get word boundaries -> 'hwid' no longer matches inside 'withWidth'
    #  - cheat phrases tolerate spaces / underscores / hyphens
    #    (killaura = Kill Aura = kill-aura = Kill_Aura); end guard (?!\p{Ll})
    #    keeps 'ClickGuiManager' matching but 'hudx' out.
    if (-not $script:CheatRx) {
        $markers = @('cracked by', 'crackedby', 'crack by', '648k', 'license key', 'keyauth', 'hwid')
        $script:MarkerRx = @{}
        foreach ($mk in $markers) {
            $script:MarkerRx[$mk] = [regex]::new(
                '(?<![0-9A-Za-z])' + [regex]::Escape($mk) + '(?![0-9A-Za-z])',
                [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
        $words = @(
            # combat
            'kill aura','crystal aura','mace aura','silent mace','aim assist','silent aim',
            'bow aimbot','triggerbot','anti weakness','fake punch','damage tick','only crit',
            'static hitbox','shield disabler','anti invis','w tap'
            # crystal / anchor pvp
            'auto crystal','crystal optimizer','cw crystal','double anchor','anchor exploder',
            'auto dtap','marlow anchor','anti anti cw','auto hit crystal'
            # totem
            'auto totem','totem offhand','hover totem','force totem','auto retotem',
            'inventorytotemlegit','auto double hand'
            # movement
            'fast bridge','bridge assist','fast swim','fast place','no break delay',
            'no jump delay','elytra swap','elytra glide','jetpack','auto sprint','inventory move'
            # utility / automation
            'auto clicker','auto pot','auto eat','auto xp','auto armor','auto tool','auto mine',
            'chest steal','shulker dropper','auto sell','cord snapper','key pearl','auto tpa',
            'bed macro','auto restock','replace mod'
            # esp / vision
            'player esp','storage esp','entity esp','esp','x ray','health indicators',
            'target hud','netherite finder','rtp base finder'
            # evasion / anticheat bypass
            'fake lag','ping spoof','pack spoof','stray bypass','donut smp bypass',
            'anti ss tool','string cleaner','self destruct','usn journal cleaner',
            'delete usn journal'
        )
        $phraseRx = ($words | ForEach-Object {
            $t = [regex]::Escape($_) -replace '\\\ ', '[\s_-]?'
            "(?<!\w)$t(?!\p{Ll})"
        }) -join '|'
        $script:CheatRx = [regex]::new($phraseRx,
            [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
            [Text.RegularExpressions.RegexOptions]::Compiled)

        # Fast gate: the full regex above costs ~7ms/KB (way too slow to run on
        # every class), so candidates are pre-filtered with plain IndexOf on a
        # separator-stripped lowercase copy (kill aura / Kill_Aura / kill-aura
        # all collapse to 'killaura'). Only classes that pass the gate are run
        # through the full regex for precise match + boundary checks.
        $script:CheatGates = @($words |
            ForEach-Object { $_ -replace '[ _\-]', '' } |
            Where-Object { $_ -ne 'esp' } | Select-Object -Unique)
        $script:StripRx = [regex]::new('[ _\-]', [Text.RegularExpressions.RegexOptions]::Compiled)
    }
    $markers = @($script:MarkerRx.Keys)

    $foundM = @{}   # marker -> first class file that contains it
    $foundC = @{}   # matched text -> pscustomobject { Match; Class; Context }
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($JarPath)
        try {
            $enc = [System.Text.Encoding]::GetEncoding(28591)
            foreach ($e in $zip.Entries) {
                if ($foundM.Count -ge $markers.Count -and $foundC.Count -ge 6) { break }
                if ($e.FullName -notlike '*.class') { continue }
                $ms = New-Object System.IO.MemoryStream
                $s  = $e.Open(); $s.CopyTo($ms); $s.Close()
                $str = $enc.GetString($ms.ToArray())
                $ms.Dispose()
                # collapse binary noise: matching runs on printable text only,
                # this also cuts the regex cost over raw bytecode ~2-3x
                $clean = [regex]::Replace($str, '[^\x20-\x7E]+', ' ')

                foreach ($mk in $markers) {
                    if ($foundM.ContainsKey($mk)) { continue }
                    if ($script:MarkerRx[$mk].IsMatch($clean)) {
                        $foundM[$mk] = $e.FullName
                        break
                    }
                }

                if ($foundC.Count -lt 6) {
                    # gate first (cheap): normalized copy + IndexOf per phrase.
                    # 'esp' alone is excluded from the phrase gates (it matches
                    # inside normal words) - standalone ESP is gated separately
                    # as the uppercase form only, which legit code rarely uses.
                    $low = $script:StripRx.Replace($clean, '').ToLowerInvariant()
                    $gate = $clean.IndexOf('ESP', [StringComparison]::Ordinal) -ge 0
                    if (-not $gate) {
                        foreach ($g in $script:CheatGates) {
                            if ($low.IndexOf($g, [StringComparison]::Ordinal) -ge 0) { $gate = $true; break }
                        }
                    }
                    if ($gate) {
                        foreach ($mt in $script:CheatRx.Matches($clean)) {
                            $key = $mt.Value.ToLowerInvariant()
                            if ($foundC.ContainsKey($key)) { continue }
                            # context around the hit as evidence
                            $from = [Math]::Max(0, $mt.Index - 40)
                            $len  = [Math]::Min($clean.Length - $from, $mt.Length + 80)
                            $ctx  = ($clean.Substring($from, $len) -replace '\s{2,}', ' ').Trim()
                            $foundC[$key] = [pscustomobject]@{
                                Match = $mt.Value; Class = $e.FullName; Context = $ctx
                            }
                            if ($foundC.Count -ge 6) { break }
                        }
                    }
                }
            }
        }
        finally { $zip.Dispose() }
    }
    catch { }

    $mOut = @()
    foreach ($k in $foundM.Keys) { $mOut += [pscustomobject]@{ Marker = $k; Class = $foundM[$k] } }
    $cOut = @()
    foreach ($k in $foundC.Keys) { $cOut += $foundC[$k] }
    return [pscustomobject]@{ Markers = $mOut; Cheats = $cOut }
}

# Full printable-string dump of a jar (manual analysis aid):
# every readable run >= 5 chars of every entry, "entry<TAB>string" per line.
function Export-JarStrings {
    param([string]$JarPath, [string]$OutPath)
    $entries = 0; $strings = 0
    $sb = New-Object System.Text.StringBuilder
    $zip = [System.IO.Compression.ZipFile]::OpenRead($JarPath)
    try {
        $enc = [System.Text.Encoding]::GetEncoding(28591)
        foreach ($e in $zip.Entries) {
            if ($e.Length -eq 0 -or $e.Length -gt 20MB) { continue }
            $entries++
            $ms = New-Object System.IO.MemoryStream
            $s  = $e.Open(); $s.CopyTo($ms); $s.Close()
            $str = $enc.GetString($ms.ToArray())
            $ms.Dispose()
            foreach ($mt in [regex]::Matches($str, '[\x20-\x7E]{5,}')) {
                [void]$sb.AppendLine($e.FullName + "`t" + $mt.Value)
                $strings++
            }
        }
    }
    finally { $zip.Dispose() }
    [System.IO.File]::WriteAllText($OutPath, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))
    return [pscustomobject]@{ Entries = $entries; Strings = $strings; Path = $OutPath }
}

# Identity metadata of a mod jar: what the jar CLAIMS to be vs its file name.
function Get-ModMetadata {
    param([string]$JarPath)
    $meta = [pscustomobject]@{
        Id = ''; Name = ''; Version = ''; Entrypoints = ''
        Containers = @(); Error = ''
    }
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($JarPath)
        try {
            $e = $zip.GetEntry('fabric.mod.json')
            if ($e) {
                $sr = New-Object System.IO.StreamReader($e.Open())
                $json = $sr.ReadToEnd(); $sr.Close()
                try {
                    $j = $json | ConvertFrom-Json
                    $meta.Id      = "$($j.id)"
                    $meta.Name    = "$($j.name)"
                    $meta.Version = "$($j.version)"
                    if ($j.entrypoints) {
                        $eps = @()
                        foreach ($p in $j.entrypoints.PSObject.Properties) {
                            $first = @($p.Value) | Select-Object -First 1
                            $eps += "$($p.Name)=$first"
                        }
                        $meta.Entrypoints = $eps -join ', '
                    }
                }
                catch { $meta.Error = 'fabric.mod.json not parseable' }
            }
            foreach ($n in @('fabric_loader.json', 'META-INF/jars/fabric.mod.json')) {
                $ce = $zip.GetEntry($n)
                if (-not $ce) { continue }
                $sr2 = New-Object System.IO.StreamReader($ce.Open())
                $cj  = $sr2.ReadToEnd(); $sr2.Close()
                try {
                    $cjObj = $cj | ConvertFrom-Json
                    if ($cjObj.id) { $meta.Containers += "$($cjObj.id) ($($cjObj.name))" }
                }
                catch { }
            }
        }
        finally { $zip.Dispose() }
    }
    catch { $meta.Error = $_.Exception.Message }
    return $meta
}

function Show-ModsInventory {
    Write-Result ''
    Write-Result '[ 03 ] ==================== MODS INVENTORY ( known launcher instances ) ====================' Green
    $dirs = Get-ModsDirectories
    if ($dirs.Count -eq 0) {
        Write-Result '  [ ! ] No known launcher mods folders found. Use -ModsPath "C:\path\to\mods" to check one manually.' DarkYellow
        return
    }
    foreach ($d in $dirs) {
        $jars = @(Get-ChildItem -LiteralPath $d -Filter '*.jar' -File -ErrorAction SilentlyContinue | Sort-Object Name)
        Write-Result ''
        Write-Result "  [ MODS ] $d   ( $($jars.Count) jars )" DarkCyan
        if ($jars.Count -eq 0) { continue }
        $shown = 0
        foreach ($jar in $jars) {
            if ($shown -ge 400) {
                Write-Result "      ... +$($jars.Count - $shown) more jars not shown" DarkGray
                break
            }
            $kw = Find-BadKeyword $jar.Name
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($jar.Name)
            $isDisguised = ($script:DisguisedNames -contains $baseName)
            $isFlagged = ($kw -or $isDisguised)
            $hashTxt = ''
            if ($Hash -or $isFlagged) {
                try {
                    $h = (Get-FileHash -LiteralPath $jar.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                    $hashTxt = '  [ sha256: ' + $h.Substring(0, 12) + ' ]'
                }
                catch { $hashTxt = '  [ sha256: <unreadable> ]' }
            }
            $line = '      {0}   ( {1} KB, {2:yyyy-MM-dd} ){3}' -f $jar.Name, [int]($jar.Length / 1KB), $jar.LastWriteTime, $hashTxt
            if ($kw) {
                $script:WarningCount++
                Write-Result ('[ ! ] ' + $line.TrimStart()) Yellow
                Write-Result "          -> keyword '$kw' matched - open and verify this jar" Yellow
            }
            elseif ($isDisguised) {
                $script:WarningCount++
                Write-Result ('[ ! ] ' + $line.TrimStart()) Yellow
                Write-Result '          -> jar disguised as a system/process file name - verify this jar' Yellow
            }
            else {
                Write-Result $line DarkGray
            }

            # string scan: crack markers + cheat module strings (EVERY jar)
            $hits = Find-JarStringHits -JarPath $jar.FullName
            if ($hits.Markers.Count -gt 0) {
                $script:Critical++
                Write-Result '          [ CRITICAL ] crack/cheat marker(s) found inside class strings:' Red
                foreach ($mk in $hits.Markers) {
                    Write-Result "              [ $($mk.Marker) ]  <-  $($mk.Class)" Red
                }
                Write-Result '          -> cracked/pirated client = cheat + malware risk - DO NOT RUN' Red
            }
            if ($hits.Cheats.Count -gt 0) {
                $script:WarningCount++
                Write-Result '          [ WARNING ] generic cheat flag(s) - module/feature strings inside classes ( verify ):' Yellow
                foreach ($ch in $hits.Cheats) {
                    Write-Result "              [ $($ch.Match) ]  <-  $($ch.Class)" Yellow
                    Write-Result "                  ( context: $($ch.Context) )" DarkGray
                }
                Write-Result '          -> matches cheat module names regardless of client - check this jar' Yellow
            }

            # identity deep-dive for flagged jars: what does the jar CLAIM to be?
            if ($isFlagged) {
                $md = Get-ModMetadata -JarPath $jar.FullName
                if ($md.Id) {
                    Write-Result "          -> claims to be: id=$($md.Id)  name=$($md.Name)  version=$($md.Version)" DarkGray
                    if ($md.Entrypoints) { Write-Result "          -> entrypoints: $($md.Entrypoints)" DarkGray }
                    if (-not $baseName.ToLowerInvariant().Contains($md.Id.ToLowerInvariant())) {
                        $script:WarningCount++
                        Write-Result "          [ MISMATCH ] file name does not match mod id '$($md.Id)' - jar is disguised" Yellow
                    }
                }
                elseif ($md.Error) {
                    Write-Result "          -> identity unreadable: $($md.Error)" DarkYellow
                }
                if ($md.Containers.Count -gt 0) {
                    Write-Result ('          -> hidden nested containers: ' + ($md.Containers -join ', ')) DarkGray
                }
            }
            $shown++
        }
    }
}

# ----------------------------------------------------------------------
# Per-process report
# ----------------------------------------------------------------------
function Show-ProcessReport {
    param($Process)
    Write-Result "  [ PROCESS ] PID $($Process.ProcessId)   ( $($Process.Name) )" Cyan

    $cmd = $Process.CommandLine
    if (-not $cmd) {
        Write-Result '    [ ! ] CommandLine not accessible ( run PowerShell as admin )' DarkYellow
        Write-Result ''
        return
    }

    $profile = Get-LaunchProfile -CommandLine $cmd
    if ($profile) { Write-Result "    Launch profile : $profile" DarkGray }

    $parent = Get-ParentInfo -Process $Process
    if ($parent.Suspicious) {
        $script:Critical++
        Write-Result "    [ CRITICAL ] Parent: $($parent.Name) ( PID $($parent.Pid) ) launched FROM TEMP/DOWNLOADS - injection suspect" Red
    }
    elseif ($parent.IsKnown) {
        $parentKind = if ($parent.Kind -eq 'console') { 'trusted console' } else { 'trusted launcher' }
        Write-Result "    Parent         : $($parent.Name)   [ OK ] ( $parentKind )" DarkGray
    }
    elseif ($parent.Note) {
        Write-Result "    Parent         : $($parent.Note)" DarkGray
    }
    else {
        Write-Result "    Parent         : $($parent.Name) ( PID $($parent.Pid) )   [ REVIEW ] - unknown parent, verify" DarkYellow
    }

    $tokens      = Get-JvmArgTokens -CommandLine $cmd
    $relevant    = @(Get-RelevantArgs -ArgList $tokens)
    $nativeDir   = ''
    $argKeyword  = $false

    if ($relevant.Count -eq 0) {
        Write-Result '    ( no relevant arguments found )' DarkGray
    }

    foreach ($arg in $relevant) {
        $script:TotalRelevant++
        $sev     = Get-ArgSeverity -Arg $arg
        $details = New-Object System.Collections.Generic.List[object]

        # ---- javaagent: deep jar analysis -------------------------------
        if ($arg -like '-javaagent:*') {
            $raw = $arg.Substring('-javaagent:'.Length)
            $eq  = $raw.IndexOf('=')
            if ($eq -gt 0) { $raw = $raw.Substring(0, $eq) }
            $agent = Get-AgentInfo -RawPath $raw
            $details.Add(@{ Text = "     -> file: $($agent.Path)" + $(if ($agent.Exists) { "  ($($agent.SizeKB) KB)" } else { '' }); Color = 'Gray' })
            if (-not $agent.Exists) {
                $sev = New-Severity 'Critical' 'java agent jar missing/deleted while process runs'
                $details.Add(@{ Text = "     -> $($agent.Error)"; Color = 'Red' })
            }
            elseif ($agent.IsKnown) {
                $sev = New-Severity 'OK' "known launcher agent: $($agent.KnownName)"
                if ($agent.Premain) { $details.Add(@{ Text = "     -> Premain-Class: $($agent.Premain)"; Color = 'Gray' }) }
                if ($agent.Packages.Count) { $details.Add(@{ Text = '     -> packages: ' + ($agent.Packages -join ', '); Color = 'Gray' }) }
                $details.Add(@{ Text = "     -> [ KNOWN LEGITIMATE AGENT ] $($agent.KnownName)"; Color = 'Green' })
            }
            else {
                $sev = New-Severity 'Critical' 'UNKNOWN java agent - manual verification required'
                if ($agent.Premain) { $details.Add(@{ Text = "     -> Premain-Class: $($agent.Premain)"; Color = 'Yellow' }) }
                if ($agent.Packages.Count) { $details.Add(@{ Text = '     -> packages: ' + ($agent.Packages -join ', '); Color = 'Yellow' }) }
                if ($agent.Error) { $details.Add(@{ Text = "     -> $($agent.Error)"; Color = 'Red' }) }
                $details.Add(@{ Text = '     -> [ UNKNOWN AGENT ] not a known launcher agent - open the jar and verify its origin'; Color = 'Red' })
            }
        }
        # ---- -D system property with a path value -----------------------
        elseif ($arg.StartsWith('-D') -and $arg.IndexOf('=') -gt 0) {
            $eq   = $arg.IndexOf('=')
            $key  = $arg.Substring(2, $eq - 2)
            $val  = $arg.Substring($eq + 1)
            if ($script:PathKeys -contains $key) {
                $worst = 'OK'
                foreach ($rawPath in ($val -split ',')) {
                    if ([string]::IsNullOrWhiteSpace($rawPath)) { continue }
                    $pi = Get-PathInfo -RawPath $rawPath
                    $details.Add(@{ Text = "     -> $($pi.Path)"; Color = 'Gray' })
                    $details.Add(@{ Text = "        $($pi.Label)"; Color = $pi.Color })
                    if ($pi.Severity -eq 'Critical' -and $worst -ne 'Critical') { $worst = 'Critical' }
                    elseif ($pi.Severity -eq 'Warning' -and $worst -eq 'OK')   { $worst = 'Warning' }
                    if ($key -eq 'java.library.path' -and $pi.Exists) { $nativeDir = $pi.Path }
                }
                if ($worst -eq 'Critical' -and $sev.Level -ne 'Critical') {
                    $sev = New-Severity 'Critical' 'referenced path problem (missing or in Downloads)'
                }
                elseif ($worst -eq 'Warning' -and $sev.Level -eq 'Info') {
                    $sev = New-Severity 'Warning' 'path outside known launcher folders'
                }
            }
        }

        # ---- keyword scan over the whole argument -----------------------
        $kw = Find-BadKeyword $arg
        if ($kw) {
            $script:WarningCount++
            $argKeyword = $true
            $details.Add(@{ Text = "     -> [ ! ] keyword '$kw' matched - verify manually ( keyword is NOT proof )"; Color = 'Yellow' })
        }

        Write-Result ('  ' + $arg) (Get-LevelColor $sev.Level)
        if ($sev.Text) { Write-Result "     // $($sev.Text)" (Get-LevelColor $sev.Level) }
        foreach ($d in $details) { Write-Result $d.Text $d.Color }
        Add-Hit $sev.Level
    }

    # ---- keyword scan over the FULL command line (classpath / main args) ----
    if (-not $argKeyword) {
        $cmdKw = Find-BadKeyword $cmd
        if ($cmdKw) {
            $script:WarningCount++
            Write-Result "  [ ! ] Keyword '$cmdKw' found in the full command line ( classpath/main args ) - open and verify" Yellow
        }
    }

    # ---- injected / external DLLs ---------------------------------------
    $javaDir = $Process.ExecutablePath
    if (-not $javaDir -and $cmd) {
        if ($cmd.StartsWith('"')) {
            $end = $cmd.IndexOf('"', 1)
            if ($end -gt 1) { $javaDir = $cmd.Substring(1, $end - 1) }
        }
        else {
            $sp = $cmd.IndexOf(' ')
            if ($sp -gt 0) { $javaDir = $cmd.Substring(0, $sp) }
        }
    }
    if ($javaDir) { $javaDir = Split-Path -Parent $javaDir }
    Show-ProcessModules -Process $Process -JavaDir $javaDir -NativeDir $nativeDir
    Write-Result ''
}

# ----------------------------------------------------------------------
# Report save
# ----------------------------------------------------------------------
function Save-Report {
    if (-not $OutFile) { return }
    $path = $OutFile
    if (-not [System.IO.Path]::IsPathRooted($path)) { $path = Join-Path (Get-Location).Path $path }
    try {
        if ($path -match '(?i)\.html?$') {
            [System.IO.File]::WriteAllText($path, (ConvertTo-HtmlReport), [System.Text.UTF8Encoding]::new($false))
        }
        else {
            $lines = @($script:Report | ForEach-Object { $_.Text })
            [System.IO.File]::WriteAllLines($path, $lines, [System.Text.UTF8Encoding]::new($false))
        }
        Write-Result "  [ OK ] Report saved: $path" Green
    }
    catch {
        Write-Result "Could not save report: $($_.Exception.Message)" Red
    }
}

function ConvertTo-HtmlReport {
    $colorMap = @{
        Red = 'crit'; Yellow = 'warn'; Cyan = 'info'; Green = 'ok'
        DarkGray = 'muted'; Gray = 'txt'; DarkYellow = 'warn2'
        DarkCyan = 'hdr'; DarkBlue = 'hdr'; Magenta = 'hdr'; White = 'txt'
    }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<title>JVM Inspector v3 - Screenshare Report</title>')
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine('body{background:#0d1117;color:#c9d1d9;padding:24px;margin:0}')
    [void]$sb.AppendLine('h1{color:#00FFB3;font:600 20px Consolas,monospace;margin:0 0 4px}')
    [void]$sb.AppendLine('.meta{color:#6e7681;font:13px Segoe UI,sans-serif;margin-bottom:18px}')
    [void]$sb.AppendLine('pre{white-space:pre-wrap;font:13px Consolas,"Courier New",monospace;margin:0}')
    [void]$sb.AppendLine('.crit{color:#ff5555;font-weight:700}.warn{color:#ffd166}.warn2{color:#b28500}')
    [void]$sb.AppendLine('.info{color:#4dd2ff}.ok{color:#00FFB3;font-weight:700}.muted{color:#6e7681}')
    [void]$sb.AppendLine('.hdr{color:#00FFB3;font-weight:700}.txt{color:#c9d1d9}')
    [void]$sb.AppendLine('</style></head><body>')
    [void]$sb.AppendLine('<h1>JVM Inspector v3 - Minecraft Screenshare Forensics</h1>')
    [void]$sb.AppendLine('<div class="meta">Generated: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') +
        ' | Host: ' + [Environment]::MachineName + ' | User: ' + [Environment]::UserName + '</div>')
    [void]$sb.AppendLine('<pre>')
    foreach ($r in $script:Report) {
        $cls = $colorMap[$r.Color]
        if (-not $cls) { $cls = 'txt' }
        $esc = [System.Net.WebUtility]::HtmlEncode($r.Text)
        [void]$sb.AppendLine('<span class="' + $cls + '">' + $esc + '</span>')
    }
    [void]$sb.AppendLine('</pre></body></html>')
    return $sb.ToString()
}

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
Clear-Host
Write-Result '[ ================================================================== ]' Green
Write-Result '   JVM INSPECTOR v3   -   Minecraft Screenshare Forensics' Green
Write-Result '   ( original: Tonynoh - discord.gg/ssa )   ( fork & improvements: ItzMeow80 )' DarkCyan
Write-Result '[ ================================================================== ]' Green
Write-Result ''
Write-Result '  Tool      :  JVM Inspector v3 ( forensics build )' DarkCyan
if (Test-IsAdmin) {
    Write-Result '  Elevation :  [ ADMIN ]' Green
}
else {
    Write-Result '  Elevation :  [ NO-ADMIN ] ( run as Administrator for DLL & parent checks )' Yellow
}
Write-Result ''

Show-EnvFlags

$processes = @(Get-CimInstance Win32_Process -Filter "name = 'javaw.exe' OR name = 'java.exe'")
Write-Result '[ 02 ] ==================== LIVE JAVA PROCESSES ( at scan time ) ====================' Green
if (-not $processes) {
    Write-Result '  [ ! ] No javaw.exe / java.exe process found.' Yellow
    if (-not $SkipModules) {
        Write-Result '      -> loaded-DLL check ( TEMP/Downloads injection suspect ), javaagent flags,' Yellow
        Write-Result '         parent process and launch profile only run on LIVE processes:' Yellow
        Write-Result '         START THE GAME ( suspect client ), keep it running, then scan again.' Yellow
    }
}
else {
    $processLabel = if ($processes.Count -eq 1) { 'process' } else { 'processes' }
    Write-Result "  ( $($processes.Count) running Java $processLabel )" Gray
    Write-Result ''
    foreach ($proc in $processes) { Show-ProcessReport -Process $proc }
}

if (-not $SkipMods) { Show-ModsInventory }

# --- Optional full string dump of a jar (manual analysis) --------------
if ($DumpStrings) {
    Write-Result ''
    Write-Result '[ 04 ] ============================ STRING DUMP ( manual analysis ) ===========================' Green
    try {
        $jarFull = (Resolve-Path -LiteralPath $DumpStrings).Path
        if (Test-Path -LiteralPath $jarFull -PathType Container) {
            Write-Result "  [ ! ] DumpStrings expects a JAR file, not a folder: $jarFull" Red
        }
        else {
            $outPath = Join-Path $env:TEMP (([IO.Path]::GetFileNameWithoutExtension($jarFull)) + '.strings.txt')
            $d = Export-JarStrings -JarPath $jarFull -OutPath $outPath
            Write-Result "  [ OK ] dumped $($d.Strings) readable string(s) from $($d.Entries) entrie(s):" Green
            Write-Result "     source  : $($d.Path -replace '\.strings\.txt$', '')" Gray
            Write-Result "     output  : [ $($d.Path) ]" Green
            Write-Result '     ( strings may contain GUI labels, module names, URLs, tokens - review by hand )' DarkGray
        }
    }
    catch {
        Write-Result "  [ ! ] String dump failed: $($_.Exception.Message)" Red
    }
}

# --- Verdict -----------------------------------------------------------
Write-Result ''
Write-Result '[ ========================================================================== ]' Green
Write-Result '   [ 05 ]  RISK SUMMARY' Green
Write-Result "   [ CRITICAL ] $($script:Critical)     [ WARNING ] $($script:WarningCount)     [ INFO ] $($script:InfoCount)     ( relevant flags: $($script:TotalRelevant) )" Gray
Write-Result ''
if ($script:Critical -ge 1) {
    Write-Result "   [ VERDICT ]  SUSPICIOUS ( $($script:Critical) critical finding(s) ) - manual verification required" Red
}
elseif ($script:WarningCount -ge 1) {
    Write-Result "   [ VERDICT ]  REVIEW ( $($script:WarningCount) unusual finding(s) ) - check them by hand" Yellow
}
else {
    Write-Result '   [ VERDICT ]  CLEAN ( no suspicious JVM flags detected )' Green
}
Write-Result '[ ========================================================================== ]' Green
Save-Report
