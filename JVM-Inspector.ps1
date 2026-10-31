<#
.SYNOPSIS
    JVM Inspector v2 - Minecraft Screenshare Forensics
.DESCRIPTION
    Improved fork of the original JVM Inspector by Tonynoh (discord.gg/ssa).

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
    [switch]$Hash
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
            if ($Arg -match '(?i)false') { return (New-Severity 'Info' 'JVM self-attach disabled (OK)') }
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
            $info.Label    = 'inside known launcher folder (OK)'
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
    $knownParents = @(
        'explorer.exe', 'powershell.exe', 'pwsh.exe', 'cmd.exe', 'windowsterminal.exe',
        'openconsole.exe', 'conhost.exe', 'modrinth app.exe', 'curseforge.exe',
        'minecraftlauncher.exe', 'minecraft.exe', 'prismlauncher.exe', 'multimc.exe',
        'atlauncher.exe', 'gdlauncher.exe', 'javaw.exe', 'java.exe', 'techniclauncher.exe',
        'serverlauncher.exe', 'steam.exe'
    )
    if ($info.Name -and ($knownParents -contains $info.Name.ToLowerInvariant())) { $info.IsKnown = $true }
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
        Write-Result '  Loaded DLLs: cannot read (try running as Administrator)' DarkYellow
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
        Write-Result "  TEMP-extracted natives from KNOWN components (normal): $($knownTemp.Count)" DarkCyan
        foreach ($k in $knownTemp) { Write-Result "      $($k.Path)  <- $($k.Label)" DarkGray }
    }
    if ($tempHits.Count -gt 0) {
        $script:Critical++
        Write-Result "  [!] $($tempHits.Count) UNKNOWN DLL(s) loaded from TEMP/Downloads - INJECTION SUSPECT:" Red
        foreach ($t in $tempHits) {
            $sig = 'UnknownError'
            try { $sig = (Get-AuthenticodeSignature -LiteralPath $t -ErrorAction Stop).Status.ToString() } catch { }
            Write-Result "      $t  [$sig]" Red
        }
    }
    if ($extHits.Count -gt 0) {
        Write-Result "  Loaded DLLs outside Java/Windows/launcher folders: $($extHits.Count) (overlays, vendors - verify)" DarkCyan
        $shown    = 0
        $unsigned = 0
        foreach ($e in $extHits) {
            if ($shown -ge 20) { Write-Result "      ... +$($extHits.Count - $shown) more" DarkGray; break }
            $sig = 'UnknownError'
            try { $sig = (Get-AuthenticodeSignature -LiteralPath $e -ErrorAction Stop).Status.ToString() } catch { }
            if ($sig -eq 'Valid') {
                Write-Result "      $e  [signed]" DarkGray
            }
            else {
                $unsigned++
                Write-Result "      $e  [$sig - NOT VALIDLY SIGNED]" Yellow
            }
            $shown++
        }
        if ($unsigned -gt 0) {
            $script:WarningCount++
            Write-Result "  [REVIEW] $unsigned unsigned/untrusted external DLL(s) loaded in the JVM process" Yellow
        }
    }
}

# ----------------------------------------------------------------------
# Environment persistence check
# ----------------------------------------------------------------------
function Show-EnvFlags {
    Write-Result '--- MACHINE-WIDE JVM VECTORS (affect every Java process) ---' Cyan
    Write-Result 'Environment variables:' DarkGray
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
                Write-Result "  [CRITICAL] $name ($scope) = $vShow" Red
                Write-Result '             persistent agent/classpath injection vector - not normal' Red
            }
            else {
                $script:WarningCount++
                Write-Result "  [REVIEW]   $name ($scope) = $vShow" Yellow
            }
        }
    }
    if (-not $any) { Write-Result '  none set (OK)' DarkGray }
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
    Write-Result "  [REVIEW] JVM attach/diagnostic tool(s) running: $names" Yellow
    Write-Result '             these can inject agents into a LIVE JVM - check what they are attached to' Yellow
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
        Write-Result "  [$lvl] Startup entry: $($e.Name)  @ $($e.Location)" (Get-LevelColor $lvl)
        Write-Result "         $cShow" DarkGray
    }
    if ($flagged -eq 0) {
        Write-Result 'Startup persistence: no Java/agent-related auto-start entries (OK)' DarkGray
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

function Show-ModsInventory {
    Write-Result ''
    Write-Result '--- MODS INVENTORY (known launcher instances) ---' Cyan
    $dirs = Get-ModsDirectories
    if ($dirs.Count -eq 0) {
        Write-Result 'No known launcher mods folders found. Use -ModsPath "C:\path\to\mods" to check one manually.' DarkYellow
        return
    }
    foreach ($d in $dirs) {
        $jars = @(Get-ChildItem -LiteralPath $d -Filter '*.jar' -File -ErrorAction SilentlyContinue | Sort-Object Name)
        Write-Result ''
        Write-Result "  $d  ($($jars.Count) jars)" DarkGray
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
            $hashTxt = ''
            if ($Hash) {
                try {
                    $h = (Get-FileHash -LiteralPath $jar.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                    $hashTxt = '  sha256:' + $h.Substring(0, 12)
                }
                catch { $hashTxt = '  sha256:<unreadable>' }
            }
            $line = '      {0}  ({1} KB, {2:yyyy-MM-dd}){3}' -f $jar.Name, [int]($jar.Length / 1KB), $jar.LastWriteTime, $hashTxt
            if ($kw) {
                $script:WarningCount++
                Write-Result ('[!] ' + $line.TrimStart()) Yellow
                Write-Result "          keyword '$kw' matched - open and verify this jar" Yellow
            }
            elseif ($isDisguised) {
                $script:WarningCount++
                Write-Result ('[!] ' + $line.TrimStart()) Yellow
                Write-Result '          jar disguised as a system/process file name - verify this jar' Yellow
            }
            else {
                Write-Result $line DarkGray
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
    Write-Result "PID $($Process.ProcessId) ($($Process.Name))" DarkGray

    $cmd = $Process.CommandLine
    if (-not $cmd) {
        Write-Result '  CommandLine not accessible (run PowerShell as admin).' DarkYellow
        Write-Result ''
        return
    }

    $profile = Get-LaunchProfile -CommandLine $cmd
    if ($profile) { Write-Result "  Launch profile: $profile" DarkGray }

    $parent = Get-ParentInfo -Process $Process
    if ($parent.Suspicious) {
        $script:Critical++
        Write-Result "  [CRITICAL] Parent process: $($parent.Name) (PID $($parent.Pid)) launched FROM TEMP/DOWNLOADS - injection suspect" Red
    }
    elseif ($parent.IsKnown) {
        Write-Result "  Parent: $($parent.Name) (known launcher/console - OK)" DarkGray
    }
    elseif ($parent.Note) {
        Write-Result "  Parent: $($parent.Note)" DarkGray
    }
    else {
        Write-Result "  Parent: $($parent.Name) (PID $($parent.Pid)) - unknown parent, verify" DarkYellow
    }

    $tokens      = Get-JvmArgTokens -CommandLine $cmd
    $relevant    = @(Get-RelevantArgs -ArgList $tokens)
    $nativeDir   = ''
    $argKeyword  = $false

    if ($relevant.Count -eq 0) {
        Write-Result '  No relevant arguments found.' DarkGray
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
                $details.Add(@{ Text = "     -> KNOWN LEGITIMATE AGENT: $($agent.KnownName)"; Color = 'Green' })
            }
            else {
                $sev = New-Severity 'Critical' 'UNKNOWN java agent - manual verification required'
                if ($agent.Premain) { $details.Add(@{ Text = "     -> Premain-Class: $($agent.Premain)"; Color = 'Yellow' }) }
                if ($agent.Packages.Count) { $details.Add(@{ Text = '     -> packages: ' + ($agent.Packages -join ', '); Color = 'Yellow' }) }
                if ($agent.Error) { $details.Add(@{ Text = "     -> $($agent.Error)"; Color = 'Red' }) }
                $details.Add(@{ Text = '     -> NOT a known launcher agent: open the jar and verify its origin'; Color = 'Red' })
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
            $details.Add(@{ Text = "     -> [!] keyword '$kw' matched - verify manually (keyword is NOT proof)"; Color = 'Yellow' })
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
            Write-Result "  [!] Keyword '$cmdKw' found in the full command line (classpath/main args) - open and verify" Yellow
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
        Write-Result "Report saved: $path" Green
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
    [void]$sb.AppendLine('<title>JVM Inspector v2 - Screenshare Report</title>')
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine('body{background:#0d1117;color:#c9d1d9;padding:24px;margin:0}')
    [void]$sb.AppendLine('h1{color:#58a6ff;font:600 20px Segoe UI,sans-serif;margin:0 0 4px}')
    [void]$sb.AppendLine('.meta{color:#6e7681;font:13px Segoe UI,sans-serif;margin-bottom:18px}')
    [void]$sb.AppendLine('pre{white-space:pre-wrap;font:13px Consolas,"Courier New",monospace;margin:0}')
    [void]$sb.AppendLine('.crit{color:#ff5555;font-weight:700}.warn{color:#ffd166}.warn2{color:#b28500}')
    [void]$sb.AppendLine('.info{color:#4dd2ff}.ok{color:#55ff99}.muted{color:#6e7681}')
    [void]$sb.AppendLine('.hdr{color:#58a6ff;font-weight:700}.txt{color:#c9d1d9}')
    [void]$sb.AppendLine('</style></head><body>')
    [void]$sb.AppendLine('<h1>JVM Inspector v2 - Minecraft Screenshare Forensics</h1>')
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
Write-Result 'JVM Inspector v2 - Minecraft Screenshare Forensics' Cyan
Write-Result 'Original by Tonynoh - discord.gg/ssa | Fork & improvements by ItzMeow80' DarkCyan
Write-Result ''
if (Test-IsAdmin) {
    Write-Result 'Elevation: Administrator (full access)' DarkGray
}
else {
    Write-Result 'Elevation: NOT admin - run as Administrator for DLL & parent checks' DarkYellow
}
Write-Result ''

Show-EnvFlags

$processes = @(Get-CimInstance Win32_Process -Filter "name = 'javaw.exe' OR name = 'java.exe'")
if (-not $processes) {
    Write-Result 'No javaw.exe / java.exe process found.' Yellow
}
else {
    $processLabel = if ($processes.Count -eq 1) { 'process' } else { 'processes' }
    Write-Result "Found $($processes.Count) running Java $processLabel." Gray
    Write-Result ''
    foreach ($proc in $processes) { Show-ProcessReport -Process $proc }
}

if (-not $SkipMods) { Show-ModsInventory }

# --- Verdict -----------------------------------------------------------
Write-Result ''
Write-Result '================ RISK SUMMARY ================' Cyan
Write-Result "Critical: $($script:Critical)   Warnings: $($script:WarningCount)   Info: $($script:InfoCount)   Relevant flags: $($script:TotalRelevant)" Gray
if ($script:Critical -ge 1) {
    Write-Result "VERDICT: SUSPICIOUS - $($script:Critical) critical finding(s), manual verification required" Red
}
elseif ($script:WarningCount -ge 1) {
    Write-Result "VERDICT: REVIEW - $($script:WarningCount) unusual finding(s), check them by hand" Yellow
}
else {
    Write-Result 'VERDICT: CLEAN - no suspicious JVM flags detected' Green
}
Save-Report
