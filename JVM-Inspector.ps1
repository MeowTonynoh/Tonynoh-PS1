#  JVM Inspector - Minecraft Screenshare Forensics
#  By Tonynoh - discord.gg/ssa

function Get-RelevantArgs {
    param (
        [string[]]$ArgList
    )
    $relevantPatterns = @(
        "-javaagent*",
        "-Dfabric.addMods*",
        "-Dloader.addMods*",
        "-Dfabric.gameJarPath*",
        "-Dloader.gameJarPath*",
        "-Djava.library.path*",
        "-Djna.boot.library.path*",
        "-Djdk.attach.allowAttachSelf*",
        "--tweakClass*",
        "--launchTarget*"
    )
    $excludedPatterns = @(
        "-cp*",
        "-classpath*"
    )
    return $ArgList | Where-Object {
        $arg = $_
        $isRelevant = $relevantPatterns | Where-Object { $arg -like $_ }
        $isExcluded  = $excludedPatterns  | Where-Object { $arg -like $_ }
        $isRelevant -and -not $isExcluded
    }
}

function Get-ArgColor {
    param ([string]$Arg)
    switch -Wildcard ($Arg) {
        "-javaagent*"                    { return "Red" }
        "-Dfabric.addMods*"              { return "Yellow" }
        "-Dloader.addMods*"              { return "Yellow" }
        "-Dfabric.gameJarPath*"          { return "Yellow" }
        "-Dloader.gameJarPath*"          { return "Yellow" }
        "-Djdk.attach.allowAttachSelf*"  { return "Red" }
        "-Djava.library.path*"           { return "Cyan" }
        "-Djna.boot.library.path*"        { return "Cyan" }
        default                          { return "Gray" }
    }
}

function Show-ProcessArgs {
    param (
        [System.Management.Automation.PSObject]$Process
    )
    $cmd = $Process.CommandLine
    Write-Host "PID $($Process.ProcessId) ($($Process.Name))" -ForegroundColor DarkGray

    if (-not $cmd) {
        Write-Host "  CommandLine not accessible (run PowerShell as admin)." -ForegroundColor DarkYellow
        Write-Host ""
        return 0
    }

    $argList  = $cmd -split ' (?=-)'
    $filtered = Get-RelevantArgs -ArgList $argList
    if ($filtered) {
        foreach ($arg in $filtered) {
            $clean = $arg.Trim()
            $color = Get-ArgColor -Arg $clean
            Write-Host "  $clean" -ForegroundColor $color
        }
    }
    else {
        Write-Host "  No relevant arguments found." -ForegroundColor DarkGray
    }
    Write-Host ""
    return $filtered.Count
}

# --- Main ---
Clear-Host
Write-Host "JVM Inspector" -ForegroundColor Cyan
Write-Host "By Tonynoh - discord.gg/ssa`n" -ForegroundColor DarkCyan

$processes = @(Get-CimInstance Win32_Process -Filter "name = 'javaw.exe' OR name = 'java.exe'")
if (-not $processes) {
    Write-Host "No javaw.exe / java.exe process found." -ForegroundColor Yellow
    return
}

$processLabel = if ($processes.Count -eq 1) { "process" } else { "processes" }
Write-Host "Found $($processes.Count) running Java $processLabel.`n" -ForegroundColor Gray

$totalFlags = 0
foreach ($proc in $processes) {
    $totalFlags += Show-ProcessArgs -Process $proc
}

$flagLabel = if ($totalFlags -eq 1) { "flag" } else { "flags" }
Write-Host "Scan completed, $totalFlags relevant $flagLabel found" -ForegroundColor Cyan
