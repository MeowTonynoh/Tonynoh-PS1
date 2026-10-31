# Test harness #1 for JVM Inspector - loads functions only (skips main) and
# runs them against fake process command lines + a fake malicious agent jar.
# Run: powershell -ExecutionPolicy Bypass -File .\tests\test-jvm-inspector.ps1
$ErrorActionPreference = 'Stop'

$repoRoot   = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $repoRoot 'JVM-Inspector.ps1'
$src = Get-Content -LiteralPath $scriptPath -Raw
$m = [regex]::Match($src, '(?m)^# Main\s*$')
if (-not $m.Success) { throw 'main marker not found' }
$prefix = $src.Substring(0, $m.Index)
Invoke-Expression $prefix

# --- build a fake "cheat" agent jar ---
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$evil = Join-Path $env:TEMP 'jvm-inspector-test-evil-agent.jar'
if (Test-Path $evil) { Remove-Item $evil -Force }
$zip = [System.IO.Compression.ZipFile]::Open($evil, [System.IO.Compression.ZipArchiveMode]::Create)
$e = $zip.CreateEntry('META-INF/MANIFEST.MF')
$sw = New-Object System.IO.StreamWriter($e.Open())
$sw.Write("Manifest-Version: 1.0`r`nPremain-Class: com.badclient.inject.Agent`r`n")
$sw.Close()
$e2 = $zip.CreateEntry('com/badclient/inject/Agent.class')
$sw2 = New-Object System.IO.StreamWriter($e2.Open())
$sw2.Write('CAFEBABE-not-really')
$sw2.Close()
$zip.Dispose()

# These may or may not exist on the test machine - both branches are valid output
$theseus = Join-Path $env:LOCALAPPDATA 'Temp\.tmpAf6QQ5\theseus.jar'
$missing = Join-Path $env:USERPROFILE 'Downloads\not-there.jar'

# --- CASE 1: realistic Modrinth launch + suspicious extras ---
$fake1 = [pscustomobject]@{
    ProcessId       = 999001
    Name            = 'javaw.exe'
    ParentProcessId = 12345
    ExecutablePath  = 'C:\Program Files\Eclipse Adoptium\jdk-21\bin\javaw.exe'
    CommandLine     = '"C:\Program Files\Eclipse Adoptium\jdk-21\bin\javaw.exe" -Djava.library.path=' +
        "$env:APPDATA\ModrinthApp\meta\natives\1.21.11-0.19.5" +
        ' -Djdk.attach.allowAttachSelf=true -javaagent:"' + $theseus + '" -Dfabric.addMods=' + $evil +
        ' -cp fabric-loader.jar net.fabricmc.loader.impl.launch.knot.KnotClient'
}

# --- CASE 2: unknown agent, missing path, cheat keyword ---
$fake2 = [pscustomobject]@{
    ProcessId       = 999002
    Name            = 'java.exe'
    ParentProcessId = 999999
    ExecutablePath  = 'C:\Java\bin\java.exe'
    CommandLine     = '"C:\Java\bin\java.exe" -javaagent:"' + $evil + '" -Dfabric.gameJarPath=' + $missing +
        ' -Djdk.attach.allowAttachSelf=false -cp x.jar com.example.Main wurst-client'
}

Write-Host ''
Write-Host '===== CASE 1: Modrinth launch + suspicious extras =====' -ForegroundColor Magenta
Show-ProcessReport -Process $fake1
Write-Host '===== CASE 2: unknown agent + missing path + keyword =====' -ForegroundColor Magenta
Show-ProcessReport -Process $fake2
Write-Host '===== totals =====' -ForegroundColor Magenta
Write-Host "Critical=$script:Critical Warning=$script:WarningCount Info=$script:InfoCount Relevant=$script:TotalRelevant"
Write-Host 'Expected: Critical>=2 (self-attach + missing path), Warning>=2 (addMods + keyword), launch profile = Fabric'
