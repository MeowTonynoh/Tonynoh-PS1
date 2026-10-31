# Test harness #2 - known-agent branch + path category classification.
# Run: powershell -ExecutionPolicy Bypass -File .\tests\test-jvm-inspector2.ps1
$ErrorActionPreference = 'Stop'
$repoRoot   = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $repoRoot 'JVM-Inspector.ps1'
$src = Get-Content -LiteralPath $scriptPath -Raw
$m = [regex]::Match($src, '(?m)^# Main\s*$')
if (-not $m.Success) { throw 'main marker not found' }
Invoke-Expression $src.Substring(0, $m.Index)

# --- build a jar that pretends to be the legit Modrinth "Theseus" agent ---
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$jar = Join-Path $env:TEMP 'jvm-inspector-test-theseus.jar'
if (Test-Path $jar) { Remove-Item $jar -Force }
$zip = [System.IO.Compression.ZipFile]::Open($jar, [System.IO.Compression.ZipArchiveMode]::Create)
$e = $zip.CreateEntry('META-INF/MANIFEST.MF')
$sw = New-Object System.IO.StreamWriter($e.Open())
$sw.Write("Manifest-Version: 1.0`r`nPremain-Class: com.modrinth.theseus.agent.TheseusAgent`r`n")
$sw.Close()
$e2 = $zip.CreateEntry('com/modrinth/theseus/agent/TheseusAgent.class')
$sw2 = New-Object System.IO.StreamWriter($e2.Open()); $sw2.Write('x'); $sw2.Close()
$e3 = $zip.CreateEntry('com/modrinth/theseus/rpc/RpcHandlers.class')
$sw3 = New-Object System.IO.StreamWriter($e3.Open()); $sw3.Write('x'); $sw3.Close()
$zip.Dispose()

$fake = [pscustomobject]@{
    ProcessId       = 999003
    Name            = 'javaw.exe'
    ParentProcessId = 999999
    ExecutablePath  = 'C:\Java\bin\javaw.exe'
    CommandLine     = '"C:\Java\bin\javaw.exe" -javaagent:"' + $jar + '" -Dfabric.gameJarPath=' +
        (Join-Path $env:USERPROFILE 'Desktop\somejar.jar') + ' -cp x.jar Main'
}
Write-Host '===== CASE 3: known Modrinth agent =====' -ForegroundColor Magenta
Show-ProcessReport -Process $fake

Write-Host '===== path categories =====' -ForegroundColor Magenta
foreach ($p in @((Join-Path $env:USERPROFILE 'Downloads'), (Join-Path $env:USERPROFILE 'Desktop'),
        (Join-Path $env:TEMP '.'), 'C:\nope\nada')) {
    $pi = Get-PathInfo -RawPath $p
    '{0,-45} -> {1} / {2}' -f $p, $pi.Category, $pi.Severity
}
Write-Host "totals: Critical=$script:Critical Warning=$script:WarningCount Info=$script:InfoCount"
Write-Host 'Expected: known agent = OK/green, gameJarPath missing = Critical, categories: Downloads/Critical, Desktop/Warning, Temp/Warning, Missing/Critical'
