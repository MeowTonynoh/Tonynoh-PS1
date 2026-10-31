# Test harness #3 - machine-wide vector checks (mocked) + HTML report smoke test.
# Run: powershell -ExecutionPolicy Bypass -File .\tests\test-jvm-inspector3.ps1
$ErrorActionPreference = 'Stop'
$repoRoot   = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $repoRoot 'JVM-Inspector.ps1'
$src = Get-Content -LiteralPath $scriptPath -Raw
$m = [regex]::Match($src, '(?m)^# Main\s*$')
if (-not $m.Success) { throw 'main marker not found' }
Invoke-Expression $src.Substring(0, $m.Index)

# --- mocks (functions shadow cmdlets inside this session) ---
function Get-CimInstance {
    param($ClassName, $Filter, $ErrorAction)
    if ($ClassName -eq 'Win32_StartupCommand') {
        return @(
            [pscustomobject]@{ Name = 'Updater';    Command = 'C:\Program Files\App\app.exe';              Location = 'HKCU Run' }
            [pscustomobject]@{ Name = 'JavaHelper'; Command = 'javaw.exe -javaagent:C:\Users\x\agent.jar'; Location = 'HKCU Run' }
            [pscustomobject]@{ Name = 'Loader';     Command = 'powershell -w hidden C:\Users\x\ld.bat';    Location = 'Startup folder' }
        )
    }
    return $null
}
function Get-Process {
    param($Name, $ErrorAction)
    if ($Name -eq 'jcmd') { return [pscustomobject]@{ ProcessName = 'jcmd' } }
    return $null
}

Write-Host '===== new machine-wide vector checks (mocked) =====' -ForegroundColor Magenta
Show-EnvFlags

Write-Host '===== verdict counters =====' -ForegroundColor Magenta
Write-Host "Critical=$script:Critical Warning=$script:WarningCount Info=$script:InfoCount"
Write-Host 'Expected: Critical=1 (javaagent run key), Warning=1 (jcmd), the non-Java "Loader" entry must be IGNORED'

# --- html conversion smoke test ---
Write-Host '===== html conversion smoke test =====' -ForegroundColor Magenta
$html = ConvertTo-HtmlReport
"html length: $($html.Length)"
if ($html -notmatch 'MACHINE-WIDE JVM VECTORS') { throw 'html missing content' }
if ($html -notmatch '<span class="crit">')      { throw 'html missing critical class' }
'html content + classes OK'
