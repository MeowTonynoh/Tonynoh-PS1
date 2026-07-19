$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$tools = @{
    "1" = @{ Name = "MeowDoomsdayFucker";  Repo = "MeowTonynoh/MeowDoomsdayFucker"; Tag = "V.1.3" }
    "2" = @{ Name = "MeowResolver";        Repo = "MeowTonynoh/MeowResolver";       Tag = "MeowResolver" }
    "3" = @{ Name = "MeowNovowareFucker";  Repo = "MeowTonynoh/MeowNovowareFucker"; Tag = "V2" }
    "4" = @{ Name = "MeowClientFucker";    Repo = "MeowTonynoh/MeowClientFucker";   Tag = "v1.0" }
    "5" = @{ Name = "MeowImportsChecker";  Repo = "MeowTonynoh/MeowImportsChecker"; Tag = "MeowImportsChecker" }
}

$outDir = Join-Path $env:USERPROFILE "Desktop\MeowTools"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

function Write-Centered {
    param([string]$Text, [string]$Color = "White")
    $width = $Host.UI.RawUI.WindowSize.Width
    if (-not $width -or $width -le 0) { $width = 80 }
    $pad = [Math]::Max(0, [Math]::Floor(($width - $Text.Length) / 2))
    Write-Host ((" " * $pad) + $Text) -ForegroundColor $Color
}

function Download-AllParallel {
    $jobs = @()
    $total = $tools.Count

    foreach ($key in ($tools.Keys | Sort-Object)) {
        $t = $tools[$key]
        $job = Start-Job -ScriptBlock {
            param($Name, $Repo, $Tag, $OutDir)

            $ProgressPreference = "SilentlyContinue"
            $apiUrl = "https://api.github.com/repos/$Repo/releases/tags/$Tag"

            try {
                $release = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "MeowDownloader" }
            } catch {
                return "[!] Release '$Tag' not found, skipped."
            }

            if (-not $release.assets -or $release.assets.Count -eq 0) {
                return "[!] No assets, skipped."
            }

            $toolDir = Join-Path $OutDir $Name
            if (-not (Test-Path $toolDir)) { New-Item -ItemType Directory -Path $toolDir | Out-Null }

            foreach ($asset in $release.assets) {
                $destPath = Join-Path $toolDir $asset.name
                Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $destPath -Headers @{ "User-Agent" = "MeowDownloader" }
            }

            return "[OK]"
        } -ArgumentList $t.Name, $t.Repo, $t.Tag, $outDir

        $job | Add-Member -NotePropertyName ToolName -NotePropertyValue $t.Name
        $jobs += $job
    }

    $spinner = @("|", "/", "-", "\")
    $frameIndex = 0
    $done = 0
    $reported = @{}
    $log = @()

    while ($done -lt $total) {
        $spin = $spinner[$frameIndex % $spinner.Length]
        $frameIndex++

        $finishedJobs = $jobs | Where-Object { $_.State -ne "Running" -and -not $reported.ContainsKey($_.Id) }

        foreach ($fj in $finishedJobs) {
            $result = Receive-Job -Job $fj
            $done++
            $reported[$fj.Id] = $true
            $log += @{ Name = $fj.ToolName; Result = $result }
        }

        Write-Host "`r[$spin] Downloading tools: $done / $total" -ForegroundColor Yellow -NoNewline
        if ($done -lt $total) { Start-Sleep -Milliseconds 150 }
    }

    Write-Host "`r$(' ' * 60)`r" -NoNewline

    foreach ($entry in $log) {
        $color = if ($entry.Result -like "[!]*") { "Red" } else { "Magenta" }
        Write-Host ("> {0, -25}" -f $entry.Name) -ForegroundColor $color -NoNewline
        Write-Host "$($entry.Result)" -ForegroundColor White
    }

    Write-Host ""
    Write-Centered -Text "All tools saved in: $outDir" -Color Cyan

    $jobs | Remove-Job
}

function Download-LatestRelease {
    param([string]$Name, [string]$Repo, [string]$Tag)

    Write-Host "[*] Fetching release '$Tag' for $Name..." -ForegroundColor Yellow
    $apiUrl = "https://api.github.com/repos/$Repo/releases/tags/$Tag"

    try {
        $release = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "MeowDownloader" }
    } catch {
        Write-Host "[!] Release '$Tag' not found for $Name (or API error), skipping." -ForegroundColor Red
        return
    }

    if (-not $release.assets -or $release.assets.Count -eq 0) {
        Write-Host "[!] $Name has no assets attached to its release, skipping." -ForegroundColor Red
        return
    }

    $toolDir = Join-Path $outDir $Name
    if (-not (Test-Path $toolDir)) { New-Item -ItemType Directory -Path $toolDir | Out-Null }

    foreach ($asset in $release.assets) {
        $destPath = Join-Path $toolDir $asset.name
        Write-Host "[+] Downloading $($asset.name)..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $destPath -Headers @{ "User-Agent" = "MeowDownloader" }
    }

    Write-Host "[OK] $Name downloaded" -ForegroundColor Magenta
    Write-Host ""
    Write-Centered -Text "Saved in: $toolDir" -Color Cyan
}

function Run-MeowModAnalyzer {
    Write-Host "[*] Launching MeowModAnalyzer..." -ForegroundColor Yellow
    Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/MeowTonynoh/MeowModAnalyzer/main/MeowModAnalyzer.ps1')
}

function Show-Menu {
    Clear-Host
    Write-Centered -Text "MeowTonynoh Tool Downloader" -Color Magenta
    Write-Host ""
    foreach ($key in ($tools.Keys | Sort-Object)) {
        Write-Host "  $key. Download $($tools[$key].Name)" -ForegroundColor White
    }
    Write-Host "  6. Download ALL tools" -ForegroundColor Cyan
    Write-Host "  7. Run MeowModAnalyzer (direct script)" -ForegroundColor Cyan
    Write-Host "  0. Exit" -ForegroundColor DarkGray
    Write-Host ""
}

do {
    Show-Menu
    $choice = Read-Host "Select an option"

    switch ($choice) {
        "6" {
            Download-AllParallel
        }
        "7" {
            Run-MeowModAnalyzer
        }
        "0" {
            Write-Host "Exiting." -ForegroundColor DarkGray
        }
        default {
            if ($tools.ContainsKey($choice)) {
                Download-LatestRelease -Name $tools[$choice].Name -Repo $tools[$choice].Repo -Tag $tools[$choice].Tag
            } else {
                Write-Host "[!] Invalid option." -ForegroundColor Red
            }
        }
    }

    if ($choice -ne "0") {
        Write-Host ""
        Read-Host "Press ENTER to return to the menu"
    }

} while ($choice -ne "0")
