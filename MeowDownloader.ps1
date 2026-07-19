# MeowDownloader.ps1
# Downloader for MeowTonynoh tools - fetches latest GitHub releases

$ErrorActionPreference = "Stop"

$tools = @{
    "1" = @{ Name = "MeowDoomsdayFucker";  Repo = "MeowTonynoh/MeowDoomsdayFucker"; Tag = "V.1.3" }
    "2" = @{ Name = "MeowResolver";        Repo = "MeowTonynoh/MeowResolver";       Tag = "MeowResolver" }
    "3" = @{ Name = "MeowNovowareFucker";  Repo = "MeowTonynoh/MeowNovowareFucker"; Tag = "V2" }
    "4" = @{ Name = "MeowClientFucker";    Repo = "MeowTonynoh/MeowClientFucker";   Tag = "v1.0" }
    "5" = @{ Name = "MeowImportsChecker";  Repo = "MeowTonynoh/MeowImportsChecker"; Tag = "MeowImportsChecker" }
}

$outDir = Join-Path $env:USERPROFILE "Desktop\MeowTools"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

function Download-LatestRelease {
    param([string]$Name, [string]$Repo, [string]$Tag)

    Write-Host "[*] Fetching release '$Tag' for $Name..." -ForegroundColor Cyan
    $apiUrl = "https://api.github.com/repos/$Repo/releases/tags/$Tag"

    try {
        $release = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "MeowDownloader" }
    } catch {
        Write-Host "[!] Release '$Tag' not found for $Name (or API error), skipping." -ForegroundColor Yellow
        return
    }

    if (-not $release.assets -or $release.assets.Count -eq 0) {
        Write-Host "[!] $Name has no assets attached to its release, skipping." -ForegroundColor Yellow
        return
    }

    $toolDir = Join-Path $outDir $Name
    if (-not (Test-Path $toolDir)) { New-Item -ItemType Directory -Path $toolDir | Out-Null }

    foreach ($asset in $release.assets) {
        $destPath = Join-Path $toolDir $asset.name
        Write-Host "[+] Downloading $($asset.name)..." -ForegroundColor Green
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $destPath -Headers @{ "User-Agent" = "MeowDownloader" }
    }

    Write-Host "[OK] $Name downloaded to: $toolDir" -ForegroundColor Green
}

function Run-MeowModAnalyzer {
    Write-Host "[*] Launching MeowModAnalyzer..." -ForegroundColor Cyan
    Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/MeowTonynoh/MeowModAnalyzer/main/MeowModAnalyzer.ps1')
}

function Show-Menu {
    Clear-Host
    Write-Host "=============================================="
    Write-Host "           MeowTonynoh Tool Downloader"
    Write-Host "=============================================="
    foreach ($key in ($tools.Keys | Sort-Object)) {
        Write-Host "  $key. Download $($tools[$key].Name)"
    }
    Write-Host "  6. Download ALL tools"
    Write-Host "  7. Run MeowModAnalyzer (direct script)"
    Write-Host "  0. Exit"
    Write-Host "=============================================="
}

do {
    Show-Menu
    $choice = Read-Host "Select an option"

    switch ($choice) {
        "6" {
            foreach ($key in ($tools.Keys | Sort-Object)) {
                Download-LatestRelease -Name $tools[$key].Name -Repo $tools[$key].Repo -Tag $tools[$key].Tag
            }
        }
        "7" {
            Run-MeowModAnalyzer
        }
        "0" {
            Write-Host "Exiting."
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
