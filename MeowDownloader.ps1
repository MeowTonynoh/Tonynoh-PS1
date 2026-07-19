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
    param([string]$Text, [int]$Width = 0)
    if ($Width -le 0) {
        $Width = $Host.UI.RawUI.WindowSize.Width
        if (-not $Width -or $Width -le 0) { $Width = 80 }
    }
    $pad = [Math]::Max(0, [Math]::Floor(($Width - $Text.Length) / 2))
    Write-Host ((" " * $pad) + $Text)
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
                return "[!] $Name : release '$Tag' not found, skipped."
            }

            if (-not $release.assets -or $release.assets.Count -eq 0) {
                return "[!] $Name : no assets, skipped."
            }

            $toolDir = Join-Path $OutDir $Name
            if (-not (Test-Path $toolDir)) { New-Item -ItemType Directory -Path $toolDir | Out-Null }

            foreach ($asset in $release.assets) {
                $destPath = Join-Path $toolDir $asset.name
                Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $destPath -Headers @{ "User-Agent" = "MeowDownloader" }
            }

            return "[OK] $Name downloaded"
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
        $color = if ($entry.Result -like "[!]*") { "DarkYellow" } else { "Green" }
        Write-Host ("> {0, -25}" -f $entry.Name) -ForegroundColor $color -NoNewline
        Write-Host "$($entry.Result)" -ForegroundColor Gray
    }

    $blockWidth = ($log | ForEach-Object { ("> {0, -25}{1}" -f $_.Name, $_.Result).Length } | Measure-Object -Maximum).Maximum
    Write-Host ""
    Write-Centered "Tools saved in: $outDir" -Width $blockWidth

    $jobs | Remove-Job
}

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

    $okLine = "[OK] $Name downloaded"
    Write-Host $okLine -ForegroundColor Green
    Write-Host ""
    Write-Centered "Saved in: $toolDir" -Width $okLine.Length
}

function Run-MeowModAnalyzer {
    Write-Host "[*] Launching MeowModAnalyzer..." -ForegroundColor Cyan
    Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/MeowTonynoh/MeowModAnalyzer/main/MeowModAnalyzer.ps1')
}

function Show-Menu {
    Clear-Host
    Write-Centered "MeowTonynoh Tool Downloader"
    Write-Host ""
    foreach ($key in ($tools.Keys | Sort-Object)) {
        Write-Host "  $key. Download $($tools[$key].Name)"
    }
    Write-Host "  6. Download ALL tools"
    Write-Host "  7. Run MeowModAnalyzer (direct script)"
    Write-Host "  0. Exit"
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
