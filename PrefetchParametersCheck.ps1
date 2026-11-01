$Tolerance = 15
$KeyPath   = "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
$FullKey   = "HKEY_LOCAL_MACHINE\$KeyPath"

function Initialize-RegistryApi {
    if ([System.Management.Automation.PSTypeName]'RegistryTime'.Type) { return }

    Add-Type @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public class RegistryTime
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern int RegOpenKeyEx(IntPtr hKey, string subKey, int options, int sam, out IntPtr result);

    [DllImport("advapi32.dll")]
    static extern int RegQueryInfoKey(IntPtr hKey, IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j, out long lastWrite);

    [DllImport("advapi32.dll")]
    static extern int RegCloseKey(IntPtr hKey);

    public static DateTime GetLastWrite(string subKey)
    {
        IntPtr handle;
        int status = RegOpenKeyEx(new IntPtr(unchecked((int)0x80000002)), subKey, 0, 0x20019, out handle);
        if (status != 0) throw new Win32Exception(status);

        long fileTime;
        RegQueryInfoKey(handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out fileTime);
        RegCloseKey(handle);

        return DateTime.FromFileTime(fileTime);
    }
}
"@
}

function Get-BootTime {
    (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
}

function Get-KeyLastWrite {
    param([string]$Path)
    [RegistryTime]::GetLastWrite($Path)
}

function Format-Duration {
    param([double]$TotalSeconds)

    $span  = [TimeSpan]::FromSeconds([math]::Round($TotalSeconds))
    $parts = @()

    if ($span.Days    -gt 0) { $parts += "{0} {1}" -f $span.Days,    $(if ($span.Days    -eq 1) { "day"    } else { "days"    }) }
    if ($span.Hours   -gt 0) { $parts += "{0} {1}" -f $span.Hours,   $(if ($span.Hours   -eq 1) { "hour"   } else { "hours"   }) }
    if ($span.Minutes -gt 0) { $parts += "{0} {1}" -f $span.Minutes, $(if ($span.Minutes -eq 1) { "minute" } else { "minutes" }) }
    if ($span.Seconds -gt 0 -or $parts.Count -eq 0) { $parts += "{0} {1}" -f $span.Seconds, $(if ($span.Seconds -eq 1) { "second" } else { "seconds" }) }

    $parts -join " "
}

function Write-Field {
    param(
        [string]$Label,
        [string]$Value,
        [ConsoleColor]$Color      = [ConsoleColor]::White,
        [ConsoleColor]$LabelColor = [ConsoleColor]::DarkGray
    )
    Write-Host ("{0,-19}" -f $Label) -NoNewline -ForegroundColor $LabelColor
    Write-Host ": " -NoNewline -ForegroundColor DarkGray
    Write-Host $Value -ForegroundColor $Color
}

function Show-Report {
    param(
        [string]$Key,
        [datetime]$Boot,
        [datetime]$LastWrite,
        [double]$Difference,
        [bool]$Modified
    )

    $format = "dd/MM/yyyy HH:mm:ss"

    Write-Field "Registry Key"   $Key
    Write-Host ""
    Write-Field "Boot Time"      $Boot.ToString($format)
    Write-Field "Key Last Write" $LastWrite.ToString($format)
    Write-Field "Difference"     (Format-Duration $Difference)
    Write-Host ""

    if ($Modified) {
        Write-Field "PrefetchParameters" "Modified after boot" Red -LabelColor Yellow
    }
    else {
        Write-Field "PrefetchParameters" "Not modified" Green -LabelColor Yellow
    }
}

Clear-Host
Write-Host ""
Write-Host "Made by Tonynoh - discord.gg/meowtools" -ForegroundColor Cyan
Write-Host ""

try {
    Initialize-RegistryApi
    $boot      = Get-BootTime
    $lastWrite = Get-KeyLastWrite -Path $KeyPath
}
catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    return
}

$difference = [math]::Abs(($lastWrite - $boot).TotalSeconds)
$modified   = $difference -gt $Tolerance

Show-Report -Key $FullKey -Boot $boot -LastWrite $lastWrite -Difference $difference -Modified $modified
Write-Host ""
