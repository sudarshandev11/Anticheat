<#
.SYNOPSIS
    Checks for suspicious DLLs loaded into a target process.

.DESCRIPTION
    This script scans the loaded modules (DLLs) of a target process (default: msiexec.exe),
    compares them against a list of safe Windows directories, and flags any that are outside these paths.

.PARAMETER ProcessName
    Name of the target process (default: msiexec).

.EXAMPLE
    .\check_injected_dlls.ps1 -ProcessName msiexec

    Scans msiexec for suspicious DLLs.
#>

param(
    [string]$ProcessName = "msiexec"
)

# Get the process object
$proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue

if (-not $proc) {
    Write-Host "❌ Process '$ProcessName' not found." -ForegroundColor Red
    exit
}

Write-Host "🔍 Checking loaded DLLs for process ID $($proc.Id) - $ProcessName" -ForegroundColor Cyan

# Known safe DLL paths
$safePaths = @(
    "$env:windir\System32",
    "$env:windir\SysWOW64",
    "$env:windir\WinSxS"
)

# Collect results
$result = @()

foreach ($module in $proc.Modules) {
    $path = $module.FileName
    $isSafe = $false

    foreach ($safe in $safePaths) {
        if ($path -like "$safe*") {
            $isSafe = $true
            break
        }
    }

    $status = if ($isSafe) { "OK" } else { "Suspicious" }

    $result += [PSCustomObject]@{
        DLLName = $module.ModuleName
        FilePath = $path
        Status = $status
    }
}

# Output as table
$result | Sort-Object Status, DLLName | Format-Table -AutoSize
