# anticheat_collector.ps1
<#
  Requires: PowerShell 7+ recommended (works in Windows PowerShell with adjustments)
  Purpose: Collect process/module info, compute hashes, detect emulator indicators,
           and post telemetry to server over HTTPS.
  NOTE: This collects sensitive info. Use only with appropriate legal/consent policies.
#>

param(
    [string]$TelemetryUrl = "https://your-server.example.com/api/telemetry",
    [string]$ApiKey = "<REPLACE_WITH_API_KEY>",
    [int]$MaxModulesPerProcess = 250
)

# --- SAFE LIST (lowercase names without paths) ---
$SafeDlls = @(
    "kernel32.dll","user32.dll","gdi32.dll","advapi32.dll","shell32.dll",
    "ntdll.dll","msvcrt.dll","combase.dll","ucrtbase.dll","rpcrt4.dll",
    "ws2_32.dll","shlwapi.dll"
) | ForEach-Object { $_.ToLower() }

# Helper - compute SHA256 (file might be locked; handle exceptions)
function Get-FileSHA256($path) {
    try {
        $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hash = $sha.ComputeHash($stream)
        $stream.Close()
        return ([BitConverter]::ToString($hash)).Replace("-","").ToLower()
    } catch {
        return $null
    }
}

# Helper - detect emulator artifacts
function Detect-Emulator($proc) {
    $pname = $proc.ProcessName.ToLower()
    $indicators = @()
    if ($pname -match "hd-player|bluestacks|bstbox|nox") { $indicators += "process-name:$($proc.ProcessName)" }
    # Check executable path for emulator paths
    try {
        $exe = $proc.Path
        if ($exe) {
            $exeLower = $exe.ToLower()
            if ($exeLower -like "*bluestacks*") { $indicators += "path:bluestacks" }
            if ($exeLower -like "*nox*") { $indicators += "path:nox" }
        }
    } catch { }
    return $indicators
}

Write-Host "Starting anti-cheat collector at $(Get-Date -Format 'u')" -ForegroundColor Cyan

$procObjs = Get-Process | Sort-Object ProcessName
$report = [System.Collections.Generic.List[object]]::new()

foreach ($p in $procObjs) {
    $entry = @{
        ProcessName = $p.ProcessName
        Id = $p.Id
        UserName = $null
        Path = $null
        Modules = @()
        EmulatorIndicators = @()
    }

    try {
        # get executable path (may throw)
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)"
        if ($proc) {
            $entry.Path = $proc.ExecutablePath
            # Owner
            $owner = $proc.GetOwner()
            $entry.UserName = if ($owner.ReturnValue -eq 0) { "$($owner.Domain)\$($owner.User)" } else { $null }
        }
    } catch { }

    # Detect emulator indicators
    $entry.EmulatorIndicators = Detect-Emulator($p)

    try {
        $modules = (Get-Process -Id $p.Id -ErrorAction Stop).Modules
        $count = 0
        foreach ($m in $modules) {
            if ($count -ge $MaxModulesPerProcess) { break }
            $dllName = [System.IO.Path]::GetFileName($m.FileName) -as [string]
            $dllLower = $dllName.ToLower()
            $isSafe = $SafeDlls -contains $dllLower
            $hash = $null
            if (-not $isSafe) {
                # Try compute hash (skip system folders if necessary)
                $hash = Get-FileSHA256($m.FileName)
            }
            $entry.Modules += @{
                ModuleName = $dllName
                Path = $m.FileName
                IsSafe = $isSafe
                SHA256 = $hash
            }
            $count++
        }
    } catch {
        # Access denied on system processes
    }

    $report.Add($entry)
}

# Build telemetry object
$payload = @{
    Timestamp = (Get-Date).ToString("o")
    Machine = (Get-WmiObject -Class Win32_ComputerSystem).Name
    OS = (Get-WmiObject -Class Win32_OperatingSystem).Caption
    Report = $report
}

# Convert to JSON and sign with HMAC (simple auth)
$json = $payload | ConvertTo-Json -Depth 6
$hmac = [System.Text.Encoding]::UTF8.GetBytes($ApiKey)
$sha = New-Object System.Security.Cryptography.HMACSHA256 $hmac
$signature = [System.Convert]::ToBase64String($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($json)))

# POST telemetry (example - ensure server uses TLS)
try {
    $headers = @{
        "X-Client-Signature" = $signature
        "X-Client-Time" = (Get-Date).ToString("o")
        "Content-Type" = "application/json"
    }
    Invoke-RestMethod -Uri $TelemetryUrl -Method Post -Body $json -Headers $headers -ErrorAction Stop
    Write-Host "Telemetry sent to server." -ForegroundColor Green
} catch {
    Write-Warning "Failed to send telemetry: $_"
}

Write-Host "Collector finished at $(Get-Date -Format 'u')" -ForegroundColor Cyan
