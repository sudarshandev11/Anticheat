param(
    [Parameter(Mandatory=$true)]
    [string[]] $ProcessNames,          # Target processes (e.g., "BlueStacks","HD-Player")
    [int] $IntervalSeconds = 5,        # Check interval
    [string] $LogPath = "$PSScriptRoot\process_module_monitor.log",
    [string] $CsvPath = "$PSScriptRoot\incidents.csv",
    [string] $ReportUrl = "https://yourserver.example.com/report-cheat",  # Change this
    [switch] $PopupAlerts
)

function Write-Log {
    param($Text)
    $t = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "$t`t$Text"
    $line | Out-File -FilePath $LogPath -Append -Encoding utf8
    Write-Host $line
}

function Log-Incident {
    param($procName, $pid, $type, $detail)
    $time = (Get-Date).ToString("o")
    $obj = [PSCustomObject]@{
        Time = $time
        ProcessName = $procName
        PID = $pid
        Type = $type
        Detail = $detail
    }
    if (-not (Test-Path $CsvPath)) {
        $obj | Export-Csv -Path $CsvPath -NoTypeInformation
    } else {
        $obj | Export-Csv -Path $CsvPath -Append -NoTypeInformation
    }
}

function Get-FileHashSafe {
    param($path)
    try {
        if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path $path)) { return $null }
        return (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch { return $null }
}

# Suspicious handle check: See which processes opened target with write access
function Get-SuspiciousHandles {
    param($targetPid)
    try {
        $handleList = Get-Process | ForEach-Object {
            $p = $_
            try {
                $handles = (Get-Process -Id $p.Id -ErrorAction SilentlyContinue) | Out-Null
                $access = (Get-Process -Id $p.Id -IncludeUserName -ErrorAction SilentlyContinue)
                # In a real EDR, you'd inspect handles here via SysInternals 'handle.exe'
            } catch {}
        }
    } catch {}
}

$state = @{}

Write-Log "=== Module Monitor START ==="
Write-Log "Watching: $($ProcessNames -join ', '), interval ${IntervalSeconds}s"

while ($true) {
    foreach ($pName in $ProcessNames) {
        try { $procs = Get-Process -Name $pName -ErrorAction SilentlyContinue } catch { $procs = @() }
        if (-not $procs) { continue }

        foreach ($proc in $procs) {
            $pid = $proc.Id
            $modules = @()
            try {
                $modules = $proc.Modules | ForEach-Object {
                    [PSCustomObject]@{
                        ModuleName = $_.ModuleName
                        FileName   = $_.FileName
                    }
                }
            } catch {
                Write-Log "WARN: Could not read modules for $($proc.ProcessName) (PID $pid)"
                continue
            }

            $current = @{}
            foreach ($m in $modules) {
                if ([string]::IsNullOrEmpty($m.FileName)) { continue }
                $hash = Get-FileHashSafe -path $m.FileName
                $current[$m.FileName.ToLower()] = @{
                    ModuleName = $m.ModuleName
                    Hash = $hash
                }
            }

            if (-not $state.ContainsKey($pid)) {
                $state[$pid] = $current
                continue
            }

            $prev = $state[$pid]
            $new = $current.Keys | Where-Object { -not $prev.ContainsKey($_) }
            $removed = $prev.Keys | Where-Object { -not $current.ContainsKey($_) }
            $changed = $current.Keys | Where-Object { $prev.ContainsKey($_) -and $prev[$_].Hash -ne $current[$_].Hash }

            if ($new.Count -or $removed.Count -or $changed.Count) {
                $msg = "ALERT: $($proc.ProcessName) PID $pid - New: $($new.Count), Removed: $($removed.Count), Changed: $($changed.Count)"
                Write-Log $msg
                Log-Incident $proc.ProcessName $pid "ModuleChange" $msg

                # Report to server
                try {
                    $report = @{
                        time = (Get-Date).ToString("o")
                        process = $proc.ProcessName
                        pid = $pid
                        changes = @{
                            new = $new
                            removed = $removed
                            changed = $changed
                        }
                    }
                    Invoke-RestMethod -Uri $ReportUrl -Method Post -Body ($report | ConvertTo-Json -Depth 4) -ContentType "application/json" -TimeoutSec 5
                } catch {
                    Write-Log "WARN: Report failed: $($_.Exception.Message)"
                }

                # Kill the process
                try {
                    Stop-Process -Id $pid -Force
                    Write-Log "ACTION: Process $pid killed due to module change."
                    Log-Incident $proc.ProcessName $pid "Action" "Killed process"
                } catch {
                    Write-Log "WARN: Kill failed: $($_.Exception.Message)"
                }

                if ($PopupAlerts) {
                    Add-Type -AssemblyName PresentationFramework
                    [System.Windows.MessageBox]::Show($msg, "Anti-Tamper Alert", "OK", "Warning") | Out-Null
                }
            }

            $state[$pid] = $current
        }
    }
    Start-Sleep -Seconds $IntervalSeconds
}
