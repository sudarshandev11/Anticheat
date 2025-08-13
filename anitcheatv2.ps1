# PowerShell script to detect suspicious and potentially injected DLLs for specified applications
# Requires administrative privileges for full process and memory access

# Define target applications (modify as needed for specific executables or paths)
$targetApps = @("HD-Player", "BlueStacks", "msiexec", "MSIAfterburner") # Adjust process names as needed

# Log file setup
$logFile = "C:\Temp\DLL_Analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
if (-not (Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" -Force | Out-Null }

# Function to check if a file has a valid digital signature
function Test-DLLSignature {
    param (
        [string]$FilePath
    )
    try {
        if (-not (Test-Path $FilePath -ErrorAction SilentlyContinue)) {
            return "File not found on disk (possible memory-only/injected DLL)"
        }
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        if ($signature.Status -eq "Valid" -and $signature.SignerCertificate) {
            return "Valid - Signed by: $($signature.SignerCertificate.Subject)"
        } else {
            return "Invalid or Unsigned"
        }
    } catch {
        return "Error checking signature: $_"
    }
}

# Function to check for indicators of DLL injection
function Test-DLLInjection {
    param (
        [string]$ModulePath,
        [string]$ModuleName
    )
    $injectionIndicators = @()

    # Check if the DLL file exists on disk
    if (-not (Test-Path $ModulePath -ErrorAction SilentlyContinue)) {
        $injectionIndicators += "DLL file not found on disk (possible memory-only injection)"
    }

    # Check for unusual paths (not in System32, Program Files, or known app directories)
    if ($ModulePath -notlike "*\Windows\System32\*" -and 
        $ModulePath -notlike "*\Program Files\*" -and 
        $ModulePath -notlike "*\Program Files (x86)\*" -and 
        $ModulePath -notlike "*\BlueStacks\*") {
        $injectionIndicators += "Unusual path: $ModulePath"
    }

    # Check for suspicious module names (e.g., random strings, temp patterns)
    if ($ModuleName -match "^[a-zA-Z0-9]{8}\.dll$" -or $ModuleName -like "*temp*.dll") {
        $injectionIndicators += "Suspicious module name: $ModuleName"
    }

    return $injectionIndicators
}

# Function to analyze DLLs for a given process
function Analyze-ProcessDLLs {
    param (
        [System.Diagnostics.Process]$Process
    )
    $output = "Analyzing process: $($Process.ProcessName) (PID: $($Process.Id), Path: $($Process.Path))\n"
    $output += "----------------------------------------\n"
    
    try {
        $modules = $Process.Modules
        foreach ($module in $modules) {
            $modulePath = $module.FileName
            $moduleName = $module.ModuleName
            $signatureStatus = Test-DLLSignature -FilePath $modulePath
            $injectionIndicators = Test-DLLInjection -FilePath $modulePath -ModuleName $moduleName
            
            # Flag suspicious DLLs
            $isSuspicious = $false
            $suspiciousReason = ""
            
            if ($signatureStatus -notlike "Valid*") {
                $isSuspicious = $true
                $suspiciousReason += "Unsigned or invalid signature; "
            }
            if ($injectionIndicators) {
                $isSuspicious = $true
                $suspiciousReason += ($injectionIndicators -join "; ")
            }
            
            $output += "DLL: $moduleName`n"
            $output += "Path: $modulePath`n"
            $output += "Signature: $signatureStatus`n"
            if ($isSuspicious) {
                $output += "Suspicious: Yes - Reason: $suspiciousReason`n"
            } else {
                $output += "Suspicious: No`n"
            }
            $output += "----------------------------------------\n"
        }
    } catch {
        $output += "Error accessing modules for process $($Process.ProcessName): $_`n"
    }
    
    return $output
}

# Main script
Write-Host "Starting DLL analysis for target applications: $($targetApps -join ', ')" -ForegroundColor Cyan
Add-Content -Path $logFile -Value "DLL Analysis Report - $(Get-Date)"
Add-Content -Path $logFile -Value "Target Applications: $($targetApps -join ', ')"
Add-Content -Path $logFile -Value "----------------------------------------"

# Get all running processes
$processes = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $processName = $_.ProcessName
    $targetApps | Where-Object { $processName -like "*$_*" }
}

if ($processes) {
    foreach ($process in $processes) {
        $result = Analyze-ProcessDLLs -Process $process
        Add-Content -Path $logFile -Value $result
        Write-Host $result
    }
} else {
    $noProcessesMsg = "No running processes found for target applications: $($targetApps -join ', ')"
    Add-Content -Path $logFile -Value $noProcessesMsg
    Write-Host $noProcessesMsg -ForegroundColor Yellow
}

# Check for installed applications (optional, to detect if the software is installed but not running)
Add-Content -Path $logFile -Value "`nChecking installed applications in registry..."
foreach ($app in $targetApps) {
    $installed = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | 
        Where-Object { $_.DisplayName -like "*$app*" }
    $installedWow = Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | 
        Where-Object { $_.DisplayName -like "*$app*" }
    $installed += $installedWow
    if ($installed) {
        foreach ($item in $installed) {
            $installedMsg = "Found installed application: $($item.DisplayName) (Version: $($item.DisplayVersion))"
            Add-Content -Path $logFile -Value $installedMsg
            Write-Host $installedMsg -ForegroundColor Green
        }
    }
}

Write-Host "Analysis complete. Results saved to $logFile" -ForegroundColor Cyan
