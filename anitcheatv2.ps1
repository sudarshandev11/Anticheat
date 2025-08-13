<#
scan_all_processes_for_hidden_dlls.ps1
Scans all running processes for in-memory PE images that are NOT present in the process' module list (possible manual-mapped/hidden DLLs).
Requires: Run PowerShell as Administrator for best results.
Usage:
  - Default (scan all processes, don't dump):
      .\scan_all_processes_for_hidden_dlls.ps1
  - Dump suspicious regions to disk:
      .\scan_all_processes_for_hidden_dlls.ps1 -DumpPath "C:\dumps"
  - Limit to specific PID(s):
      .\scan_all_processes_for_hidden_dlls.ps1 -Pids 1234,5678
#>

param(
    [int[]]$Pids = @(),                 # optional list of PIDs to scan; empty = scan all
    [string]$DumpPath = $null,          # optional folder to dump suspicious region(s)
    [int]$MaxRegionsPerProcess = 2000,  # safety cap per process
    [int]$ReadWindow = 4096             # bytes to read per region for PE header scanning
)

# Add native APIs
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class Win32 {
    [Flags]
    public enum AllocationProtect : uint {
        PAGE_NOACCESS = 0x01,
        PAGE_READONLY = 0x02,
        PAGE_READWRITE = 0x04,
        PAGE_WRITECOPY = 0x08,
        PAGE_EXECUTE = 0x10,
        PAGE_EXECUTE_READ = 0x20,
        PAGE_EXECUTE_READWRITE = 0x40,
        PAGE_EXECUTE_WRITECOPY = 0x80
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public AllocationProtect AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public AllocationProtect Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern UIntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);

    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_VM_READ = 0x0010;
}
"@ -PassThru | Out-Null

function Open-TargetProcess([int]$pid) {
    $access = [Win32]::PROCESS_QUERY_INFORMATION -bor [Win32]::PROCESS_VM_READ
    return [Win32]::OpenProcess($access, $false, $pid)
}

function Close-TargetProcess([IntPtr]$h) {
    if ($h -ne [IntPtr]::Zero) { [Win32]::CloseHandle($h) | Out-Null }
}

function Read-MemoryHeader([IntPtr]$h, [IntPtr]$baseAddr, [int]$size) {
    $buf = New-Object byte[] $size
    $bytesRead = [UIntPtr]::Zero
    $ok = [Win32]::ReadProcessMemory($h, $baseAddr, $buf, [UIntPtr] $size, [ref]$bytesRead)
    if ($ok) { return ,$buf,$bytesRead.ToUInt32() } else { return $null }
}

function Find-PEOffsetsInBuffer([byte[]]$buf) {
    $results = @()
    $len = $buf.Length
    for ($i=0; $i -lt $len-1; $i++) {
        if ($buf[$i] -eq 0x4D -and $buf[$i+1] -eq 0x5A) { # 'MZ'
            # check e_lfanew at offset 0x3c if available in buffer
            if ($i + 0x3c + 4 -lt $len) {
                $e_lfanew = [BitConverter]::ToInt32($buf, $i + 0x3c)
                $peOff = $i + $e_lfanew
                if ($peOff + 4 -lt $len) {
                    if ($buf[$peOff] -eq 0x50 -and $buf[$peOff+1] -eq 0x45 -and $buf[$peOff+2] -eq 0 -and $buf[$peOff+3] -eq 0) {
                        $results += $i
                    }
                }
            }
        }
    }
    return $results
}

function Dump-Region([IntPtr]$h, [IntPtr]$baseAddr, [long]$regionSize, [string]$outPath) {
    try {
        $remaining = $regionSize
        $chunkSize = 0x10000
        $pos = 0
        $fs = [System.IO.File]::Open($outPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        while ($remaining -gt 0) {
            $read = [int][System.Math]::Min($chunkSize, $remaining)
            $buf = New-Object byte[] $read
            $bytesRead = [UIntPtr]::Zero
            $ok = [Win32]::ReadProcessMemory($h, [IntPtr]::Add($baseAddr, $pos), $buf, [UIntPtr] $read, [ref]$bytesRead)
            if (-not $ok) { break }
            $fs.Write($buf, 0, [int]$bytesRead)
            $pos += $bytesRead.ToUInt32()
            $remaining -= $bytesRead.ToUInt32()
        }
        $fs.Close()
        return $true
    } catch {
        return $false
    }
}

Write-Host "Starting global in-memory PE scan: $(Get-Date -Format 'u')" -ForegroundColor Cyan

# Build process list
if ($Pids.Count -eq 0) {
    try {
        $procList = Get-Process | Sort-Object ProcessName
    } catch {
        $procList = @()
    }
} else {
    $procList = @()
    foreach ($pid in $Pids) {
        try { $procList += Get-Process -Id $pid -ErrorAction Stop } catch { }
    }
}

$globalFindings = @()

foreach ($p in $procList) {
    $pid = $p.Id
    Write-Host "`n--- Scanning process: $($p.ProcessName) (PID $pid) ---" -ForegroundColor Green

    $hProc = Open-TargetProcess -pid $pid
    if ($hProc -eq [IntPtr]::Zero) {
        Write-Warning "  Cannot open process PID $pid. (Requires admin or SYSTEM?) Skipping."
        continue
    }

    try {
        # Collect known module base addresses
        $knownBases = @{}
        try {
            foreach ($m in $p.Modules) {
                $knownBases[[IntPtr]$m.BaseAddress.ToInt64()] = $m.ModuleName
            }
        } catch { } # some processes throw access denied for Modules

        $addr = [IntPtr]::Zero
        $regions = 0
        $processFindings = @()

        while ($regions -lt $MaxRegionsPerProcess) {
            $mbi = New-Object Win32+MEMORY_BASIC_INFORMATION
            $res = [Win32]::VirtualQueryEx($hProc, $addr, [ref]$mbi, [UIntPtr]([System.Runtime.InteropServices.Marshal]::SizeOf($mbi)))
            if ($res -eq [UIntPtr]::Zero) { break }
            $regions++
            # MEM_COMMIT == 0x1000
            if ($mbi.State -eq 0x1000) {
                # Read small window to detect PE signatures
                $readSize = [int]([Math]::Min($ReadWindow, [int]$mbi.RegionSize))
                $ret = Read-MemoryHeader -h $hProc -baseAddr $mbi.BaseAddress -size $readSize
                if ($ret) {
                    $buf = $ret[0]
                    $foundOffsets = Find-PEOffsetsInBuffer -buf $buf
                    if ($foundOffsets.Count -gt 0) {
                        foreach ($off in $foundOffsets) {
                            $candidateBase = [IntPtr]($mbi.BaseAddress.ToInt64() + $off)
                            $isKnown = $false
                            foreach ($kb in $knownBases.Keys) { if ($kb -eq $candidateBase.ToInt64()) { $isKnown = $true; break } }
                            # Report if not in module list
                            if (-not $isKnown) {
                                $entry = [PSCustomObject]@{
                                    ProcessName = $p.ProcessName
                                    PID = $pid
                                    CandidateAddress = ("0x{0:X}" -f $candidateBase.ToInt64())
                                    RegionBase = ("0x{0:X}" -f $mbi.BaseAddress.ToInt64())
                                    RegionSize = $mbi.RegionSize.ToInt64()
                                    Protection = $mbi.Protect.ToString()
                                    AllocationBase = ("0x{0:X}" -f $mbi.AllocationBase.ToInt64())
                                    DetectedOffsetInRegion = $off
                                    ModuleListMatches = ($knownBases.Values -join ",")
                                }
                                $processFindings += $entry

                                # Optionally dump the region
                                if ($DumpPath) {
                                    try {
                                        if (-not (Test-Path $DumpPath)) { New-Item -Path $DumpPath -ItemType Directory -Force | Out-Null }
                                        $safeName = "{0}_{1}_0x{2:X}.bin" -f $p.ProcessName, $pid, $candidateBase.ToInt64()
                                        $outFile = Join-Path $DumpPath $safeName
                                        $dumpOk = Dump-Region -h $hProc -baseAddr $candidateBase -regionSize ([Math]::Min($mbi.RegionSize.ToInt64(), 10MB)) -outPath $outFile
                                        if ($dumpOk) { $entry | Add-Member -NotePropertyName DumpPath -NotePropertyValue $outFile }
                                        else { $entry | Add-Member -NotePropertyName DumpPath -NotePropertyValue "Dump failed" }
                                    } catch { $entry | Add-Member -NotePropertyName DumpPath -NotePropertyValue "Dump error" }
                                }
                            }
                        }
                    }
                }
            }
            $addr = [IntPtr]($mbi.BaseAddress.ToInt64() + $mbi.RegionSize.ToInt64())
        }

        if ($processFindings.Count -eq 0) {
            Write-Host "  No hidden PE candidates found (or access denied to modules/memory)." -ForegroundColor DarkGray
        } else {
            Write-Host "  Found $($processFindings.Count) suspicious in-memory PE candidate(s):" -ForegroundColor Yellow
            foreach ($f in $processFindings) {
                Write-Host "    PID $($f.PID) $($f.ProcessName) Candidate: $($f.CandidateAddress) RegionBase: $($f.RegionBase) Size: $($f.RegionSize) Dump: $($f.DumpPath)" -ForegroundColor Magenta
            }
            $globalFindings += $processFindings
        }

    } finally {
        Close-TargetProcess -h $hProc
    }
}

Write-Host "`nScan complete at $(Get-Date -Format 'u'). Summary:" -ForegroundColor Cyan
if ($globalFindings.Count -eq 0) {
    Write-Host "  No suspicious in-memory PE candidates detected across scanned processes." -ForegroundColor Green
} else {
    Write-Host "  Total suspicious candidates: $($globalFindings.Count)" -ForegroundColor Yellow
    # Print short table
    $globalFindings | Select-Object ProcessName,PID,CandidateAddress,RegionBase,RegionSize,DumpPath | Format-Table -AutoSize
    if ($DumpPath) { Write-Host "`nDump files (if any) saved to $DumpPath" -ForegroundColor Cyan }
}

# End
