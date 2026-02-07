<#
.SYNOPSIS
    Headless batch extractor for PE files using IDA Pro.

.DESCRIPTION
    Automates PE file analysis using IDA Pro in headless mode with concurrent processing.
    Extracts function signatures, assembly code, dangerous APIs, strings, control flow,
    and other results into SQLite databases.

.PARAMETER ExtractDir
    Directory path to scan for PE files (.exe, .dll, .sys). Use with -Recursive for subdirectory scanning.

.PARAMETER FilesToAnalyze
    Path to a text file containing a list of PE file paths to analyze (one per line).

.PARAMETER TargetPid
    Process ID (PID) to extract loaded modules from. Enumerates all modules and analyzes them.

.PARAMETER StorageDir
    Directory where analysis results will be stored (SQLite databases, logs, IDB cache).

.PARAMETER Recursive
    Include subdirectories when scanning (only valid with -ExtractDir).

.PARAMETER IdaPath
    Path to IDA Pro executable (idat.exe or idat64.exe). If not specified, the script auto-detects the latest IDA 9.x installation.

.PARAMETER MaxConcurrentProcesses
    Maximum number of concurrent IDA processes to run (default: 4). Adjust based on system resources.

.PARAMETER Help
    Display detailed help information with usage examples.

.PARAMETER NoDownloadSymbols
    Skip automatic symbol (PDB) downloading before analysis. Symbols are downloaded by default.

.PARAMETER SymbolStorePath
    Local symbol store directory where PDB files are cached (default: C:\symbols).

.PARAMETER SymchkPath
    Path to symchk.exe from the Windows SDK Debugging Tools. Auto-detected if not specified.

.PARAMETER SymbolServerUrl
    Symbol server URL to download PDBs from (default: https://msdl.microsoft.com/download/symbols).

.EXAMPLE
    .\headless_batch_extractor.ps1 -ExtractDir "C:\Windows\System32" -StorageDir "C:\Analysis" -Recursive

.EXAMPLE
    .\headless_batch_extractor.ps1 -FilesToAnalyze "files.txt" -StorageDir "C:\Analysis"

.EXAMPLE
    .\headless_batch_extractor.ps1 -TargetPid 1234 -StorageDir "C:\Analysis"

.EXAMPLE
    .\headless_batch_extractor.ps1 -ExtractDir "C:\Binaries" -StorageDir "C:\Analysis" -IdaPath "C:\IDA92\idat64.exe"

.EXAMPLE
    .\headless_batch_extractor.ps1 -ExtractDir "C:\Large\Dataset" -StorageDir "C:\Analysis" -MaxConcurrentProcesses 8
#>

[CmdletBinding(DefaultParameterSetName = 'Directory')]
param(
    # Parameter set for directory-based extraction
    [Parameter(Mandatory = $true, ParameterSetName = 'Directory', HelpMessage = "Directory path to scan for PE files")]
    [ValidateNotNullOrEmpty()]
    [string]$ExtractDir,

    # Parameter set for file-list based extraction
    [Parameter(Mandatory = $true, ParameterSetName = 'FileList', HelpMessage = "Path to text file containing list of PE files to analyze")]
    [ValidateScript({ 
            if (-not (Test-Path $_ -PathType Leaf)) {
                throw "File '$_' does not exist."
            }
            return $true
        })]
    [string]$FilesToAnalyze,

    # Parameter set for PID-based extraction
    [Parameter(Mandatory = $true, ParameterSetName = 'Pid', HelpMessage = "Process ID to extract loaded modules from")]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$TargetPid,

    [Parameter(Mandatory = $true, ParameterSetName = 'Directory', HelpMessage = "Directory where analysis results will be stored")]
    [Parameter(Mandatory = $true, ParameterSetName = 'FileList')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Pid')]
    [Parameter(ParameterSetName = 'Help')]
    [ValidateNotNullOrEmpty()]
    [string]$StorageDir,

    [Parameter(HelpMessage = "Include subdirectories when scanning for PE files (only valid with -ExtractDir)")]
    [switch]$Recursive,

    [Parameter(HelpMessage = "Path to IDA Pro executable (idat.exe). Auto-detected if not specified.")]
    [ValidateScript({ 
            if ($_ -and -not (Test-Path $_ -PathType Leaf)) {
                throw "IDA executable not found at '$_'."
            }
            return $true
        })]
    [string]$IdaPath,

    [Parameter(HelpMessage = "Maximum number of concurrent IDA processes (default: 4)")]
    [ValidateRange(1, 32)]
    [int]$MaxConcurrentProcesses = 4,

    # Display help
    [Parameter(ParameterSetName = 'Help', HelpMessage = "Display detailed help information")]
    [Alias('h', '?')]
    [switch]$Help,

    # Analysis Feature Flags
    [Parameter(HelpMessage = "Skip extraction of dangerous API calls")] [switch]$NoExtractDangerousApis,
    [Parameter(HelpMessage = "Skip string extraction")] [switch]$NoExtractStrings,
    [Parameter(HelpMessage = "Skip stack frame analysis")] [switch]$NoExtractStackFrame,
    [Parameter(HelpMessage = "Skip global variable extraction")] [switch]$NoExtractGlobals,
    [Parameter(HelpMessage = "Skip loop analysis")] [switch]$NoAnalyzeLoops,
    [Parameter(HelpMessage = "Skip PE header information extraction")] [switch]$NoPeInfo,
    [Parameter(HelpMessage = "Skip PE metadata extraction")] [switch]$NoPeMetadata,
    [Parameter(HelpMessage = "Skip advanced PE analysis")] [switch]$NoAdvancedPe,
    [Parameter(HelpMessage = "Skip runtime information extraction")] [switch]$NoRuntimeInfo,
    [Parameter(HelpMessage = "Force re-analysis of previously analyzed files")] [switch]$ForceReanalyze,
    [Parameter(HelpMessage = "Skip C++ file generation from decompiled code")] [switch]$NoGenerateCpp,

    # Symbol Download Options
    [Parameter(HelpMessage = "Skip automatic symbol (PDB) downloading before analysis (enabled by default)")]
    [switch]$NoDownloadSymbols,

    [Parameter(HelpMessage = "Local symbol store directory (default: C:\symbols)")]
    [ValidateNotNullOrEmpty()]
    [string]$SymbolStorePath = "C:\symbols",

    [Parameter(HelpMessage = "Path to symchk.exe. Auto-detected from Windows SDK if not specified.")]
    [ValidateScript({ 
            if ($_ -and -not (Test-Path $_ -PathType Leaf)) {
                throw "symchk.exe not found at '$_'."
            }
            return $true
        })]
    [string]$SymchkPath,

    [Parameter(HelpMessage = "Symbol server URL (default: Microsoft public symbol server)")]
    [ValidateNotNullOrEmpty()]
    [string]$SymbolServerUrl = "https://msdl.microsoft.com/download/symbols"
)

# Show-Help function
function Show-Help {
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host "  DeepExtract - Headless Batch Extractor for IDA Pro" -ForegroundColor Cyan
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "DESCRIPTION:" -ForegroundColor Yellow
    Write-Host "  Automates PE file analysis using IDA Pro in headless mode with concurrent"
    Write-Host "  processing. Extracts function signatures, assembly code, dangerous APIs,"
    Write-Host "  strings, control flow, and other results into SQLite databases."
    Write-Host ""
    Write-Host "EXTRACTION MODES:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  1. Directory Scan Mode" -ForegroundColor Green
    Write-Host "     Scans a directory for PE files (.exe, .dll, .sys)"
    Write-Host "     Usage: -ExtractDir <path> [-Recursive]"
    Write-Host ""
    Write-Host "  2. File List Mode" -ForegroundColor Green
    Write-Host "     Processes files listed in a text file (one path per line)"
    Write-Host "     Usage: -FilesToAnalyze <file.txt>"
    Write-Host ""
    Write-Host "  3. PID Mode" -ForegroundColor Green
    Write-Host "     Extracts all modules loaded by a running process"
    Write-Host "     Usage: -TargetPid <process_id>"
    Write-Host ""
    Write-Host "COMMON PARAMETERS:" -ForegroundColor Yellow
    Write-Host "  -StorageDir <path>      Output directory for analysis results (required)"
    Write-Host "  -IdaPath <path>         Path to IDA Pro executable (auto-detected if not specified)"
    Write-Host "  -MaxConcurrentProcesses Number of parallel IDA processes (default: 4)"
    Write-Host "  -Recursive              Include subdirectories (Directory mode only)"
    Write-Host "  -Help                   Display this help message"
    Write-Host ""
    Write-Host "ANALYSIS FLAGS (disable specific features):" -ForegroundColor Yellow
    Write-Host "  -NoExtractDangerousApis Skip dangerous API detection"
    Write-Host "  -NoExtractStrings       Skip string literal extraction"
    Write-Host "  -NoExtractStackFrame    Skip stack frame analysis"
    Write-Host "  -NoExtractGlobals       Skip global variable tracking"
    Write-Host "  -NoAnalyzeLoops         Skip loop analysis (Tarjan algorithm)"
    Write-Host "  -NoPeInfo               Skip PE version info extraction"
    Write-Host "  -NoPeMetadata           Skip PE metadata extraction"
    Write-Host "  -NoAdvancedPe           Skip Rich header/TLS callbacks"
    Write-Host "  -NoRuntimeInfo          Skip .NET/delay-load analysis"
    Write-Host "  -ForceReanalyze         Force re-analysis of all files"
    Write-Host "  -NoGenerateCpp          Skip C++ code generation"
    Write-Host ""
    Write-Host "SYMBOL DOWNLOAD OPTIONS:" -ForegroundColor Yellow
    Write-Host "  Symbols (PDBs) are automatically downloaded before analysis using symchk.exe."
    Write-Host "  This enables IDA Pro to produce richer analysis with proper function names."
    Write-Host ""
    Write-Host "  -NoDownloadSymbols      Skip automatic symbol downloading (enabled by default)"
    Write-Host "  -SymbolStorePath <path>  Local symbol cache directory (default: C:\symbols)"
    Write-Host "  -SymchkPath <path>      Path to symchk.exe (auto-detected from Windows SDK)"
    Write-Host "  -SymbolServerUrl <url>   Symbol server URL (default: Microsoft public server)"
    Write-Host ""
    Write-Host "  Sets _NT_SYMBOL_PATH environment variable at user level (no admin required)."
    Write-Host "  Requires symchk.exe from Windows SDK Debugging Tools."
    Write-Host ""
    Write-Host "EXAMPLES:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  # Analyze all PE files in System32 (recursive, symbols auto-downloaded)" -ForegroundColor Gray
    Write-Host "  .\headless_batch_extractor.ps1 -ExtractDir 'C:\Windows\System32' -StorageDir 'C:\Analysis' -Recursive"
    Write-Host ""
    Write-Host "  # Analyze files from a list" -ForegroundColor Gray
    Write-Host "  .\headless_batch_extractor.ps1 -FilesToAnalyze 'targets.txt' -StorageDir 'C:\Analysis'"
    Write-Host ""
    Write-Host "  # Extract modules from a running process (PID 1234)" -ForegroundColor Gray
    Write-Host "  .\headless_batch_extractor.ps1 -TargetPid 1234 -StorageDir 'C:\Analysis'"
    Write-Host ""
    Write-Host "  # Skip symbol downloading (faster startup, less accurate analysis)" -ForegroundColor Gray
    Write-Host "  .\headless_batch_extractor.ps1 -ExtractDir 'C:\Binaries' -StorageDir 'C:\Analysis' -NoDownloadSymbols"
    Write-Host ""
    Write-Host "  # Use a custom symbol store path" -ForegroundColor Gray
    Write-Host "  .\headless_batch_extractor.ps1 -ExtractDir 'C:\Binaries' -StorageDir 'C:\Analysis' -SymbolStorePath 'D:\MySymbols'"
    Write-Host ""
    Write-Host "  # Skip string extraction to reduce analysis time" -ForegroundColor Gray
    Write-Host "  .\headless_batch_extractor.ps1 -ExtractDir 'C:\Binaries' -StorageDir 'C:\Analysis' -NoExtractStrings"
    Write-Host ""
    Write-Host "  # Use a specific IDA installation" -ForegroundColor Gray
    Write-Host "  .\headless_batch_extractor.ps1 -ExtractDir 'C:\Binaries' -StorageDir 'C:\Analysis' -IdaPath 'C:\IDA92\idat64.exe'"
    Write-Host ""
    Write-Host "  # Run with 8 concurrent IDA processes (high-core systems)" -ForegroundColor Gray
    Write-Host "  .\headless_batch_extractor.ps1 -ExtractDir 'C:\Large\Dataset' -StorageDir 'C:\Analysis' -MaxConcurrentProcesses 8"
    Write-Host ""
    Write-Host "OUTPUT STRUCTURE:" -ForegroundColor Yellow
    Write-Host "  <storageDir>/"
    Write-Host "    +-- analyzed_modules_list.txt  List of files analyzed"
    Write-Host "    +-- extraction_report.json     Summary report"
    Write-Host "    +-- extracted_dbs/           SQLite analysis databases"
    Write-Host "    +-- extracted_code/          Generated C++ code"
    Write-Host "    +-- logs/                    IDA analysis logs"
    Write-Host "    +-- idb_cache/               IDA database files (.i64)"
    Write-Host ""
    Write-Host "MORE HELP:" -ForegroundColor Yellow
    Write-Host "  Get-Help .\headless_batch_extractor.ps1 -Detailed"
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host ""
}

# Check for -Help parameter
if ($Help) {
    Show-Help
    exit 0
}

# ============================================================================
# Script Constants
# ============================================================================

# Exit codes
$script:EXIT_SUCCESS = 0
$script:EXIT_VALIDATION_ERROR = 1      # Parameter validation, invalid paths, etc.
$script:EXIT_IDA_NOT_FOUND = 2         # IDA Pro installation not found
$script:EXIT_PYTHON_ERROR = 3          # Python not installed or script error
$script:EXIT_PERMISSION_ERROR = 4      # Admin privileges required but not available
$script:EXIT_SCRIPT_MISSING = 5        # Required script files not found
$script:EXIT_PROCESS_ERROR = 6         # Error starting or managing IDA processes

# Timeout constant for IDA processes (6 hours in seconds)
$script:IDA_PROCESS_TIMEOUT_SECONDS = 6 * 60 * 60  # 21600 seconds = 6 hours

# Length of hash prefix used for unique file naming (from MD5 hash)
$script:HASH_PREFIX_LENGTH = 10

# Process management constants
$script:PROCESS_KILL_WAIT_MS = 5000      # Wait time for graceful process termination
$script:PROCESS_CLEANUP_WAIT_MS = 3000   # Wait time during cleanup termination
$script:STATUS_UPDATE_INTERVAL_SECONDS = 300  # How often to print status updates (5 minutes)
$script:PROCESS_POLL_INTERVAL_SECONDS = 5    # Polling interval in final wait loop

# Add parameter validation at the start of the script
if ($PSCmdlet.ParameterSetName -eq 'FileList' -and $Recursive) {
    Write-Error "The -Recursive parameter cannot be used with -FilesToAnalyze. The -Recursive parameter is only valid when scanning directories with -ExtractDir."
    Write-Host ""
    Write-Host "Usage examples:"
    Write-Host "  Directory scan: .\headless_batch_extractor.ps1 -ExtractDir 'C:\path\to\scan' -Recursive -StorageDir 'C:\tools\db'"
    Write-Host "  File list:      .\headless_batch_extractor.ps1 -FilesToAnalyze 'input.txt' -StorageDir 'C:\tools\db'"
    Write-Host "  Skip C++ gen:   .\headless_batch_extractor.ps1 -ExtractDir 'C:\path\to\scan' -StorageDir 'C:\tools\db' -NoGenerateCpp"
    exit $script:EXIT_VALIDATION_ERROR
}

# Auto-detect IDA Pro installation
function Find-LatestIDA {
    # Strategy 1: Check PATH environment variable first
    $idaInPath = Get-Command -Name "idat.exe", "idat64.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($idaInPath) {
        Write-Host "Found IDA in PATH: $($idaInPath.Source)" -ForegroundColor Gray
        return $idaInPath.Source
    }
    
    # Strategy 2: Check Windows Registry for IDA installation
    $registryPaths = @(
        "HKLM:\SOFTWARE\Hex-Rays\IDA",
        "HKLM:\SOFTWARE\WOW6432Node\Hex-Rays\IDA",
        "HKCU:\SOFTWARE\Hex-Rays\IDA"
    )
    foreach ($regPath in $registryPaths) {
        try {
            $regKey = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            if ($regKey -and $regKey.InstallDir) {
                $idatPath = Join-Path $regKey.InstallDir "idat.exe"
                $idat64Path = Join-Path $regKey.InstallDir "idat64.exe"
                if (Test-Path $idatPath) {
                    Write-Host "Found IDA via registry: $idatPath" -ForegroundColor Gray
                    return $idatPath
                }
                if (Test-Path $idat64Path) {
                    Write-Host "Found IDA via registry: $idat64Path" -ForegroundColor Gray
                    return $idat64Path
                }
            }
        }
        catch {
            # Registry key doesn't exist or can't be read, continue
        }
    }
    
    # Strategy 3: Search common installation directories
    $searchPaths = @(
        "C:\Program Files\IDA Professional 9.*",
        "C:\Program Files\IDA Pro 9.*",
        "C:\Program Files (x86)\IDA Professional 9.*",
        "C:\Program Files (x86)\IDA Pro 9.*",
        # Additional common locations
        "D:\Program Files\IDA Professional 9.*",
        "D:\Program Files\IDA Pro 9.*",
        "C:\Tools\IDA*",
        "D:\Tools\IDA*"
    )
    
    $idaInstallations = @()
    foreach ($pattern in $searchPaths) {
        $found = Get-Item -Path $pattern -ErrorAction SilentlyContinue
        if ($found) {
            $idaInstallations += $found
        }
    }
    
    if ($idaInstallations.Count -eq 0) {
        return $null
    }
    
    # Sort by version number (extract numeric version from folder name) and get the latest
    $latestIDA = $idaInstallations | Sort-Object {
        # Extract version number like "9.1" or "9.2" from the path
        if ($_.Name -match '(\d+\.\d+)') {
            [version]$matches[1]
        }
        else {
            [version]"0.0"
        }
    } -Descending | Select-Object -First 1
    
    $idatPath = Join-Path $latestIDA.FullName "idat.exe"
    if (Test-Path $idatPath) {
        return $idatPath
    }
    
    # Fallback to idat64.exe if idat.exe not found
    $idat64Path = Join-Path $latestIDA.FullName "idat64.exe"
    if (Test-Path $idat64Path) {
        return $idat64Path
    }
    
    return $null
}

# Auto-detect symchk.exe from Windows SDK Debugging Tools
function Find-Symchk {
    # Strategy 1: Check PATH environment variable first
    $symchkInPath = Get-Command -Name "symchk.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($symchkInPath) {
        Write-Host "Found symchk.exe in PATH: $($symchkInPath.Source)" -ForegroundColor Gray
        return $symchkInPath.Source
    }
    
    # Strategy 2: Search common Windows SDK Debugger installation directories
    # Prefer x64 over x86
    $searchPaths = @(
        "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe",
        "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\symchk.exe",
        "C:\Program Files\Windows Kits\10\Debuggers\x64\symchk.exe",
        "C:\Program Files\Windows Kits\10\Debuggers\x86\symchk.exe"
    )
    
    foreach ($path in $searchPaths) {
        if (Test-Path $path -PathType Leaf) {
            Write-Host "Found symchk.exe: $path" -ForegroundColor Gray
            return $path
        }
    }
    
    return $null
}

# Set _NT_SYMBOL_PATH environment variable (user-level, no admin required)
function Set-SymbolPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SymbolStorePath,
        [Parameter(Mandatory = $true)]
        [string]$SymbolServerUrl
    )
    
    $symbolPathValue = "srv*$SymbolStorePath*$SymbolServerUrl"
    
    # Check if already set to the same value
    $currentValue = [System.Environment]::GetEnvironmentVariable('_NT_SYMBOL_PATH', 'User')
    if ($currentValue -eq $symbolPathValue) {
        Write-Host "_NT_SYMBOL_PATH already set (user-level): $symbolPathValue" -ForegroundColor Gray
    }
    else {
        # Set persistent user-level environment variable (no admin required)
        try {
            [System.Environment]::SetEnvironmentVariable('_NT_SYMBOL_PATH', $symbolPathValue, 'User')
            Write-Host "Set _NT_SYMBOL_PATH (user-level): $symbolPathValue" -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not set persistent _NT_SYMBOL_PATH: $($_.Exception.Message)"
            Write-Warning "The variable will only be set for the current session."
        }
    }
    
    # Always set in current process so IDA picks it up immediately
    $env:_NT_SYMBOL_PATH = $symbolPathValue
    Write-Host "_NT_SYMBOL_PATH set for current process." -ForegroundColor Gray
}

# Download symbols for a list of files using symchk.exe
# Runs one symchk process per file with concurrency throttling
function Start-SymbolDownload {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo[]]$Files,
        [Parameter(Mandatory = $true)]
        [string]$SymchkExePath,
        [Parameter(Mandatory = $true)]
        [string]$SymbolStorePath,
        [Parameter(Mandatory = $true)]
        [string]$SymbolServerUrl,
        [Parameter(Mandatory = $true)]
        [string]$LogsDir,
        [int]$MaxConcurrent = 10
    )
    
    if ($Files.Count -eq 0) {
        Write-Host "No files to download symbols for." -ForegroundColor Yellow
        return
    }
    
    # Ensure the symbol store directory exists
    if (-not (Test-Path $SymbolStorePath)) {
        try {
            New-Item -ItemType Directory -Path $SymbolStorePath -Force -ErrorAction Stop | Out-Null
            Write-Host "Created symbol store directory: $SymbolStorePath"
        }
        catch {
            Write-Error "Failed to create symbol store directory '$SymbolStorePath': $($_.Exception.Message)"
            return
        }
    }
    
    $symbolServerArg = "srv*$SymbolStorePath*$SymbolServerUrl"
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    
    Write-Host ""
    Write-Host "=== Symbol Download ===" -ForegroundColor Cyan
    Write-Host "Downloading symbols for $($Files.Count) file(s) (max $MaxConcurrent concurrent)"
    Write-Host "Symbol store: $SymbolStorePath"
    Write-Host "Symbol server: $SymbolServerUrl"
    Write-Host ""
    
    $downloadStartTime = Get-Date
    
    # Track active and completed processes
    $activeProcesses = [System.Collections.Generic.List[hashtable]]::new()
    $succeeded = 0
    $failed = 0
    $totalStarted = 0
    
    foreach ($file in $Files) {
        $fileName = $file.Name
        $filePath = $file.FullName
        
        # Throttle: wait for a slot to open if at max concurrency
        while ($activeProcesses.Count -ge $MaxConcurrent) {
            # Check for completed processes
            $stillRunning = [System.Collections.Generic.List[hashtable]]::new()
            foreach ($entry in $activeProcesses) {
                if ($entry.Process.HasExited) {
                    # Harvest result
                    $exitCode = $entry.Process.ExitCode
                    
                    # Write log files from captured output
                    try { $entry.StdoutBuilder.ToString() | Out-File -FilePath $entry.LogFile -Encoding UTF8 -Force } catch { }
                    $stderrContent = $entry.StderrBuilder.ToString()
                    if (-not [string]::IsNullOrWhiteSpace($stderrContent)) {
                        try { $stderrContent | Out-File -FilePath "$($entry.LogFile).err" -Encoding UTF8 -Force } catch { }
                    }
                    
                    # Unregister events and dispose
                    try { Unregister-Event -SourceIdentifier $entry.StdoutEvent.Name -ErrorAction SilentlyContinue } catch { }
                    try { Unregister-Event -SourceIdentifier $entry.StderrEvent.Name -ErrorAction SilentlyContinue } catch { }
                    try { $entry.Process.Dispose() } catch { }
                    
                    if ($exitCode -eq 0) {
                        $succeeded++
                    }
                    else {
                        $failed++
                        Write-Host "  No symbols: $($entry.FileName) (exit code: $exitCode)" -ForegroundColor Yellow
                    }
                }
                else {
                    $stillRunning.Add($entry)
                }
            }
            $activeProcesses = $stillRunning
            
            if ($activeProcesses.Count -ge $MaxConcurrent) {
                Start-Sleep -Milliseconds 500
            }
        }
        
        # Create a sanitized filename for the log
        $sanitizedName = $fileName -replace '[\\/:*?"<>|]', '_'
        $logFile = Join-Path $LogsDir "symchk_${sanitizedName}_${timestamp}.log"
        
        $symchkArgsStr = "/v /s `"$symbolServerArg`" `"$filePath`""
        
        try {
            # Use System.Diagnostics.Process directly instead of Start-Process
            # Start-Process with -RedirectStandardOutput breaks .ExitCode retrieval
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $SymchkExePath
            $psi.Arguments = $symchkArgsStr
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            
            $proc = New-Object System.Diagnostics.Process
            $proc.StartInfo = $psi
            
            # Capture stdout/stderr asynchronously to avoid deadlocks
            $stdoutBuilder = New-Object System.Text.StringBuilder
            $stderrBuilder = New-Object System.Text.StringBuilder
            
            $stdoutEvent = Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -Action {
                if ($null -ne $EventArgs.Data) {
                    $Event.MessageData.AppendLine($EventArgs.Data) | Out-Null
                }
            } -MessageData $stdoutBuilder
            
            $stderrEvent = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -Action {
                if ($null -ne $EventArgs.Data) {
                    $Event.MessageData.AppendLine($EventArgs.Data) | Out-Null
                }
            } -MessageData $stderrBuilder
            
            $proc.Start() | Out-Null
            $proc.BeginOutputReadLine()
            $proc.BeginErrorReadLine()
            
            $activeProcesses.Add(@{
                    Process       = $proc
                    FileName      = $fileName
                    FilePath      = $filePath
                    LogFile       = $logFile
                    StdoutBuilder = $stdoutBuilder
                    StderrBuilder = $stderrBuilder
                    StdoutEvent   = $stdoutEvent
                    StderrEvent   = $stderrEvent
                })
            $totalStarted++
            
            # Print progress periodically (every 50 files)
            if ($totalStarted % 50 -eq 0) {
                Write-Host "  Started $totalStarted / $($Files.Count) symchk processes..." -ForegroundColor Gray
            }
        }
        catch {
            Write-Warning "Failed to start symchk for '$filePath': $($_.Exception.Message)"
        }
    }
    
    # Wait for remaining active processes to finish
    if ($activeProcesses.Count -gt 0) {
        Write-Host "  Waiting for final $($activeProcesses.Count) symchk process(es)..."
    }
    
    foreach ($entry in $activeProcesses) {
        try {
            $entry.Process.WaitForExit()
        }
        catch {
            Write-Warning "Error waiting for symchk process: $($_.Exception.Message)"
        }
        
        $exitCode = $entry.Process.ExitCode
        
        # Write log files from captured output
        try { $entry.StdoutBuilder.ToString() | Out-File -FilePath $entry.LogFile -Encoding UTF8 -Force } catch { }
        $stderrContent = $entry.StderrBuilder.ToString()
        if (-not [string]::IsNullOrWhiteSpace($stderrContent)) {
            try { $stderrContent | Out-File -FilePath "$($entry.LogFile).err" -Encoding UTF8 -Force } catch { }
        }
        
        # Unregister events and dispose
        try { Unregister-Event -SourceIdentifier $entry.StdoutEvent.Name -ErrorAction SilentlyContinue } catch { }
        try { Unregister-Event -SourceIdentifier $entry.StderrEvent.Name -ErrorAction SilentlyContinue } catch { }
        try { $entry.Process.Dispose() } catch { }
        
        if ($exitCode -eq 0) {
            $succeeded++
        }
        else {
            $failed++
            Write-Host "  No symbols: $($entry.FileName) (exit code: $exitCode)" -ForegroundColor Yellow
        }
    }
    
    $downloadDuration = (Get-Date) - $downloadStartTime
    $durationStr = "{0:N1}" -f $downloadDuration.TotalMinutes
    Write-Host ""
    Write-Host "Symbol download completed in $durationStr minutes. $succeeded succeeded, $failed had no symbols available." -ForegroundColor Cyan
    if ($failed -gt 0) {
        Write-Host "Note: Missing symbols are normal - not all PE files have public symbols available." -ForegroundColor Yellow
    }
    Write-Host ""
}

# Determine IDA path: use provided path or auto-detect
if ($IdaPath) {
    # User provided explicit path
    $IDA_PATH = $IdaPath
    Write-Host "Using specified IDA Pro: $IDA_PATH" -ForegroundColor Green
}
else {
    # Auto-detect IDA installation
    $IDA_PATH = Find-LatestIDA
    if (-not $IDA_PATH) {
        Write-Error "Could not auto-detect IDA Pro installation."
        Write-Error "IDA Pro was not found via:"
        Write-Error "  - PATH environment variable (idat.exe, idat64.exe)"
        Write-Error "  - Windows Registry (HKLM/HKCU\SOFTWARE\Hex-Rays\IDA)"
        Write-Error "  - Standard installation directories:"
        Write-Error "    - C:\Program Files\IDA Professional 9.*"
        Write-Error "    - C:\Program Files\IDA Pro 9.*"
        Write-Error "    - C:\Tools\IDA*"
        Write-Error ""
        Write-Error "Please either:"
        Write-Error "  1. Add IDA Pro to your PATH environment variable, or"
        Write-Error "  2. Install IDA Pro 9.x to a standard location, or"
        Write-Error "  3. Specify the path manually with -IdaPath parameter"
        Write-Error ""
        Write-Error "Example: .\headless_batch_extractor.ps1 -ExtractDir 'C:\path' -StorageDir 'C:\output' -IdaPath 'D:\Custom\IDA\idat64.exe'"
        exit $script:EXIT_IDA_NOT_FOUND
    }
    
    Write-Host "Auto-detected IDA Pro: $IDA_PATH" -ForegroundColor Green
}

function Confirm-DirectoryExists {
    param([string]$path, [bool]$create = $false)
    
    if (-not (Test-Path $path)) {
        if ($create) {
            try {
                New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop | Out-Null
                Write-Host "Created directory: $path"
            }
            catch {
                Write-Error "Failed to create directory: $path"
                Write-Error $_.Exception.Message
                exit $script:EXIT_VALIDATION_ERROR
            }
        }
        else {
            Write-Error "Directory does not exist: $path"
            exit $script:EXIT_VALIDATION_ERROR
        }
    }
}

# Function to get candidate files by scanning a directory
function Get-CandidateFilesFromDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExtractDir,
        [Parameter()]
        [switch]$Recursive
    )

    Write-Host "Searching for files in: $ExtractDir"
    Write-Host "Recursive search: $($Recursive.IsPresent)"

    # List all .exe, .sys, and .dll files in the extract directory
    $searchParams = @{
        Path = $ExtractDir
        File = $true
    }
    if ($Recursive) {
        $searchParams['Recurse'] = $true
    }

    $allFiles = Get-ChildItem @searchParams | 
    Where-Object { $_.Extension.ToLower() -in '.exe', '.sys', '.dll' }

    Write-Host "Found $($allFiles.Count) total files matching extension criteria"
    return $allFiles
}

# Function to get candidate files from a list in a file
function Get-CandidateFilesFromFileList {
    param(
        [Parameter(Mandatory = $true)]
        [string]$filePath
    )

    Write-Host "Reading file list from: $filePath"
    $filePaths = Get-Content -Path $filePath
    $candidateFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    
    foreach ($path in $filePaths) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }
        $fileInfo = Get-Item -Path $path.Trim() -ErrorAction SilentlyContinue
        if ($fileInfo -and $fileInfo.Exists -and ($fileInfo.Extension.ToLower() -in '.exe', '.sys', '.dll')) {
            $candidateFiles.Add($fileInfo)
        }
        else {
            Write-Warning "Skipping invalid, non-existent, or non-matching file path from list: $path"
        }
    }
    Write-Host "Found $($candidateFiles.Count) valid files in the list."
    return [array]$candidateFiles
}

function Get-CandidateFilesFromPid {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId,
        [Parameter(Mandatory = $true)]
        [string]$StorageDir
    )

    Write-Host "Enumerating modules from process ID: $ProcessId"
    
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        Write-Host "Target process: $($process.ProcessName) (PID: $ProcessId)"
        
        # Get all loaded modules
        $modules = $process.Modules | Where-Object { 
            $_.FileName -match '\.(exe|dll|sys)$' -and 
            $_.FileName -notmatch '\\Windows\\Installer\\' # Skip temp installer files
        }
        
        if ($modules.Count -eq 0) {
            Write-Warning "No PE modules found for process $ProcessId"
            return @{
                Files       = @()
                ProcessName = $process.ProcessName
                ProcessId   = $ProcessId
            }
        }
        
        Write-Host "Found $($modules.Count) modules loaded by process"
        
        # Convert modules to FileInfo objects
        $candidateFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
        foreach ($module in $modules) {
            try {
                $fileInfo = Get-Item -Path $module.FileName -ErrorAction Stop
                $candidateFiles.Add($fileInfo)
            }
            catch {
                Write-Warning "Cannot access module file: $($module.FileName)"
            }
        }
        
        Write-Host "Ready to analyze $($candidateFiles.Count) modules"
        
        # Return structured result instead of using script-scoped side effects
        return @{
            Files       = [array]$candidateFiles
            ProcessName = $process.ProcessName
            ProcessId   = $ProcessId
        }
    }
    catch {
        Write-Error "Failed to enumerate modules from process $ProcessId : $($_.Exception.Message)"
        exit $script:EXIT_PERMISSION_ERROR
    }
}

# Function selects files that have not been analyzed yet from the candidate list
function Select-UnprocessedFiles {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo[]]$candidateFiles,
        [Parameter(Mandatory = $true)]
        [string]$StorageDir,
        [Parameter(Mandatory = $true)]
        [hashtable]$analysisFlags
    )
    
    if ($candidateFiles.Count -eq 0) {
        Write-Warning "No candidate files provided for processing!"
        return @()
    }
    
    # If forcing reanalysis, skip the check and return all candidates.
    if ($analysisFlags.force_reanalyze) {
        Write-Host "Forcing re-analysis for all $($candidateFiles.Count) candidate files."
        return $candidateFiles
    }

    $commonDbPath = Join-Path $StorageDir "analyzed_files.db"
    
    # Early check: If the database doesn't exist, all files need analysis
    # This avoids unnecessary processing and the "analyzing xx files" message
    try {
        if (-not (Test-Path $commonDbPath -PathType Leaf)) {
            Write-Host "No previous analysis database found at '$commonDbPath'. All $($candidateFiles.Count) candidate files will be analyzed."
            return $candidateFiles
        }
    }
    catch {
        Write-Warning "Error checking for analysis database at '$commonDbPath': $($_.Exception.Message)"
        Write-Host "Proceeding with analysis of all $($candidateFiles.Count) candidate files."
        return $candidateFiles
    }
    $checkerScriptPath = Join-Path $PSScriptRoot "deep_extract\utils\check_analyzed_files.py"

    # Convert flags to Base64-encoded JSON for command line
    $flagsJson = $analysisFlags | ConvertTo-Json -Compress
    $flagsJsonBytes = [System.Text.Encoding]::UTF8.GetBytes($flagsJson)
    $flagsJsonBase64 = [System.Convert]::ToBase64String($flagsJsonBytes)

    # Get the full paths of all candidate files and join them with newlines
    $candidatePaths = $candidateFiles.FullName -join [Environment]::NewLine

    Write-Host "Calling batch checker for $($candidateFiles.Count) files..."
    
    # Use & operator to capture output directly without Start-Process redirection conflicts
    $pythonCommand = "python.exe"
    $pythonArgs = @($checkerScriptPath, $commonDbPath, $flagsJsonBase64)
    
    try {
        $result = $candidatePaths | & $pythonCommand @pythonArgs 2>&1
        
        # Separate stdout and stderr from the combined result
        $stdOut = ""
        $stdErr = ""
        
        foreach ($line in $result) {
            if ($line -is [System.Management.Automation.ErrorRecord]) {
                $stdErr += $line.ToString() + [Environment]::NewLine
            }
            else {
                $stdOut += $line.ToString() + [Environment]::NewLine
            }
        }
        
        if (-not [string]::IsNullOrWhiteSpace($stdErr)) {
            Write-Warning "The following messages were reported by the Python checker script:"
            Write-Warning $stdErr.Trim()
        }

        $filesToProcessPaths = $stdOut -split '[\r\n]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    }
    catch {
        Write-Error "Failed to run Python checker script: $($_.Exception.Message)"
        Write-Error "Ensure Python is installed and accessible in PATH."
        Write-Error "Cannot safely determine which files need analysis - aborting to prevent re-analyzing already processed files."
        Write-Error "If you want to force re-analysis of all files, use the -ForceReanalyze parameter."
        exit $script:EXIT_PYTHON_ERROR
    }

    $filesToProcess = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $skippedCount = 0
    foreach ($path in $filesToProcessPaths) {
        try {
            $fileInfo = Get-Item -Path $path -ErrorAction Stop
            $filesToProcess.Add($fileInfo)
        }
        catch {
            # File may have been deleted between Python check and now, or is inaccessible
            Write-Warning "Cannot access file '$path': $($_.Exception.Message)"
            $skippedCount++
        }
    }

    if ($skippedCount -gt 0) {
        Write-Warning "Skipped $skippedCount file(s) that became inaccessible during processing."
    }
    Write-Host "Found $($filesToProcess.Count) files requiring analysis after filtering."
    return [array]$filesToProcess
}

function Confirm-RequiredPaths {
    param(
        [Parameter(Mandatory = $false)][string]$ExtractDir,
        [Parameter(Mandatory = $true)][string]$StorageDir
    )
    
    Write-Host "Using storage directory: $StorageDir"
    
    if (-not ([string]::IsNullOrEmpty($ExtractDir))) {
        Confirm-DirectoryExists -path $ExtractDir -create $false
    }

    # Create storage directory and subdirectories
    Confirm-DirectoryExists -path $StorageDir -create $true
    Confirm-DirectoryExists -path (Join-Path $StorageDir "extracted_dbs") -create $true
    Confirm-DirectoryExists -path (Join-Path $StorageDir "extracted_code") -create $true
    Confirm-DirectoryExists -path (Join-Path $StorageDir "logs") -create $true
    Confirm-DirectoryExists -path (Join-Path $StorageDir "idb_cache") -create $true
    
    Write-Host "SQLite databases will be stored in: $(Join-Path $StorageDir 'extracted_dbs')"
    Write-Host "Generated C++ code will be stored in: $(Join-Path $StorageDir 'extracted_code')"
    Write-Host "IDA logs will be stored in: $(Join-Path $StorageDir 'logs')"
    Write-Host "IDA databases (.i64) will be stored in: $(Join-Path $StorageDir 'idb_cache')"
}

$script:ActiveIdaProcesses = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()

# Cleanup function to terminate all active IDA processes
function Stop-AllIdaProcesses {
    param(
        [string]$reason = "Script termination"
    )
    
    if ($script:ActiveIdaProcesses.Count -eq 0) {
        return
    }
    
    Write-Warning "Cleanup triggered: $reason"
    Write-Warning "Terminating $($script:ActiveIdaProcesses.Count) active IDA process(es)..."
    
    foreach ($process in $script:ActiveIdaProcesses) {
        try {
            if (-not $process.HasExited) {
                Write-Warning "  Stopping PID $($process.Id)..."
                $process.Kill()
                $null = $process.WaitForExit($script:PROCESS_CLEANUP_WAIT_MS)
            }
        }
        catch {
            # Process may have already exited
            Write-Warning "  Could not stop PID $($process.Id): $($_.Exception.Message)"
        }
    }
    
    $script:ActiveIdaProcesses.Clear()
    Write-Warning "Cleanup completed."
}

# Register cleanup handler for PowerShell engine exit
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    Stop-AllIdaProcesses -reason "PowerShell exiting"
}

# Set up trap for script termination (Ctrl+C, errors, etc.)
# This complements the try/finally blocks in the main execution
trap {
    Stop-AllIdaProcesses -reason "Script terminated unexpectedly: $($_.Exception.Message)"
    # Re-throw to allow normal error handling
    break
}

function Update-CompletedProcessInfo {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[System.Diagnostics.Process]]$processes,
        [Parameter(Mandatory = $true)]
        [hashtable]$processInfo
    )
    
    foreach ($p in $processes) {
        if ($p.HasExited) {
            $info = $processInfo[$p.BaseName]
            if ($info -and -not $info.ContainsKey('ExitCode')) {
                # Capture exit code and duration while process object is still valid
                try {
                    $info['ExitCode'] = $p.ExitCode
                    $info['CompletedTime'] = Get-Date
                    # Calculate and store duration in minutes
                    if ($info.StartTime) {
                        $info['DurationMinutes'] = ($info['CompletedTime'] - $info['StartTime']).TotalMinutes
                    }
                    
                    # Log completion notification
                    $fileName = [System.IO.Path]::GetFileName($info.FileName)
                    $durationStr = if ($info.DurationMinutes) { 
                        "{0:N1} minutes" -f $info.DurationMinutes 
                    }
                    else { 
                        "unknown duration" 
                    }
                    
                    if ($p.ExitCode -eq 0) {
                        Write-Host "Completed: $fileName (PID $($p.Id)) in $durationStr - Exit code: 0" -ForegroundColor Green
                    }
                    else {
                        Write-Host "Completed: $fileName (PID $($p.Id)) in $durationStr - Exit code: $($p.ExitCode)" -ForegroundColor Yellow
                    }
                }
                catch {
                    # Process object may be in an invalid state
                    Write-Warning "Could not retrieve exit code for PID $($p.Id): $($_.Exception.Message)"
                    $info['ExitCode'] = -1  # Mark as unknown failure
                    $info['ExitCodeError'] = $_.Exception.Message
                }
            }
        }
    }
}

# Helper function to check for and kill timed-out processes
# Returns an array of process IDs that were timed out and removed
function Test-ProcessTimeouts {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[System.Diagnostics.Process]]$processes,
        [Parameter(Mandatory = $true)]
        [hashtable]$processInfo,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[hashtable]]$timedOutFiles,
        [Parameter(Mandatory = $true)]
        [int]$timeoutSeconds
    )
    
    # First, capture exit codes for any completed processes before we filter
    Update-CompletedProcessInfo -processes $processes -processInfo $processInfo
    
    $currentTime = Get-Date
    # Collect processes to remove (iterate over a copy to avoid modification during enumeration)
    $processesToRemove = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
    
    foreach ($p in $processes) {
        if (-not $p.HasExited) {
            $info = $processInfo[$p.BaseName]
            if ($info -and $info.StartTime) {
                $elapsed = ($currentTime - $info.StartTime).TotalSeconds
                if ($elapsed -ge $timeoutSeconds) {
                    Write-Warning "Process for '$($info.FileName)' exceeded timeout of $($timeoutSeconds / 3600) hours (elapsed: $([math]::Round($elapsed / 3600, 2)) hours). Terminating..."
                    try {
                        $p.Kill()
                        $null = $p.WaitForExit($script:PROCESS_KILL_WAIT_MS)
                    }
                    catch {
                        Write-Warning "Failed to gracefully terminate process $($p.Id), attempting force kill..."
                        try {
                            Stop-Process -Id $p.Id -Force -ErrorAction Stop
                        }
                        catch {
                            Write-Error "Could not kill process $($p.Id): $($_.Exception.Message)"
                        }
                    }
                    
                    $info['TimedOut'] = $true
                    $info['ExitCode'] = -999  # Special code for timeout
                    
                    # Record the timed-out file
                    $timedOutFiles.Add(@{
                            FileName    = $info.FileName
                            LogFile     = $info.LogFile
                            ElapsedTime = [math]::Round($elapsed / 3600, 2)
                            Reason      = "Exceeded timeout of $($timeoutSeconds / 3600) hours"
                        })
                    
                    $processesToRemove.Add($p)
                }
            }
        }
    }
    
    # Remove timed-out processes from the active list (safe: iterating over separate list)
    foreach ($p in $processesToRemove) {
        $processes.Remove($p) | Out-Null
        # Also remove from global tracking
        $script:ActiveIdaProcesses.Remove($p) | Out-Null
    }
}

function Start-IDAProcesses {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo[]]$files,
        [Parameter(Mandatory = $true)]
        [string]$IDA_PATH,
        [Parameter(Mandatory = $true)]
        [string]$StorageDir,
        [int]$MaxConcurrent,
        [Parameter(Mandatory = $true)]
        [hashtable]$analysisFlags
    )

    # Get directory paths
    $extractedDbsDir = Join-Path $StorageDir "extracted_dbs"
    $extractedCodeDir = Join-Path $StorageDir "extracted_code"
    $logsDir = Join-Path $StorageDir "logs"
    $idbCacheDir = Join-Path $StorageDir "idb_cache"
    
    # Note: Directory locations already printed by Confirm-RequiredPaths
    Write-Host "Process timeout set to: $($script:IDA_PROCESS_TIMEOUT_SECONDS / 3600) hours" -ForegroundColor Yellow
    
    # Use Generic.List to store process objects
    $processes = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
    $processInfo = @{}
    $timedOutFiles = [System.Collections.Generic.List[hashtable]]::new()
    
    # Track total files attempted for accurate reporting (separate from $processes which gets filtered)
    $totalFilesAttempted = 0
    $batchStartTime = Get-Date

    # Track files that couldn't be processed due to access issues
    $skippedFiles = @()
    
    foreach ($file in $files) {
        # Create a hash of the full path for uniqueness
        try {
            $pathHash = Get-FileHash -Path $file.FullName -Algorithm MD5 -ErrorAction Stop
            $shortHash = $pathHash.Hash.Substring(0, $script:HASH_PREFIX_LENGTH)
        }
        catch {
            Write-Warning "Cannot compute hash for '$($file.FullName)': $($_.Exception.Message)"
            Write-Warning "  Skipping this file (may be locked or inaccessible)."
            $skippedFiles += @{
                FileName = $file.FullName
                Reason   = "Cannot compute file hash: $($_.Exception.Message)"
            }
            continue
        }
        
        # Construct unique base name using filename and hash
        $baseNameForPaths = "$($file.Name.Replace('.', '_'))_$shortHash".ToLower()

        # Use the proper directories for SQLite DB and IDB paths
        $dbPath = Join-Path $extractedDbsDir "$baseNameForPaths.db"
        $idbPath = Join-Path $idbCacheDir "$baseNameForPaths.i64"
        
        Write-Host "Starting processing of $($file.FullName)"
        Write-Host "SQLite Database will be stored at: $dbPath"
        Write-Host "IDA Database (.i64) will be stored at: $idbPath"
        
        while ($processes.Count -ge $MaxConcurrent) {
            # Check for timed-out processes and kill them (also captures exit codes for completed processes)
            Test-ProcessTimeouts -processes $processes -processInfo $processInfo -timedOutFiles $timedOutFiles -timeoutSeconds $script:IDA_PROCESS_TIMEOUT_SECONDS
            
            # Remove completed processes from the active list (create new list to avoid modification during iteration)
            $stillRunning = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
            foreach ($p in $processes) {
                if (-not $p.HasExited) {
                    $stillRunning.Add($p)
                }
                else {
                    # Remove completed process from global tracking and dispose
                    $script:ActiveIdaProcesses.Remove($p) | Out-Null
                    try { $p.Dispose() } catch { }
                }
            }
            $processes = $stillRunning
            Start-Sleep -Seconds 1
        }
        
        # Include hash in log filename to correlate with DB files (Issue: log naming consistency)
        try {
            $logFile = Join-Path $logsDir "${baseNameForPaths}_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            
            $processArgs = [System.Collections.Generic.List[string]]::new()
            
            # Always use -B for batch creation/processing
            $processArgs.Add('-B')
            
            # Add the -o argument for the IDB path
            # Use explicit string concatenation for clarity with paths that may contain spaces
            $processArgs.Add('-o"' + $idbPath + '"')
            
            # Construct analysis flags for the IDA script
            # IDA's -S argument passes the script path and args to the script interpreter.
            # Use backslash-escaped quotes (\") for paths inside -S that need to survive
            # through IDA's parsing to reach Python's argparse.
            # NOTE: analysisFlags uses snake_case keys with ENABLED state (true = feature enabled)
            #       We pass --no-* flags when the feature is DISABLED (value is $false)
            $idaScriptArgs = [System.Collections.Generic.List[string]]::new()
            $idaScriptArgs.Add("--sqlite-db")
            $idaScriptArgs.Add('\"' + $dbPath + '\"')
            
            if (-not $analysisFlags.extract_dangerous_apis) { $idaScriptArgs.Add("--no-extract-dangerous-apis") }
            if (-not $analysisFlags.extract_strings) { $idaScriptArgs.Add("--no-extract-strings") }
            if (-not $analysisFlags.extract_stack_frame) { $idaScriptArgs.Add("--no-extract-stack-frame") }
            if (-not $analysisFlags.extract_globals) { $idaScriptArgs.Add("--no-extract-globals") }
            if (-not $analysisFlags.analyze_loops) { $idaScriptArgs.Add("--no-analyze-loops") }
            if (-not $analysisFlags.extract_pe_info) { $idaScriptArgs.Add("--no-pe-info") }
            if (-not $analysisFlags.extract_pe_metadata) { $idaScriptArgs.Add("--no-pe-metadata") }
            if (-not $analysisFlags.extract_advanced_pe) { $idaScriptArgs.Add("--no-advanced-pe") }
            if (-not $analysisFlags.extract_runtime_info) { $idaScriptArgs.Add("--no-runtime-info") }
            if ($analysisFlags.force_reanalyze) { $idaScriptArgs.Add("--force-reanalyze") }
            if ($analysisFlags.generate_cpp) { 
                $idaScriptArgs.Add("--generate-cpp")
                $idaScriptArgs.Add("--cpp-output-dir")
                # Use backslash-escaped quotes for the path (survives IDA's command parsing)
                $idaScriptArgs.Add('\"' + $extractedCodeDir + '\"')
            }
            
            # Use full path to main.py (already validated at script startup)
            $mainPyPath = Join-Path $PSScriptRoot "main.py"
            $idaScriptCommand = '\"' + $mainPyPath + '\" ' + ($idaScriptArgs -join ' ')

            # Add remaining arguments individually (AddRange requires explicit string[] cast in PowerShell)
            # Use explicit string concatenation for clarity with paths that may contain spaces
            $processArgs.Add('-A')
            $processArgs.Add('-S"' + $idaScriptCommand + '"')
            $processArgs.Add('-L"' + $logFile + '"')
            $processArgs.Add('"' + $file.FullName + '"')
            
            $commandLine = "$IDA_PATH $($processArgs -join ' ')"
            # Use verbose-style gray for command output to keep the main log clean
            Write-Host "Running: $commandLine" -ForegroundColor Gray
            
            # Use Hidden instead of Minimized for headless/CI compatibility
            $process = Start-Process -FilePath $IDA_PATH -ArgumentList $processArgs -PassThru -WindowStyle Hidden
            $process | Add-Member -NotePropertyName "BaseName" -NotePropertyValue $baseNameForPaths
            $startTime = Get-Date
            
            $processInfo[$baseNameForPaths] = @{
                'FileName'    = $file.FullName
                'BaseName'    = $baseNameForPaths
                'DbPath'      = $dbPath
                'CommandLine' = $commandLine
                'LogFile'     = $logFile
                'IdbPath'     = $idbPath
                'StartTime'   = $startTime
                'Pid'         = $process.Id
            }
            
            $processes.Add($process)
            # Track process globally for cleanup on script interruption
            $script:ActiveIdaProcesses.Add($process)
            # Track that we've successfully started processing this file
            $totalFilesAttempted++
            
            Write-Host "Started IDA process for $($file.FullName) (PID: $($process.Id))"
            Write-Host "Log file: $logFile"
            Write-Host "IDB file: $idbPath"
        }
        catch {
            Write-Error "Failed to start IDA process for $($file.FullName)"
            Write-Error $_.Exception.Message
            # Still count this as attempted even if it failed to start
            $totalFilesAttempted++
            continue
        }
    }
    
    # Wait for all IDA processes to complete (outside the foreach loop)
    Write-Host "Waiting for all IDA processes to complete..."
    $lastStatusTime = Get-Date
    while ($processes | Where-Object { -not $_.HasExited }) {
        # Check for timed-out processes (also captures exit codes for completed processes)
        Test-ProcessTimeouts -processes $processes -processInfo $processInfo -timedOutFiles $timedOutFiles -timeoutSeconds $script:IDA_PROCESS_TIMEOUT_SECONDS
        
        # Get active processes for status display
        $activeProcesses = $processes | Where-Object { -not $_.HasExited }
        $runningCount = @($activeProcesses).Count
        
        # Output status at configured interval to avoid spam but keep user informed
        $currentTime = Get-Date
        if (($currentTime - $lastStatusTime).TotalSeconds -ge $script:STATUS_UPDATE_INTERVAL_SECONDS) {
            if ($runningCount -gt 0) {
                # Calculate progress: completed = total started - still running
                $completedCount = $totalFilesAttempted - $runningCount
                Write-Host "[$completedCount/$totalFilesAttempted completed] Still running: $runningCount processes..."
                # Show status of all running processes
                foreach ($p in $activeProcesses) {
                    $info = $processInfo[$p.BaseName]
                    if ($info -and $info.StartTime) {
                        $elapsed = [math]::Round(($currentTime - $info.StartTime).TotalMinutes, 1)
                        Write-Host "  PID $($p.Id): $([System.IO.Path]::GetFileName($info.FileName)) - running for $elapsed minutes"
                    }
                }
            }
            $lastStatusTime = $currentTime
        }
        
        Start-Sleep -Seconds $script:PROCESS_POLL_INTERVAL_SECONDS
    }
    
    # Final pass: capture exit codes for all remaining completed processes
    Update-CompletedProcessInfo -processes $processes -processInfo $processInfo
    
    # Dispose all process objects now that we've captured their exit codes
    foreach ($p in $processes) {
        try { $p.Dispose() } catch { }
    }

    # Collect results for report by iterating over processInfo (reliable source of all started processes)
    # Exit codes are now stored in processInfo, so we don't need to find the process objects
    $successfulFiles = [System.Collections.Generic.List[hashtable]]::new()
    $failedFiles = [System.Collections.Generic.List[hashtable]]::new()
    
    foreach ($entry in $processInfo.GetEnumerator()) {
        $info = $entry.Value
        
        # Skip if this file was already recorded as timed out
        if ($info.ContainsKey('TimedOut') -and $info.TimedOut) {
            continue
        }
        
        # Get the exit code from processInfo (captured earlier by Update-CompletedProcessInfo)
        $exitCode = if ($info.ContainsKey('ExitCode')) { $info.ExitCode } else { -1 }
        
        if ($exitCode -eq 0) {
            $successfulFiles.Add(@{
                    FileName = $info.FileName
                    DbPath   = $info.DbPath
                    IdbPath  = $info.IdbPath
                    LogFile  = $info.LogFile
                })
        }
        else {
            $failedFiles.Add(@{
                    FileName = $info.FileName
                    ExitCode = $exitCode
                    LogFile  = $info.LogFile
                })
        }
    }
    
    # Report skipped files (couldn't access for hashing) - these aren't in timing summary
    if ($skippedFiles.Count -gt 0) {
        Write-Warning "Some files were skipped (could not access for processing):"
        foreach ($skipped in $skippedFiles) {
            Write-Warning "  Skipped: $($skipped.FileName)"
            Write-Warning "    Reason: $($skipped.Reason)"
        }
        Write-Host ""
    }
    
    # Clear global process tracking - all processes have completed
    $script:ActiveIdaProcesses.Clear()
    
    $batchEndTime = Get-Date
    $batchDurationMinutes = ($batchEndTime - $batchStartTime).TotalMinutes
    
    return @{
        SuccessfulFiles      = [array]$successfulFiles
        FailedFiles          = [array]$failedFiles
        TimedOutFiles        = [array]$timedOutFiles
        SkippedFiles         = $skippedFiles
        # Use totalFilesAttempted which accurately tracks all files we tried to process
        # (includes successful, failed, timed out; skippedFiles are counted separately as they never started)
        TotalProcessed       = $totalFilesAttempted + $skippedFiles.Count
        BatchDurationMinutes = $batchDurationMinutes
        # Include process info for timing summary
        ProcessInfo          = $processInfo
    }
}

# Test-AdminPrivileges: Verifies the script is running with administrator privileges
# Uses approved PowerShell verb 'Test' which returns boolean or validates a condition
function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Error "This script requires administrator privileges. Please run PowerShell as Administrator."
        exit $script:EXIT_PERMISSION_ERROR
    }
}

# Function to generate extraction report
function Write-ExtractionReport {
    param(
        [Parameter(Mandatory = $true)][string]$StorageDir,
        [Parameter(Mandatory = $true)][hashtable]$results,
        [Parameter(Mandatory = $false)][string]$mode,
        [Parameter(Mandatory = $false)][int]$targetPid,
        [Parameter(Mandatory = $false)][string]$processName
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'
    
    # Safely get counts (handle null arrays)
    $timedOutCount = if ($results.TimedOutFiles) { $results.TimedOutFiles.Count } else { 0 }
    $skippedCount = if ($results.SkippedFiles) { $results.SkippedFiles.Count } else { 0 }
    
    $report = @{
        extraction_info        = @{
            timestamp         = $timestamp
            mode              = $mode
            storage_directory = $StorageDir
            timeout_hours     = $script:IDA_PROCESS_TIMEOUT_SECONDS / 3600
        }
        summary                = @{
            total_files = $results.TotalProcessed
            successful  = $results.SuccessfulFiles.Count
            failed      = $results.FailedFiles.Count
            timed_out   = $timedOutCount
            skipped     = $skippedCount
        }
        successful_extractions = $results.SuccessfulFiles
        failed_extractions     = $results.FailedFiles
        timed_out_extractions  = $results.TimedOutFiles
        skipped_files          = $results.SkippedFiles
    }
    
    # Add PID-specific info if applicable
    if ($mode -eq 'Pid' -and $targetPid) {
        $report.extraction_info.target_pid = $targetPid
        $report.extraction_info.process_name = $processName
    }
    
    $reportPath = Join-Path $StorageDir "extraction_report.json"
    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8
    
    Write-Host "Extraction report saved to: $reportPath"
    return $reportPath
}

# Function to format duration in human-readable format
function Format-Duration {
    param(
        [Parameter(Mandatory = $true)]
        [double]$Minutes
    )
    
    if ($Minutes -ge 60) {
        $hours = [math]::Floor($Minutes / 60)
        $mins = [math]::Round($Minutes % 60)
        return "${hours}h ${mins}m"
    }
    elseif ($Minutes -ge 1) {
        return "$([math]::Round($Minutes, 1)) min"
    }
    else {
        $seconds = [math]::Round($Minutes * 60)
        return "${seconds}s"
    }
}

# Function to display timing summary
function Write-TimingSummary {
    param(
        [Parameter(Mandatory = $true)]
        $processInfo,
        [Parameter(Mandatory = $true)]
        $results,
        [Parameter(Mandatory = $true)]
        [int]$timeoutSeconds
    )
    
    # Validate inputs
    if ($null -eq $processInfo -or $processInfo.Count -eq 0) {
        Write-Host "No timing data available." -ForegroundColor Yellow
        return
    }
    
    # Collect timing data from all processes
    $timingData = [System.Collections.Generic.List[PSCustomObject]]::new()
    
    foreach ($entry in $processInfo.GetEnumerator()) {
        $info = $entry.Value
        $fileName = [System.IO.Path]::GetFileName($info.FileName)
        if ([string]::IsNullOrWhiteSpace($fileName)) {
            $fileName = "<unknown>"
        }
        
        # Determine status
        $status = "completed"
        if ($info.ContainsKey('TimedOut') -and $info.TimedOut) {
            $status = "timeout"
        }
        elseif ($info.ContainsKey('ExitCode') -and $info.ExitCode -ne 0) {
            $status = "failed, exit code $($info.ExitCode)"
        }
        
        # Get duration (use stored value or calculate from timeout)
        $durationMinutes = 0
        if ($info.ContainsKey('DurationMinutes')) {
            $durationMinutes = $info.DurationMinutes
        }
        elseif ($info.ContainsKey('TimedOut') -and $info.TimedOut) {
            $durationMinutes = $timeoutSeconds / 60
        }
        
        $timingData.Add([PSCustomObject]@{
                FileName        = $fileName
                DurationMinutes = $durationMinutes
                Status          = $status
            })
    }
    
    # Sort by duration descending - ensure always an array
    $sortedData = @($timingData | Sort-Object -Property DurationMinutes -Descending)
    
    # Calculate statistics
    $totalModules = $sortedData.Count
    if ($totalModules -eq 0) {
        Write-Host "No timing data collected." -ForegroundColor Yellow
        return
    }
    
    $completedCount = if ($results.SuccessfulFiles) { $results.SuccessfulFiles.Count } else { 0 }
    $failedCount = if ($results.FailedFiles) { $results.FailedFiles.Count } else { 0 }
    $timedOutCount = if ($results.TimedOutFiles) { $results.TimedOutFiles.Count } else { 0 }
    
    # Ensure durations is always an array (single values need @() wrapper)
    $durations = @($sortedData.DurationMinutes)
    $totalMinutes = ($durations | Measure-Object -Sum).Sum
    $avgMinutes = $totalMinutes / $totalModules
    
    # Calculate wall-clock time if available
    $wallClockMinutes = if ($results.BatchDurationMinutes) { $results.BatchDurationMinutes } else { 0 }
    
    # Calculate median
    $sortedDurations = @($durations | Sort-Object)
    if ($totalModules -eq 1) {
        $medianMinutes = $sortedDurations[0]
    }
    elseif ($totalModules % 2 -eq 0) {
        $medianIdx = [int]($totalModules / 2)
        $medianMinutes = ($sortedDurations[$medianIdx - 1] + $sortedDurations[$medianIdx]) / 2
    }
    else {
        $medianMinutes = $sortedDurations[[math]::Floor($totalModules / 2)]
    }
    
    # Output summary
    Write-Host ""
    Write-Host "=== Module Timing Summary ===" -ForegroundColor Cyan
    
    # Only show timeout warning if any modules timed out
    if ($timedOutCount -gt 0) {
        Write-Host "WARNING: $timedOutCount module(s) exceeded $($timeoutSeconds / 3600)-hour timeout and were terminated" -ForegroundColor Yellow
        foreach ($item in $sortedData) {
            if ($item.Status -eq "timeout") {
                Write-Host "  $($item.FileName): $(Format-Duration $item.DurationMinutes) (timeout)" -ForegroundColor Yellow
            }
        }
        Write-Host ""
    }
    
    Write-Host "Completed: $completedCount | Failed: $failedCount | Timed out: $timedOutCount"
    $elapsedLabel = if ($wallClockMinutes -gt 0) { Format-Duration $wallClockMinutes } else { "n/a" }
    $statsLine = "Elapsed (wall-clock): $elapsedLabel | Total analysis time: $(Format-Duration $totalMinutes) | Average: $(Format-Duration $avgMinutes) | Median: $(Format-Duration $medianMinutes)"
    Write-Host $statsLine
    Write-Host ""
    Write-Host "All modules (sorted by duration):"
    
    # Find the longest filename for alignment (measure by length, not lexicographic max)
    $maxLen = ($sortedData | ForEach-Object { $_.FileName.Length } | Measure-Object -Maximum).Maximum
    if ($maxLen -lt 20) { $maxLen = 20 }

    foreach ($item in $sortedData) {
        $durationStr = "{0,10}" -f (Format-Duration $item.DurationMinutes)
        $padding = " " * [math]::Max(0, $maxLen - $item.FileName.Length)
        $outputLine = "  $($item.FileName):$padding $durationStr"
        
        if ($item.Status -eq "completed") {
            Write-Host $outputLine
        }
        elseif ($item.Status -eq "timeout") {
            Write-Host "$outputLine (timeout)" -ForegroundColor Yellow
        }
        else {
            Write-Host "$outputLine ($($item.Status))" -ForegroundColor Red
        }
    }
}

################################################################
# Main work starts here
################################################################

# Check admin privileges (only required for PID mode)
if ($PSCmdlet.ParameterSetName -eq 'Pid') {
    Test-AdminPrivileges
}

# Pre-flight check: Verify Python is installed and accessible
Write-Host "Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = & python.exe --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Python returned non-zero exit code"
    }
    Write-Host "Found Python: $pythonVersion" -ForegroundColor Green
}
catch {
    Write-Error "Python is not installed or not accessible in PATH."
    Write-Error "Please install Python 3.x and ensure 'python.exe' is available in your system PATH."
    Write-Error "Download Python from: https://www.python.org/downloads/"
    exit $script:EXIT_PYTHON_ERROR
}

# Validate required scripts exist before proceeding
$mainPyPath = Join-Path $PSScriptRoot "main.py"
if (-not (Test-Path $mainPyPath -PathType Leaf)) {
    Write-Error "Required script 'main.py' not found at: $mainPyPath"
    Write-Error "Ensure you are running this script from the DeepExtract installation directory."
    exit $script:EXIT_SCRIPT_MISSING
}
Write-Host "Found IDA analysis script: $mainPyPath" -ForegroundColor Green

$checkerScriptPath = Join-Path $PSScriptRoot "deep_extract\utils\check_analyzed_files.py"
if (-not (Test-Path $checkerScriptPath -PathType Leaf)) {
    Write-Error "Required script 'check_analyzed_files.py' not found at: $checkerScriptPath"
    Write-Error "Ensure you are running this script from the DeepExtract installation directory."
    exit $script:EXIT_SCRIPT_MISSING
}
Write-Host "Found file checker script: $checkerScriptPath" -ForegroundColor Green

# Pre-flight check: Verify symchk.exe if symbol downloading is enabled
$script:downloadSymbolsEnabled = -not $NoDownloadSymbols.IsPresent
$script:SYMCHK_PATH = $null

if ($script:downloadSymbolsEnabled) {
    if ($SymchkPath) {
        $script:SYMCHK_PATH = $SymchkPath
        Write-Host "Using specified symchk.exe: $($script:SYMCHK_PATH)" -ForegroundColor Green
    }
    else {
        $script:SYMCHK_PATH = Find-Symchk
        if (-not $script:SYMCHK_PATH) {
            Write-Warning "Could not find symchk.exe. Symbol downloading will be skipped."
            Write-Warning "To enable symbol downloading, install Windows SDK Debugging Tools or specify -SymchkPath."
            Write-Warning "  Download from: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/"
            Write-Warning "  Or specify:    -SymchkPath 'C:\path\to\symchk.exe'"
            $script:downloadSymbolsEnabled = $false
        }
        else {
            Write-Host "Auto-detected symchk.exe: $($script:SYMCHK_PATH)" -ForegroundColor Green
        }
    }
}
else {
    Write-Host "Symbol downloading disabled (-NoDownloadSymbols)." -ForegroundColor Gray
}

# Ensure required directories exist
# Pass ExtractDir for validation if in Directory mode
if ($PSCmdlet.ParameterSetName -eq 'Directory') {
    Confirm-RequiredPaths -ExtractDir $ExtractDir -StorageDir $StorageDir
}
else {
    Confirm-RequiredPaths -StorageDir $StorageDir
}

# Prepare Analysis Flags
# These flags are passed to both the checker and the IDA script for consistency.
$analysisFlags = @{
    extract_dangerous_apis = -not $NoExtractDangerousApis.IsPresent
    extract_strings        = -not $NoExtractStrings.IsPresent
    extract_stack_frame    = -not $NoExtractStackFrame.IsPresent
    extract_globals        = -not $NoExtractGlobals.IsPresent
    analyze_loops          = -not $NoAnalyzeLoops.IsPresent
    extract_pe_info        = -not $NoPeInfo.IsPresent
    extract_pe_metadata    = -not $NoPeMetadata.IsPresent
    extract_advanced_pe    = -not $NoAdvancedPe.IsPresent
    extract_runtime_info   = -not $NoRuntimeInfo.IsPresent
    force_reanalyze        = $ForceReanalyze.IsPresent
    generate_cpp           = -not $NoGenerateCpp.IsPresent
}

# Determine which files to analyze based on the parameter set used
$candidateFiles = @()
$pidModeInfo = $null  # Store process info for PID mode reporting

if ($PSCmdlet.ParameterSetName -eq 'Directory') {
    # ExtractDir already validated in Confirm-RequiredPaths above
    if ($Recursive) {
        $candidateFiles = Get-CandidateFilesFromDirectory -ExtractDir $ExtractDir -Recursive
    }
    else {
        $candidateFiles = Get-CandidateFilesFromDirectory -ExtractDir $ExtractDir
    }
}
elseif ($PSCmdlet.ParameterSetName -eq 'FileList') {
    $candidateFiles = Get-CandidateFilesFromFileList -filePath $FilesToAnalyze
}
elseif ($PSCmdlet.ParameterSetName -eq 'Pid') {
    # Get-CandidateFilesFromPid returns a structured hashtable with Files, ProcessName, ProcessId
    $pidModeInfo = Get-CandidateFilesFromPid -ProcessId $TargetPid -StorageDir $StorageDir
    $candidateFiles = $pidModeInfo.Files
}

# Filter out files that have already been analyzed
$files = Select-UnprocessedFiles -candidateFiles $candidateFiles -StorageDir $StorageDir -analysisFlags $analysisFlags

# Symbol Download Phase
# Download symbols for the files that will be analyzed (before IDA starts)
if ($script:downloadSymbolsEnabled -and $files.Count -gt 0) {
    # Set _NT_SYMBOL_PATH environment variable (user-level + current process)
    Set-SymbolPath -SymbolStorePath $SymbolStorePath -SymbolServerUrl $SymbolServerUrl
    
    # Download symbols using symchk
    $logsDir = Join-Path $StorageDir "logs"
    Start-SymbolDownload -Files $files -SymchkExePath $script:SYMCHK_PATH `
        -SymbolStorePath $SymbolStorePath -SymbolServerUrl $SymbolServerUrl `
        -LogsDir $logsDir
}

if ($files.Count -gt 0) {
    # Export the list of files that will be analyzed to analyzed_modules_list.txt
    $analyzedListPath = Join-Path $StorageDir "analyzed_modules_list.txt"
    $files | ForEach-Object { $_.FullName } | Out-File -FilePath $analyzedListPath -Encoding UTF8
    Write-Host "Analyzed modules list exported to: $analyzedListPath"
    
    try {
        $results = Start-IDAProcesses `
            -files $files `
            -IDA_PATH $IDA_PATH `
            -StorageDir $StorageDir `
            -MaxConcurrent $MaxConcurrentProcesses `
            -analysisFlags $analysisFlags
        
        # Generate extraction report
        $reportParams = @{
            storageDir = $StorageDir
            results    = $results
            mode       = $PSCmdlet.ParameterSetName
        }
        
        if ($PSCmdlet.ParameterSetName -eq 'Pid' -and $null -ne $pidModeInfo) {
            $reportParams.targetPid = $pidModeInfo.ProcessId
            $reportParams.processName = $pidModeInfo.ProcessName
        }
        
        $reportPath = Write-ExtractionReport @reportParams
        
        # Display timing summary for all modules
        if ($results.ProcessInfo -and $results.ProcessInfo.Count -gt 0) {
            Write-TimingSummary -processInfo $results.ProcessInfo -results $results -timeoutSeconds $script:IDA_PROCESS_TIMEOUT_SECONDS
        }
    }
    finally {
        # Ensure cleanup of any remaining IDA processes on script termination (Ctrl+C, errors, etc.)
        if ($script:ActiveIdaProcesses.Count -gt 0) {
            Stop-AllIdaProcesses -reason "Script termination or interruption"
        }
    }
}
else {
    Write-Host "No files to process. Skipping IDA analysis."
}

Write-Host ""
Write-Host "Script execution completed successfully"
