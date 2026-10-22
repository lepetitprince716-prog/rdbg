Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$ConfirmPreference = 'None'

# rdbg comfy: one fixed ComfyUI service action per run. Windows PowerShell 5.1.
# The prefix sets $ComfyPort, $ExpectedService, $ExpectedComfyVersion, $CanonicalPython,
# $Action, $ComfyRoot, $ComfyListen, $ComfyArgs, $ShawlExe, $ShawlSha256 and $StartType.
# The script never prompts, never elevates and never kills a process. It prints exactly
# one JSON line: the rdbg.comfy.<action>.v1 observation.

$script:Clock = [System.Diagnostics.Stopwatch]::StartNew()
$script:Reasons = New-Object System.Collections.Generic.List[string]
$PollSeconds = 2
$StopTimeoutMs = 30000
$ConflictScanMaxBytes = 64KB

function Add-Reason {
    param([Parameter(Mandatory = $true)][string]$Reason)
    if (-not $script:Reasons.Contains($Reason)) {
        $script:Reasons.Add($Reason)
    }
}

function Get-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) {
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return [bool]$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

# Run a native command without letting its stderr become a terminating error.
function Invoke-Native {
    param([string]$FilePath, [string[]]$ArgumentList)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = -1
    $output = @()
    try {
        $output = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { [string]$_ })
        $code = [int]$global:LASTEXITCODE
    }
    catch {
        $code = -1
    }
    finally {
        $ErrorActionPreference = $previous
    }
    return [pscustomobject]@{ exit_code = $code; output = $output }
}

# Split a Windows command line into tokens: "quoted text" or runs of non-space.
function Split-CommandLine {
    param([string]$Text)
    $tokens = @()
    if ([string]::IsNullOrEmpty($Text)) {
        return $tokens
    }
    foreach ($match in [regex]::Matches($Text, '"([^"]*)"|(\S+)')) {
        if ($match.Groups[1].Success) {
            $tokens += $match.Groups[1].Value
        }
        else {
            $tokens += $match.Groups[2].Value
        }
    }
    return $tokens
}

function Get-LeafName {
    param([string]$Path)
    $parts = @($Path -split '[\\/]')
    return [string]$parts[$parts.Count - 1]
}

function Get-ParentPath {
    param([string]$Path)
    $index = $Path.LastIndexOfAny([char[]]@('\', '/'))
    if ($index -le 0) {
        return $null
    }
    return $Path.Substring(0, $index)
}

function Get-ServiceState {
    if ($null -eq $ExpectedService) {
        return $null
    }
    $state = [ordered]@{
        name = [string]$ExpectedService
        present = $false
        status = 'Missing'
        pid = 0
        start_type = $null
        error = $null
        path_name = $null
    }
    try {
        $filter = "Name='" + [string]$ExpectedService + "'"
        $svc = @(
            Get-CimInstance -ClassName Win32_Service -Filter $filter -OperationTimeoutSec 5 -ErrorAction Stop
        ) | Select-Object -First 1
        if ($null -ne $svc) {
            $state.name = [string](Get-Prop $svc 'Name')
            $state.present = $true
            $state.status = [string](Get-Prop $svc 'State')
            $state.pid = [int](Get-Prop $svc 'ProcessId')
            $startMode = Get-Prop $svc 'StartMode'
            if ($null -ne $startMode) {
                $state.start_type = [string]$startMode
            }
            $state.path_name = [string](Get-Prop $svc 'PathName')
        }
    }
    catch {
        $state.status = 'Unknown'
        $state.error = [string]$_.Exception.Message
    }
    return [pscustomobject]$state
}

function Get-LineagePids {
    param([int]$OwnerPid)
    $pids = @()
    $currentPid = $OwnerPid
    $seen = @{}
    while ($currentPid -gt 0 -and $pids.Count -lt 64) {
        $key = [string]$currentPid
        if ($seen.ContainsKey($key)) {
            break
        }
        $seen[$key] = $true
        $pids += $currentPid
        $proc = $null
        try {
            $proc = Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId=" + $key) -OperationTimeoutSec 5 -ErrorAction Stop
        }
        catch {
            $proc = $null
        }
        if ($null -eq $proc) {
            break
        }
        $currentPid = [int](Get-Prop $proc 'ParentProcessId')
    }
    return $pids
}

function Get-ListenerState {
    param([int]$ServicePid)
    $ownerPids = @()
    $allBound = $null
    $listenerError = $null
    try {
        $listeners = @(
            Get-NetTCPConnection -State Listen -ErrorAction Stop |
                Where-Object {
                    [string]$_.State -eq 'Listen' -and [int]$_.LocalPort -eq [int]$ComfyPort
                }
        )
        $ownerPids = @($listeners | ForEach-Object { [int]$_.OwningProcess } | Sort-Object -Unique)
        if ($null -ne $ExpectedService) {
            $allBound = ($ownerPids.Count -gt 0)
            foreach ($ownerPid in $ownerPids) {
                $lineage = @(Get-LineagePids -OwnerPid $ownerPid)
                if (-not ($ServicePid -gt 0 -and $lineage -contains $ServicePid)) {
                    $allBound = $false
                }
            }
        }
    }
    catch {
        $listenerError = [string]$_.Exception.Message
        $ownerPids = @()
        $allBound = $null
    }
    return [pscustomobject][ordered]@{
        port = [int]$ComfyPort
        listening = ($ownerPids.Count -gt 0)
        owner_pids = [int[]]$ownerPids
        all_owners_service_bound = $allBound
        error = $listenerError
    }
}

function Get-LiveState {
    $baseUri = 'http://127.0.0.1:' + [string]$ComfyPort
    $reachable = $false
    $version = $null
    $liveError = $null
    try {
        $stats = Invoke-RestMethod -Uri ($baseUri + '/system_stats') -Method Get -TimeoutSec 4
        $reachable = $true
        $system = Get-Prop $stats 'system'
        $reported = Get-Prop $system 'comfyui_version'
        if ($null -ne $reported) {
            $version = [string]$reported
        }
    }
    catch {
        $liveError = [string]$_.Exception.Message
    }
    $versionMatches = $null
    if ($null -ne $ExpectedComfyVersion) {
        $versionMatches = ($null -ne $version -and $version -eq [string]$ExpectedComfyVersion)
    }
    return [pscustomobject][ordered]@{
        reachable = $reachable
        base_uri = $baseUri
        version = $version
        expected_version = $ExpectedComfyVersion
        version_matches = $versionMatches
        error = $liveError
    }
}

function Get-Snapshot {
    param([switch]$SkipLive)
    $service = Get-ServiceState
    $servicePid = 0
    if ($null -ne $service) {
        $servicePid = [int]$service.pid
    }
    $listener = Get-ListenerState -ServicePid $servicePid
    $live = $null
    if (-not $SkipLive) {
        $live = Get-LiveState
    }
    return [pscustomobject]@{ service = $service; listener = $listener; live = $live }
}

# Reasons the snapshot is not a ready, service-owned ComfyUI.
function Get-StateReasons {
    param($Snapshot)
    $found = @()
    $service = $Snapshot.service
    if ($null -ne $service) {
        if ($null -ne $service.error) {
            $found += 'service_query_failed'
        }
        elseif (-not $service.present) {
            $found += 'service_missing'
        }
        elseif ([string]$service.status -ne 'Running') {
            $found += 'service_not_running'
        }
    }
    $listener = $Snapshot.listener
    if ($null -ne $listener.error) {
        $found += 'listener_query_failed'
    }
    elseif (-not $listener.listening) {
        $found += 'port_not_listening'
    }
    elseif ($listener.all_owners_service_bound -eq $false) {
        $found += 'rogue_listener'
    }
    $live = $Snapshot.live
    if ($null -ne $live) {
        if (-not $live.reachable) {
            $found += 'comfy_unreachable'
        }
        elseif ($live.version_matches -eq $false) {
            $found += 'version_mismatch'
        }
    }
    return $found
}

# Poll until the service owns a reachable ComfyUI with the expected version.
function Wait-Ready {
    param([double]$LimitSeconds)
    $waitClock = [System.Diagnostics.Stopwatch]::StartNew()
    $maxAttempts = [int][math]::Ceiling($LimitSeconds / $PollSeconds) + 1
    $attempt = 0
    while ($true) {
        $attempt += 1
        $snapshot = Get-Snapshot
        $pending = @(Get-StateReasons -Snapshot $snapshot)
        if ($pending.Count -eq 0) {
            return [pscustomobject]@{ ready = $true; snapshot = $snapshot; reasons = $pending }
        }
        if ($attempt -ge $maxAttempts -or $waitClock.Elapsed.TotalSeconds -ge $LimitSeconds) {
            return [pscustomobject]@{ ready = $false; snapshot = $snapshot; reasons = $pending }
        }
        Start-Sleep -Seconds $PollSeconds
    }
}

# Seconds left for a wait: at most $Wanted, and never past $Budget seconds of the run.
function Get-WaitLimit {
    param([double]$Wanted, [double]$Budget)
    $left = $Budget - $script:Clock.Elapsed.TotalSeconds
    return [math]::Max(1, [math]::Min($Wanted, $left))
}

function Test-ShawlManaged {
    param([string]$PathName, [string]$Name)
    $tokens = @(Split-CommandLine -Text $PathName)
    if ($tokens.Count -lt 3) {
        return $false
    }
    if ((Get-LeafName -Path $tokens[0]) -ine 'shawl.exe') {
        return $false
    }
    for ($index = 1; $index -lt $tokens.Count; $index++) {
        $token = [string]$tokens[$index]
        if ($token -eq '--') {
            break
        }
        if ($token -ieq ('--name=' + $Name)) {
            return $true
        }
        if ($token -eq '--name' -and $index + 1 -lt $tokens.Count -and [string]$tokens[$index + 1] -ieq $Name) {
            return $true
        }
    }
    return $false
}

function Test-ConflictText {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) {
        return $false
    }
    foreach ($match in [regex]::Matches($Text, '(?i)--port(?:\s+|=)["'']?(\d+)')) {
        if ([int]$match.Groups[1].Value -eq [int]$ComfyPort) {
            return $true
        }
    }
    if ([int]$ComfyPort -eq 8188 -and $Text -notmatch '(?i)--port\b' -and $Text -match '(?i)main\.py') {
        return $true
    }
    return $false
}

# The text of a .bat, .cmd or .ps1 wrapper under 64 KB, or $null.
function Get-WrapperText {
    param([string]$Path)
    if ([string]::IsNullOrEmpty($Path)) {
        return $null
    }
    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if ($expanded -notmatch '(?i)\.(bat|cmd|ps1)$') {
        return $null
    }
    try {
        if (-not (Test-Path -LiteralPath $expanded -PathType Leaf)) {
            return $null
        }
        $item = Get-Item -LiteralPath $expanded -ErrorAction Stop
        if ([int64]$item.Length -ge $ConflictScanMaxBytes) {
            return $null
        }
        return [string](Get-Content -LiteralPath $expanded -Raw -ErrorAction Stop)
    }
    catch {
        return $null
    }
}

function Test-LauncherConflict {
    param([string]$CommandLine)
    if (Test-ConflictText -Text $CommandLine) {
        return $true
    }
    # Any token may name the wrapper (cmd /c X.bat, powershell -ExecutionPolicy Bypass -File X.ps1);
    # Get-WrapperText reads only .bat, .cmd and .ps1 files.
    foreach ($token in @(Split-CommandLine -Text $CommandLine)) {
        if (Test-ConflictText -Text (Get-WrapperText -Path ([string]$token))) {
            return $true
        }
    }
    return $false
}

# Every service and scheduled task that already starts ComfyUI on this port.
function Find-LauncherConflicts {
    $conflicts = @()
    $services = @(Get-CimInstance -ClassName Win32_Service -OperationTimeoutSec 15 -ErrorAction Stop)
    foreach ($svc in $services) {
        $pathName = Get-Prop $svc 'PathName'
        if ($null -ne $pathName -and (Test-LauncherConflict -CommandLine ([string]$pathName))) {
            $conflicts += [pscustomobject][ordered]@{ kind = 'service'; name = [string](Get-Prop $svc 'Name') }
        }
    }
    $tasks = @(Get-ScheduledTask -ErrorAction Stop)
    foreach ($task in $tasks) {
        foreach ($taskAction in @(Get-Prop $task 'Actions')) {
            $execute = Get-Prop $taskAction 'Execute'
            if ($null -eq $execute) {
                continue
            }
            $commandLine = '"' + [string]$execute + '"'
            $arguments = Get-Prop $taskAction 'Arguments'
            if ($null -ne $arguments) {
                $commandLine += ' ' + [string]$arguments
            }
            if (Test-LauncherConflict -CommandLine $commandLine) {
                $conflicts += [pscustomobject][ordered]@{
                    kind = 'scheduled_task'
                    name = [string](Get-Prop $task 'TaskPath') + [string](Get-Prop $task 'TaskName')
                }
                break
            }
        }
    }
    return $conflicts
}

function Remove-CreatedService {
    $stopped = $true
    try {
        Stop-Service -Name $ExpectedService -ErrorAction Stop -WarningAction SilentlyContinue
    }
    catch {
        $stopped = $false
        Add-Reason 'rollback_stop_failed'
    }
    $delete = Invoke-Native -FilePath 'sc.exe' -ArgumentList @('delete', [string]$ExpectedService)
    if ($delete.exit_code -ne 0) {
        Add-Reason 'rollback_delete_failed'
    }
    $after = Get-ServiceState
    return (-not $after.present -and $null -eq $after.error -and $stopped)
}

function ConvertTo-ServiceView {
    param($Service)
    if ($null -eq $Service) {
        return $null
    }
    return [ordered]@{
        name = $Service.name
        present = $Service.present
        status = $Service.status
        pid = $Service.pid
        start_type = $Service.start_type
        error = $Service.error
    }
}

function Write-Observation {
    param([string]$Outcome, [bool]$Changed, $Snapshot, $Extra)
    $live = $Snapshot.live
    if ($null -eq $live) {
        $live = Get-LiveState
    }
    $observation = [ordered]@{
        schema = 'rdbg.comfy.' + [string]$Action + '.v1'
        outcome = $Outcome
        changed = $Changed
        reasons = [string[]]$script:Reasons.ToArray()
        service = ConvertTo-ServiceView -Service $Snapshot.service
        listener = $Snapshot.listener
        live = $live
    }
    if ($null -ne $Extra) {
        foreach ($key in $Extra.Keys) {
            $observation[$key] = $Extra[$key]
        }
    }
    [Console]::Out.WriteLine(($observation | ConvertTo-Json -Depth 8 -Compress))
}

# --- actions ---

function Invoke-Status {
    $snapshot = Get-Snapshot
    foreach ($reason in @(Get-StateReasons -Snapshot $snapshot)) {
        Add-Reason $reason
    }
    Write-Observation -Outcome 'done' -Changed $false -Snapshot $snapshot -Extra $null
}

function Invoke-Restart {
    $admin = Test-IsAdministrator
    $snapshot = Get-Snapshot -SkipLive
    if (-not $admin) {
        Add-Reason 'not_administrator'
    }
    if ($null -ne $snapshot.service.error) {
        Add-Reason 'service_query_failed'
    }
    elseif (-not $snapshot.service.present) {
        Add-Reason 'service_missing'
    }
    if ($null -ne $snapshot.listener.error) {
        Add-Reason 'listener_query_failed'
    }
    elseif ($snapshot.listener.listening -and $snapshot.listener.all_owners_service_bound -ne $true) {
        Add-Reason 'rogue_listener'
    }
    if ($script:Reasons.Count -gt 0) {
        Write-Observation -Outcome 'refused' -Changed $false -Snapshot $snapshot -Extra ([ordered]@{ ready = $false })
        return
    }

    try {
        Restart-Service -Name $ExpectedService -ErrorAction Stop -WarningAction SilentlyContinue
    }
    catch {
        Add-Reason 'restart_failed'
        Write-Observation -Outcome 'failed' -Changed $true -Snapshot (Get-Snapshot) -Extra ([ordered]@{ ready = $false })
        return
    }
    $wait = Wait-Ready -LimitSeconds (Get-WaitLimit -Wanted 120 -Budget 135)
    if ($wait.ready) {
        Write-Observation -Outcome 'done' -Changed $true -Snapshot $wait.snapshot -Extra ([ordered]@{ ready = $true })
        return
    }
    Add-Reason 'not_ready_timeout'
    foreach ($reason in @($wait.reasons)) {
        Add-Reason $reason
    }
    Write-Observation -Outcome 'failed' -Changed $true -Snapshot $wait.snapshot -Extra ([ordered]@{ ready = $false })
}

function Invoke-InstallService {
    $root = [string]$ComfyRoot
    if ($root.Length -gt 3) {
        $root = $root.TrimEnd('\', '/')
    }
    $extra = [ordered]@{
        ready = $false
        rolled_back = $false
        start_type = [string]$StartType
        log_dir = $null
        conflicts = @()
    }

    if (-not (Test-IsAdministrator)) {
        Add-Reason 'not_administrator'
    }
    if (-not (Test-Path -LiteralPath ($root + '\main.py') -PathType Leaf)) {
        Add-Reason 'root_main_py_missing'
    }
    if (-not (Test-Path -LiteralPath $CanonicalPython -PathType Leaf)) {
        Add-Reason 'python_missing'
    }
    if (-not (Test-Path -LiteralPath $ShawlExe -PathType Leaf)) {
        Add-Reason 'shawl_missing'
    }
    else {
        try {
            $hash = [string](Get-FileHash -LiteralPath $ShawlExe -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($hash -ine [string]$ShawlSha256) {
                Add-Reason 'shawl_hash_mismatch'
            }
        }
        catch {
            Add-Reason 'shawl_hash_unreadable'
        }
    }
    $snapshot = Get-Snapshot -SkipLive
    if ($null -ne $snapshot.listener.error) {
        Add-Reason 'listener_query_failed'
    }
    elseif ($snapshot.listener.listening) {
        Add-Reason 'port_in_use'
    }
    if ($null -ne $snapshot.service.error) {
        Add-Reason 'service_query_failed'
    }
    elseif ($snapshot.service.present) {
        Add-Reason 'service_exists'
    }
    try {
        $conflicts = @(Find-LauncherConflicts)
        $extra.conflicts = $conflicts
        if ($conflicts.Count -gt 0) {
            Add-Reason 'launcher_conflict'
        }
    }
    catch {
        Add-Reason 'launcher_scan_failed'
    }
    if ($script:Reasons.Count -gt 0) {
        Write-Observation -Outcome 'refused' -Changed $false -Snapshot $snapshot -Extra $extra
        return
    }

    # Shawl writes shawl_for_<name>_*.log next to shawl.exe.
    $extra.log_dir = Get-ParentPath -Path ([string]$ShawlExe)
    $shawlArgs = @(
        'add', '--name', [string]$ExpectedService, '--cwd', $root,
        '--stop-timeout', [string]$StopTimeoutMs, '--kill-process-tree', '--',
        [string]$CanonicalPython, 'main.py', '--listen', [string]$ComfyListen,
        '--port', [string]$ComfyPort, '--disable-auto-launch'
    ) + @($ComfyArgs)
    $add = Invoke-Native -FilePath ([string]$ShawlExe) -ArgumentList $shawlArgs
    $failed = $false
    if ($add.exit_code -ne 0) {
        Add-Reason 'shawl_add_failed'
        $failed = $true
    }
    if (-not $failed) {
        $startupType = 'Automatic'
        if ([string]$StartType -eq 'manual') {
            $startupType = 'Manual'
        }
        try {
            Set-Service -Name $ExpectedService -StartupType $startupType -ErrorAction Stop
        }
        catch {
            Add-Reason 'set_start_type_failed'
            $failed = $true
        }
    }
    if (-not $failed) {
        try {
            Start-Service -Name $ExpectedService -ErrorAction Stop -WarningAction SilentlyContinue
        }
        catch {
            Add-Reason 'start_failed'
            $failed = $true
        }
    }
    if (-not $failed) {
        $wait = Wait-Ready -LimitSeconds (Get-WaitLimit -Wanted 120 -Budget 150)
        if ($wait.ready) {
            $extra.ready = $true
            Write-Observation -Outcome 'done' -Changed $true -Snapshot $wait.snapshot -Extra $extra
            return
        }
        Add-Reason 'not_ready_timeout'
        foreach ($reason in @($wait.reasons)) {
            Add-Reason $reason
        }
    }

    # Roll back only what this run created: the service named $ExpectedService,
    # which the preflight proved absent.
    $created = Get-ServiceState
    $changed = $false
    if ($created.present -or $null -ne $created.error) {
        $extra.rolled_back = Remove-CreatedService
        $changed = -not $extra.rolled_back
    }
    $final = Get-Snapshot
    if ($final.listener.listening) {
        Add-Reason 'port_still_busy'
    }
    Write-Observation -Outcome 'failed' -Changed $changed -Snapshot $final -Extra $extra
}

function Invoke-UninstallService {
    $extra = [ordered]@{ removed = $false }
    if (-not (Test-IsAdministrator)) {
        Add-Reason 'not_administrator'
    }
    $snapshot = Get-Snapshot -SkipLive
    $service = $snapshot.service
    if ($null -ne $service.error) {
        Add-Reason 'service_query_failed'
    }
    elseif (-not $service.present) {
        Add-Reason 'service_missing'
    }
    elseif (-not (Test-ShawlManaged -PathName ([string]$service.path_name) -Name ([string]$ExpectedService))) {
        Add-Reason 'service_not_shawl_managed'
    }
    if ($script:Reasons.Count -gt 0) {
        Write-Observation -Outcome 'refused' -Changed $false -Snapshot $snapshot -Extra $extra
        return
    }

    $initialStatus = [string]$service.status
    try {
        Stop-Service -Name $ExpectedService -ErrorAction Stop -WarningAction SilentlyContinue
    }
    catch {
        Add-Reason 'stop_failed'
    }
    $limit = Get-WaitLimit -Wanted 45 -Budget 75
    $waitClock = [System.Diagnostics.Stopwatch]::StartNew()
    $maxAttempts = [int][math]::Ceiling($limit / $PollSeconds) + 1
    $attempt = 0
    while ($true) {
        $attempt += 1
        $current = Get-Snapshot -SkipLive
        $stopped = ([string]$current.service.status -eq 'Stopped')
        $portFree = ($null -eq $current.listener.error -and -not $current.listener.listening)
        if (($stopped -and $portFree) -or $attempt -ge $maxAttempts -or $waitClock.Elapsed.TotalSeconds -ge $limit) {
            break
        }
        Start-Sleep -Seconds $PollSeconds
    }
    $changed = ([string]$current.service.status -ne $initialStatus)
    if (-not $stopped) {
        Add-Reason 'stop_timeout'
    }
    if (-not $portFree) {
        Add-Reason 'port_still_busy'
    }
    if ($script:Reasons.Count -gt 0) {
        Write-Observation -Outcome 'failed' -Changed $changed -Snapshot $current -Extra $extra
        return
    }

    $delete = Invoke-Native -FilePath 'sc.exe' -ArgumentList @('delete', [string]$ExpectedService)
    if ($delete.exit_code -ne 0) {
        Add-Reason 'delete_failed'
        Write-Observation -Outcome 'failed' -Changed $true -Snapshot (Get-Snapshot -SkipLive) -Extra $extra
        return
    }
    $extra.removed = $true
    Write-Observation -Outcome 'done' -Changed $true -Snapshot (Get-Snapshot -SkipLive) -Extra $extra
}

# --- main ---

switch ([string]$Action) {
    'status' { Invoke-Status }
    'restart' { Invoke-Restart }
    'install-service' { Invoke-InstallService }
    'uninstall-service' { Invoke-UninstallService }
    default { throw ('unknown action: ' + [string]$Action) }
}
