#![cfg(unix)]

//! `remote/comfy-service.ps1` under a local PowerShell 7 with a fake Windows host.
//!
//! Each test composes the exact script with `rdbg comfy ... --emit-script`, splices a
//! fake host in front of its `# --- main ---` line (after the script's own function
//! definitions, so `Test-IsAdministrator` can be replaced), runs it under `pwsh`, and
//! checks the observation with `rdbg comfy validate`. Every mutating command records
//! a `CALL` line on stderr, and throws when the test forbids mutation. Without `pwsh`
//! on PATH each test prints a skip line.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

const MAIN_MARKER: &str = "# --- main ---";

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("rdbg-comfy-pwsh-{}-{id}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn pwsh() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("pwsh"))
        .find(|candidate| candidate.is_file())
}

const FULL_COMFY: &str = "port = 8188\nexpected_service = 'Svc'\nexpected_version = '1.0.0'\n\
     python = 'C:\\venv dir\\python.exe'\nroot = 'C:\\ComfyUI'\nargs = ['--lowvram', \"it's\"]\n";

/// Compose `action` (with extra CLI arguments) for a host whose comfy table is `comfy`.
fn compose(scratch: &Scratch, comfy: &str, action: &[&str]) -> String {
    let config = scratch.0.join("hosts.toml");
    fs::write(
        &config,
        format!("[hosts.box-a]\nssh = \"box-a\"\n[hosts.box-a.comfy]\n{comfy}\n"),
    )
    .unwrap();
    let script = scratch.0.join("composed.ps1");
    let output = Command::new(env!("CARGO_BIN_EXE_rdbg"))
        .arg("comfy")
        .arg("--config")
        .arg(&config)
        .arg("box-a")
        .args(action)
        .arg("--emit-script")
        .arg(&script)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    fs::read_to_string(script).unwrap()
}

/// The fake Windows host. Tests adjust `$global:Fake` in their own snippet.
const FAKE_HOST: &str = r#"
$global:Fake = @{
    Admin = $true
    AllowMutation = $true
    Files = @{
        'C:\ComfyUI\main.py' = ''
        'C:\venv dir\python.exe' = ''
        'C:\tools\shawl.exe' = ''
    }
    # Get-FileHash reports upper case; the pinned constant is lower case.
    Hash = ([string]$ShawlSha256).ToUpperInvariant()
    HashThrows = $false
    Listeners = @()
    # Rows on a port in a state other than Listen: State, Port, Pid, RemotePort.
    OtherRows = @()
    Processes = @{}
    Services = @(
        @{ Name = 'sshd'; State = 'Running'; ProcessId = 5; StartMode = 'Auto'; PathName = 'C:\Windows\System32\OpenSSH\sshd.exe' }
    )
    ServiceQueryThrows = $false
    ListenerQueryThrows = $false
    TaskQueryThrows = $false
    Tasks = @(
        @{ TaskPath = '\'; TaskName = 'Unrelated'; Actions = @(@{ Execute = 'C:\Windows\notepad.exe'; Arguments = $null }) }
    )
    Version = $null
    StartBehavior = 'ready'
    PortStaysBusy = $false
    Calls = New-Object System.Collections.Generic.List[string]
}

function Record-Mutation {
    param([string]$Text)
    $global:Fake.Calls.Add($Text)
    if (-not $global:Fake.AllowMutation) {
        throw ('mutation attempted: ' + $Text)
    }
}

function Test-IsAdministrator { return [bool]$global:Fake.Admin }

function Find-FakeService {
    param([string]$Name)
    foreach ($svc in $global:Fake.Services) {
        if ($svc.Name -ieq $Name) {
            return $svc
        }
    }
    return $null
}

function ConvertTo-FakeService {
    param($Svc)
    return [pscustomobject]@{
        Name = $Svc.Name; State = $Svc.State; ProcessId = $Svc.ProcessId
        StartMode = $Svc.StartMode; PathName = $Svc.PathName
    }
}

function Get-CimInstance {
    param($ClassName, $Filter, $OperationTimeoutSec)
    if ($ClassName -eq 'Win32_Service') {
        if ($global:Fake.ServiceQueryThrows) {
            throw 'service query failed'
        }
        if ($null -ne $Filter) {
            $name = [regex]::Match([string]$Filter, "Name='([^']*)'").Groups[1].Value
            $svc = Find-FakeService -Name $name
            if ($null -eq $svc) {
                return $null
            }
            return ConvertTo-FakeService -Svc $svc
        }
        return @($global:Fake.Services | ForEach-Object { ConvertTo-FakeService -Svc $_ })
    }
    if ($ClassName -eq 'Win32_Process') {
        $processId = [regex]::Match([string]$Filter, '\d+').Value
        if ($global:Fake.Processes.ContainsKey($processId)) {
            return [pscustomobject]@{ ProcessId = [int]$processId; ParentProcessId = [int]$global:Fake.Processes[$processId] }
        }
        return $null
    }
    throw ('unexpected CIM class ' + $ClassName)
}

function Get-NetTCPConnection {
    if ($global:Fake.ListenerQueryThrows) {
        throw 'listener query failed'
    }
    return @(
        @($global:Fake.Listeners | ForEach-Object {
            [pscustomobject]@{ State = 'Listen'; LocalPort = $_.Port; RemotePort = 0; OwningProcess = $_.Pid }
        }) +
        @($global:Fake.OtherRows | ForEach-Object {
            [pscustomobject]@{ State = $_.State; LocalPort = $_.Port; RemotePort = $_.RemotePort; OwningProcess = $_.Pid }
        })
    )
}

function Invoke-RestMethod {
    param($Uri, $Method, $TimeoutSec)
    if ($TimeoutSec -ne 4) {
        throw 'system_stats must use a 4 second timeout'
    }
    if ($null -eq $global:Fake.Version) {
        throw 'connection refused'
    }
    return [pscustomobject]@{ system = [pscustomobject]@{ comfyui_version = $global:Fake.Version } }
}

function Test-Path {
    param($LiteralPath, $PathType)
    return $global:Fake.Files.ContainsKey([string]$LiteralPath)
}

function Get-Item {
    param($LiteralPath)
    return [pscustomobject]@{ Length = ([string]$global:Fake.Files[[string]$LiteralPath]).Length }
}

function Get-Content {
    param($LiteralPath)
    return [string]$global:Fake.Files[[string]$LiteralPath]
}

function Get-FileHash {
    param($LiteralPath, $Algorithm)
    if ($global:Fake.HashThrows) {
        throw 'hash failed'
    }
    if ($Algorithm -ne 'SHA256') {
        throw 'expected SHA256'
    }
    return [pscustomobject]@{ Hash = $global:Fake.Hash }
}

function Get-ScheduledTask {
    if ($global:Fake.TaskQueryThrows) {
        throw 'task query failed'
    }
    return @($global:Fake.Tasks | ForEach-Object {
        $actions = @($_.Actions | ForEach-Object {
            [pscustomobject]@{ Execute = $_.Execute; Arguments = $_.Arguments }
        })
        [pscustomobject]@{ TaskPath = $_.TaskPath; TaskName = $_.TaskName; Actions = $actions }
    })
}

function Start-Sleep { }

function Start-FakeComfy {
    param($Svc)
    $Svc.State = 'Running'
    $Svc.ProcessId = 10
    if ($global:Fake.StartBehavior -eq 'ready') {
        $global:Fake.Processes['10'] = 1
        $global:Fake.Processes['100'] = 10
        $global:Fake.Listeners = @(@{ Port = 8188; Pid = 100 })
        $global:Fake.Version = '1.0.0'
    }
    elseif ($global:Fake.StartBehavior -eq 'wrong-version') {
        $global:Fake.Processes['10'] = 1
        $global:Fake.Processes['100'] = 10
        $global:Fake.Listeners = @(@{ Port = 8188; Pid = 100 })
        $global:Fake.Version = '0.9.0'
    }
}

function Stop-FakeComfy {
    param($Svc)
    $Svc.State = 'Stopped'
    $Svc.ProcessId = 0
    if (-not $global:Fake.PortStaysBusy) {
        $global:Fake.Listeners = @()
        $global:Fake.Version = $null
    }
}

function Restart-Service {
    param($Name)
    Record-Mutation ('Restart-Service ' + $Name)
    $svc = Find-FakeService -Name $Name
    Stop-FakeComfy -Svc $svc
    Start-FakeComfy -Svc $svc
}

function Start-Service {
    param($Name)
    Record-Mutation ('Start-Service ' + $Name)
    Start-FakeComfy -Svc (Find-FakeService -Name $Name)
}

function Stop-Service {
    param($Name)
    Record-Mutation ('Stop-Service ' + $Name)
    Stop-FakeComfy -Svc (Find-FakeService -Name $Name)
}

function Set-Service {
    param($Name, $StartupType)
    Record-Mutation ('Set-Service ' + $Name + ' ' + $StartupType)
    (Find-FakeService -Name $Name).StartMode = $StartupType
}

${function:C:\tools\shawl.exe} = {
    Record-Mutation ('shawl ' + ($args -join '|'))
    $name = $args[[array]::IndexOf($args, '--name') + 1]
    $global:Fake.Services += @{
        Name = $name; State = 'Stopped'; ProcessId = 0; StartMode = 'Manual'
        PathName = 'C:\tools\shawl.exe run --name ' + $name + ' -- python main.py'
    }
    $global:LASTEXITCODE = 0
}

function sc.exe {
    Record-Mutation ('sc.exe ' + ($args -join '|'))
    if ($args[0] -eq 'delete') {
        $target = [string]$args[1]
        $global:Fake.Services = @($global:Fake.Services | Where-Object { $_.Name -ine $target })
    }
    $global:LASTEXITCODE = 0
}
"#;

/// Setup that installs a running, shawl-managed, ready service `Svc`.
const RUNNING_SERVICE: &str = r#"
$global:Fake.Services += @{
    Name = 'Svc'; State = 'Running'; ProcessId = 10; StartMode = 'Auto'
    PathName = '"C:\tools\shawl.exe" run --name Svc --cwd C:\ComfyUI -- python main.py'
}
$global:Fake.Processes['10'] = 1
$global:Fake.Processes['100'] = 10
$global:Fake.Listeners = @(@{ Port = 8188; Pid = 100 })
$global:Fake.Version = '1.0.0'
"#;

struct Run {
    observation: Value,
    calls: Vec<String>,
    exit_code: i32,
}

/// Run `action` under pwsh against the fake host adjusted by `setup`.
fn run(comfy: &str, action: &[&str], setup: &str) -> Option<Run> {
    let Some(pwsh) = pwsh() else {
        println!("skipping comfy {action:?} runtime test: pwsh not found on PATH");
        return None;
    };
    let scratch = Scratch::new();
    let composed = compose(&scratch, comfy, action);
    assert_eq!(composed.matches(MAIN_MARKER).count(), 1);
    let script = composed.replace(
        MAIN_MARKER,
        &format!("{FAKE_HOST}\n{setup}\ntry {{\n{MAIN_MARKER}"),
    );
    let script = format!(
        "{script}\n}} finally {{ foreach ($call in $global:Fake.Calls) {{ [Console]::Error.WriteLine('CALL ' + $call) }} }}\n"
    );
    let path = scratch.0.join("run.ps1");
    fs::write(&path, script).unwrap();
    let output = Command::new(pwsh)
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
        .arg(&path)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "pwsh failed: {stderr}\n{stdout}");
    let lines: Vec<&str> = stdout.lines().filter(|line| !line.is_empty()).collect();
    assert_eq!(lines.len(), 1, "stdout must be one JSON line: {stdout}");
    let calls = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("CALL "))
        .map(ToOwned::to_owned)
        .collect();
    let other_stderr: Vec<&str> = stderr
        .lines()
        .filter(|line| !line.starts_with("CALL "))
        .collect();
    assert!(other_stderr.is_empty(), "stderr: {stderr}");

    // The observation must satisfy the strict contract rdbg enforces.
    let saved = json!({
        "schema": "rdbg.result.v1", "ok": true, "error_class": null, "rdbg_exit_code": 0,
        "process_exit_code": 0, "target": "box-a", "mode": "file", "timeout_seconds": 30,
        "stdout": format!("{}\r\n", lines[0]), "stderr": "", "stdout_utf8_lossy": false,
        "stderr_utf8_lossy": false, "stdout_truncated": false, "stderr_truncated": false,
        "message": null
    });
    let saved_path = scratch.0.join("saved.json");
    fs::write(&saved_path, saved.to_string()).unwrap();
    let validated = Command::new(env!("CARGO_BIN_EXE_rdbg"))
        .args(["comfy", "validate", action[0]])
        .arg(&saved_path)
        .output()
        .unwrap();
    let result: Value = serde_json::from_slice(&validated.stdout).unwrap();
    let observation: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(
        result["observation"], observation,
        "{action:?} contract: {result}"
    );
    let exit_code = validated.status.code().unwrap();
    let expected_code = match observation["outcome"].as_str().unwrap() {
        "done" => 0,
        "refused" => rdbg::EXIT_REFUSED,
        _ => rdbg::EXIT_ACTION_FAILED,
    };
    assert_eq!(exit_code, expected_code, "{result}");
    Some(Run {
        observation,
        calls,
        exit_code,
    })
}

fn reasons(observation: &Value) -> Vec<String> {
    observation["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|reason| reason.as_str().unwrap().to_owned())
        .collect()
}

const INSTALL: &[&str] = &["install-service", "--shawl-exe", "C:\\tools\\shawl.exe"];

/// Install preflight with mutation forbidden: exactly `reason`, refused, nothing called.
fn assert_install_refused(setup: &str, reason: &str) {
    let setup = format!("$global:Fake.AllowMutation = $false\n{setup}");
    let Some(run) = run(FULL_COMFY, INSTALL, &setup) else {
        return;
    };
    assert_eq!(run.observation["outcome"], "refused");
    assert_eq!(run.observation["changed"], false);
    assert_eq!(reasons(&run.observation), [reason]);
    assert!(run.calls.is_empty(), "{:?}", run.calls);
    assert_eq!(run.exit_code, rdbg::EXIT_REFUSED);
}

macro_rules! install_refusal {
    ($($name:ident: $setup:expr => $reason:expr;)*) => {
        $(#[test]
        fn $name() {
            assert_install_refused($setup, $reason);
        })*
    };
}

install_refusal! {
    install_refuses_without_administrator: "$global:Fake.Admin = $false" => "not_administrator";
    install_refuses_without_main_py: "$global:Fake.Files.Remove('C:\\ComfyUI\\main.py')" => "root_main_py_missing";
    install_refuses_without_python: "$global:Fake.Files.Remove('C:\\venv dir\\python.exe')" => "python_missing";
    install_refuses_without_shawl: "$global:Fake.Files.Remove('C:\\tools\\shawl.exe')" => "shawl_missing";
    install_refuses_a_wrong_shawl_hash: "$global:Fake.Hash = 'ABCDEF'" => "shawl_hash_mismatch";
    install_refuses_an_unreadable_shawl_hash: "$global:Fake.HashThrows = $true" => "shawl_hash_unreadable";
    install_refuses_a_busy_port: "$global:Fake.Listeners = @(@{ Port = 8188; Pid = 300 })" => "port_in_use";
    install_refuses_an_unreadable_listener_table: "$global:Fake.ListenerQueryThrows = $true" => "listener_query_failed";
    install_refuses_an_inconsistent_listener_table: "$global:Fake.OtherRows = @(@{ State = 'FinWait1'; Port = 8188; Pid = 300; RemotePort = 0 })" => "listener_query_failed";
    install_refuses_an_existing_service: "$global:Fake.Services += @{ Name = 'Svc'; State = 'Stopped'; ProcessId = 0; StartMode = 'Manual'; PathName = 'C:\\x.exe' }" => "service_exists";
    install_refuses_when_launchers_cannot_be_scanned: "$global:Fake.TaskQueryThrows = $true" => "launcher_scan_failed";
    install_refuses_a_conflicting_service_launcher: "$global:Fake.Services += @{ Name = 'OldComfy'; State = 'Stopped'; ProcessId = 0; StartMode = 'Manual'; PathName = '\"C:\\py\\python.exe\" C:\\ComfyUI\\main.py --port 8188' }" => "launcher_conflict";
}

#[test]
fn install_refuses_when_services_cannot_be_read() {
    // A failed service query also blocks the launcher scan; both reasons are reported.
    let Some(run) = run(
        FULL_COMFY,
        INSTALL,
        "$global:Fake.AllowMutation = $false\n$global:Fake.ServiceQueryThrows = $true",
    ) else {
        return;
    };
    assert_eq!(run.observation["outcome"], "refused");
    assert_eq!(
        reasons(&run.observation),
        ["service_query_failed", "launcher_scan_failed"]
    );
    assert!(run.calls.is_empty(), "{:?}", run.calls);
}

#[test]
fn install_collects_every_failing_reason() {
    let Some(run) = run(
        FULL_COMFY,
        INSTALL,
        "$global:Fake.AllowMutation = $false\n$global:Fake.Admin = $false\n\
         $global:Fake.Files.Remove('C:\\ComfyUI\\main.py')\n$global:Fake.Hash = 'AB'",
    ) else {
        return;
    };
    assert_eq!(
        reasons(&run.observation),
        [
            "not_administrator",
            "root_main_py_missing",
            "shawl_hash_mismatch"
        ]
    );
    assert!(run.calls.is_empty());
}

#[test]
fn launcher_conflict_found_via_scheduled_task_action() {
    let Some(run) = run(
        FULL_COMFY,
        INSTALL,
        "$global:Fake.AllowMutation = $false\n\
         $global:Fake.Tasks += @{ TaskPath = '\\Tools\\'; TaskName = 'Start Comfy'; \
         Actions = @(@{ Execute = 'C:\\py\\python.exe'; Arguments = 'C:\\ComfyUI\\main.py --port=8188 --lowvram' }) }",
    ) else {
        return;
    };
    assert_eq!(reasons(&run.observation), ["launcher_conflict"]);
    assert_eq!(
        run.observation["conflicts"],
        json!([{"kind": "scheduled_task", "name": "\\Tools\\Start Comfy"}])
    );
    assert!(!run.observation.to_string().contains("--lowvram"));
    assert!(run.calls.is_empty());
}

#[test]
fn launcher_conflict_found_via_wrapper_bat() {
    let Some(run) = run(
        FULL_COMFY,
        INSTALL,
        "$global:Fake.AllowMutation = $false\n\
         $global:Fake.Files['C:\\launch\\start comfy.bat'] = \"cd /d C:\\ComfyUI`r`npython main.py --listen --port 8188`r`n\"\n\
         $global:Fake.Tasks += @{ TaskPath = '\\'; TaskName = 'Wrapper'; \
         Actions = @(@{ Execute = 'cmd.exe'; Arguments = '/c \"C:\\launch\\start comfy.bat\"' }) }",
    ) else {
        return;
    };
    assert_eq!(reasons(&run.observation), ["launcher_conflict"]);
    assert_eq!(
        run.observation["conflicts"],
        json!([{"kind": "scheduled_task", "name": "\\Wrapper"}])
    );
}

#[test]
fn launcher_conflict_found_via_wrapper_ps1_after_option_values() {
    let Some(run) = run(
        FULL_COMFY,
        INSTALL,
        "$global:Fake.AllowMutation = $false\n\
         $global:Fake.Files['C:\\launch\\start comfy.ps1'] = \"Set-Location C:\\ComfyUI`r`n& python main.py --port=8188`r`n\"\n\
         $global:Fake.Tasks += @{ TaskPath = '\\'; TaskName = 'PsWrapper'; \
         Actions = @(@{ Execute = 'powershell.exe'; Arguments = '-NoProfile -ExecutionPolicy Bypass -File \"C:\\launch\\start comfy.ps1\"' }) }",
    ) else {
        return;
    };
    assert_eq!(reasons(&run.observation), ["launcher_conflict"]);
    assert_eq!(
        run.observation["conflicts"],
        json!([{"kind": "scheduled_task", "name": "\\PsWrapper"}])
    );
}

#[test]
fn launcher_conflict_found_via_default_port_rule() {
    let Some(run) = run(
        FULL_COMFY,
        INSTALL,
        "$global:Fake.AllowMutation = $false\n\
         $global:Fake.Services += @{ Name = 'LegacyComfy'; State = 'Stopped'; ProcessId = 0; StartMode = 'Manual'; \
         PathName = 'C:\\nssm\\nssm.exe' }\n\
         $global:Fake.Services += @{ Name = 'BareComfy'; State = 'Stopped'; ProcessId = 0; StartMode = 'Manual'; \
         PathName = 'C:\\py\\python.exe C:\\ComfyUI\\main.py --listen 0.0.0.0' }",
    ) else {
        return;
    };
    assert_eq!(reasons(&run.observation), ["launcher_conflict"]);
    assert_eq!(
        run.observation["conflicts"],
        json!([{"kind": "service", "name": "BareComfy"}])
    );
}

#[test]
fn launchers_for_other_ports_do_not_conflict() {
    let comfy = FULL_COMFY.replace("port = 8188", "port = 8189");
    let Some(run) = run(
        &comfy,
        INSTALL,
        "$global:Fake.AllowMutation = $false\n$global:Fake.Admin = $false\n\
         $global:Fake.Services += @{ Name = 'BareComfy'; State = 'Stopped'; ProcessId = 0; StartMode = 'Manual'; \
         PathName = 'C:\\py\\python.exe C:\\ComfyUI\\main.py' }\n\
         $global:Fake.Services += @{ Name = 'OtherPort'; State = 'Stopped'; ProcessId = 0; StartMode = 'Manual'; \
         PathName = 'C:\\py\\python.exe main.py --port 81890' }",
    ) else {
        return;
    };
    assert_eq!(reasons(&run.observation), ["not_administrator"]);
    assert_eq!(run.observation["conflicts"], json!([]));
}

#[test]
fn install_registers_shawl_and_waits_until_ready() {
    let action = [INSTALL, &["--start-type", "manual"]].concat();
    let Some(run) = run(FULL_COMFY, &action, "") else {
        return;
    };
    assert_eq!(run.observation["outcome"], "done", "{}", run.observation);
    assert_eq!(run.observation["changed"], true);
    assert_eq!(run.observation["ready"], true);
    assert_eq!(run.observation["rolled_back"], false);
    assert_eq!(run.observation["start_type"], "manual");
    assert_eq!(run.observation["log_dir"], "C:\\tools");
    assert_eq!(run.observation["service"]["status"], "Running");
    assert_eq!(
        run.observation["listener"]["all_owners_service_bound"],
        true
    );
    assert_eq!(run.observation["live"]["version_matches"], true);
    assert_eq!(
        run.calls,
        [
            "shawl add|--name|Svc|--cwd|C:\\ComfyUI|--stop-timeout|30000|--kill-process-tree|--|\
             C:\\venv dir\\python.exe|main.py|--listen|127.0.0.1|--port|8188|--disable-auto-launch|\
             --lowvram|it's",
            "Set-Service Svc Manual",
            "Start-Service Svc",
        ]
    );
}

#[test]
fn install_defaults_to_automatic_start() {
    let Some(run) = run(FULL_COMFY, INSTALL, "") else {
        return;
    };
    assert_eq!(run.observation["start_type"], "auto");
    assert!(run.calls.contains(&"Set-Service Svc Automatic".to_owned()));
}

#[test]
fn install_that_never_gets_ready_rolls_back_its_own_service() {
    let Some(run) = run(FULL_COMFY, INSTALL, "$global:Fake.StartBehavior = 'never'") else {
        return;
    };
    assert_eq!(run.observation["outcome"], "failed");
    assert_eq!(run.observation["changed"], false);
    assert_eq!(run.observation["rolled_back"], true);
    assert_eq!(run.observation["ready"], false);
    assert_eq!(run.observation["service"]["present"], false);
    assert_eq!(run.observation["log_dir"], "C:\\tools");
    let found = reasons(&run.observation);
    assert_eq!(found[0], "not_ready_timeout");
    assert!(
        found.contains(&"port_not_listening".to_owned()),
        "{found:?}"
    );
    assert!(found.contains(&"comfy_unreachable".to_owned()), "{found:?}");
    assert_eq!(&run.calls[3..], ["Stop-Service Svc", "sc.exe delete|Svc"]);
    assert_eq!(run.exit_code, rdbg::EXIT_ACTION_FAILED);
}

#[test]
fn install_with_a_wrong_version_rolls_back() {
    let Some(run) = run(
        FULL_COMFY,
        INSTALL,
        "$global:Fake.StartBehavior = 'wrong-version'",
    ) else {
        return;
    };
    assert_eq!(run.observation["outcome"], "failed");
    assert!(reasons(&run.observation).contains(&"version_mismatch".to_owned()));
    assert!(run.calls.contains(&"sc.exe delete|Svc".to_owned()));
}

#[test]
fn uninstall_refuses_a_service_not_created_by_shawl() {
    let Some(run) = run(
        FULL_COMFY,
        &["uninstall-service"],
        "$global:Fake.AllowMutation = $false\n\
         $global:Fake.Services += @{ Name = 'Svc'; State = 'Running'; ProcessId = 10; StartMode = 'Auto'; \
         PathName = 'C:\\nssm\\nssm.exe' }",
    ) else {
        return;
    };
    assert_eq!(run.observation["outcome"], "refused");
    assert_eq!(reasons(&run.observation), ["service_not_shawl_managed"]);
    assert!(run.calls.is_empty());
}

#[test]
fn uninstall_refuses_shawl_for_another_name_and_missing_service() {
    let other = "$global:Fake.AllowMutation = $false\n\
         $global:Fake.Services += @{ Name = 'Svc'; State = 'Running'; ProcessId = 10; StartMode = 'Auto'; \
         PathName = 'C:\\tools\\shawl.exe run --name Other -- python main.py --name Svc' }";
    if let Some(run) = run(FULL_COMFY, &["uninstall-service"], other) {
        assert_eq!(reasons(&run.observation), ["service_not_shawl_managed"]);
        assert!(run.calls.is_empty());
    }
    let missing = "$global:Fake.AllowMutation = $false\n$global:Fake.Admin = $false";
    if let Some(run) = run(FULL_COMFY, &["uninstall-service"], missing) {
        assert_eq!(
            reasons(&run.observation),
            ["not_administrator", "service_missing"]
        );
        assert!(run.calls.is_empty());
    }
}

#[test]
fn uninstall_with_a_port_that_stays_busy_keeps_the_service() {
    let setup = format!("{RUNNING_SERVICE}\n$global:Fake.PortStaysBusy = $true");
    let Some(run) = run(FULL_COMFY, &["uninstall-service"], &setup) else {
        return;
    };
    assert_eq!(run.observation["outcome"], "failed");
    assert_eq!(run.observation["changed"], true);
    assert_eq!(run.observation["removed"], false);
    assert_eq!(reasons(&run.observation), ["port_still_busy"]);
    assert_eq!(run.observation["service"]["present"], true);
    assert_eq!(run.calls, ["Stop-Service Svc"]);
}

#[test]
fn uninstall_stops_and_deletes_a_shawl_service() {
    let Some(run) = run(FULL_COMFY, &["uninstall-service"], RUNNING_SERVICE) else {
        return;
    };
    assert_eq!(run.observation["outcome"], "done");
    assert_eq!(run.observation["removed"], true);
    assert_eq!(run.observation["service"]["present"], false);
    assert_eq!(run.calls, ["Stop-Service Svc", "sc.exe delete|Svc"]);
}

#[test]
fn restart_refuses_a_rogue_listener() {
    let setup = format!(
        "$global:Fake.AllowMutation = $false\n{RUNNING_SERVICE}\n\
         $global:Fake.Processes['200'] = 20\n\
         $global:Fake.Listeners += @{{ Port = 8188; Pid = 200 }}"
    );
    let Some(run) = run(FULL_COMFY, &["restart"], &setup) else {
        return;
    };
    assert_eq!(run.observation["outcome"], "refused");
    assert_eq!(reasons(&run.observation), ["rogue_listener"]);
    assert_eq!(run.observation["listener"]["owner_pids"], json!([100, 200]));
    assert_eq!(
        run.observation["listener"]["all_owners_service_bound"],
        false
    );
    assert!(run.calls.is_empty());
}

#[test]
fn restart_refuses_without_administrator_or_service() {
    let Some(run) = run(
        FULL_COMFY,
        &["restart"],
        "$global:Fake.AllowMutation = $false\n$global:Fake.Admin = $false",
    ) else {
        return;
    };
    assert_eq!(
        reasons(&run.observation),
        ["not_administrator", "service_missing"]
    );
    assert!(run.calls.is_empty());
}

#[test]
fn restart_waits_until_ready() {
    let Some(run) = run(FULL_COMFY, &["restart"], RUNNING_SERVICE) else {
        return;
    };
    assert_eq!(run.observation["outcome"], "done");
    assert_eq!(run.observation["ready"], true);
    assert_eq!(run.observation["changed"], true);
    assert_eq!(run.calls, ["Restart-Service Svc"]);
}

#[test]
fn restart_that_never_gets_ready_fails_without_rollback() {
    let setup = format!("{RUNNING_SERVICE}\n$global:Fake.StartBehavior = 'never'");
    let Some(run) = run(FULL_COMFY, &["restart"], &setup) else {
        return;
    };
    assert_eq!(run.observation["outcome"], "failed");
    assert_eq!(run.observation["changed"], true);
    assert_eq!(reasons(&run.observation)[0], "not_ready_timeout");
    assert_eq!(run.calls, ["Restart-Service Svc"]);
}

#[test]
fn status_with_a_service_name_reports_ownership() {
    let setup = format!("$global:Fake.AllowMutation = $false\n{RUNNING_SERVICE}");
    let Some(run) = run(FULL_COMFY, &["status"], &setup) else {
        return;
    };
    let observation = &run.observation;
    assert_eq!(observation["outcome"], "done");
    assert_eq!(observation["changed"], false);
    assert_eq!(observation["reasons"], json!([]));
    assert_eq!(
        observation["service"],
        json!({"name": "Svc", "present": true, "status": "Running", "pid": 10,
               "start_type": "Auto", "error": null})
    );
    assert_eq!(
        observation["listener"],
        json!({"port": 8188, "listening": true, "owner_pids": [100],
               "all_owners_service_bound": true, "error": null})
    );
    assert_eq!(observation["live"]["version"], "1.0.0");
    assert_eq!(observation["live"]["version_matches"], true);
    assert!(run.calls.is_empty());
}

#[test]
fn status_reports_a_server_socket_without_listen_state_as_a_query_failure() {
    let setup = format!(
        "$global:Fake.AllowMutation = $false\n{RUNNING_SERVICE}\n\
         $global:Fake.Listeners = @()\n\
         $global:Fake.OtherRows = @(\
         @{{ State = 'FinWait1'; Port = 8188; Pid = 100; RemotePort = 0 }}, \
         @{{ State = ''; Port = 8188; Pid = 100; RemotePort = 0 }}, \
         @{{ State = 'Established'; Port = 8188; Pid = 100; RemotePort = 50000 }})"
    );
    let Some(run) = run(FULL_COMFY, &["status"], &setup) else {
        return;
    };
    let observation = &run.observation;
    assert_eq!(
        observation["listener"],
        json!({"port": 8188, "listening": false, "owner_pids": [],
               "all_owners_service_bound": null,
               "error": "TCP table inconsistent: no Listen row on the port, but 2 row(s) \
                         without a remote endpoint (state FinWait1,unnamed)"})
    );
    assert_eq!(reasons(observation), ["listener_query_failed"]);
    assert!(run.calls.is_empty());
}

#[test]
fn status_ignores_connected_rows_when_nothing_listens() {
    let setup = "$global:Fake.AllowMutation = $false\n\
                 $global:Fake.OtherRows = @(\
                 @{ State = 'TimeWait'; Port = 8188; Pid = 0; RemotePort = 50000 })";
    let Some(run) = run(FULL_COMFY, &["status"], setup) else {
        return;
    };
    assert_eq!(run.observation["listener"]["listening"], false);
    assert_eq!(run.observation["listener"]["error"], Value::Null);
    assert!(reasons(&run.observation).contains(&"port_not_listening".to_owned()));
}

#[test]
fn status_without_a_service_name_reports_null_service_fields() {
    let Some(run) = run(
        "port = 9188\n",
        &["status"],
        "$global:Fake.AllowMutation = $false",
    ) else {
        return;
    };
    let observation = &run.observation;
    assert_eq!(observation["service"], Value::Null);
    assert_eq!(observation["listener"]["port"], 9188);
    assert_eq!(observation["listener"]["listening"], false);
    assert_eq!(
        observation["listener"]["all_owners_service_bound"],
        Value::Null
    );
    assert_eq!(observation["live"]["reachable"], false);
    assert_eq!(observation["live"]["expected_version"], Value::Null);
    assert_eq!(observation["live"]["version_matches"], Value::Null);
    assert_eq!(
        reasons(observation),
        ["port_not_listening", "comfy_unreachable"]
    );
}

#[test]
fn every_composed_action_parses() {
    let Some(pwsh) = pwsh() else {
        println!("skipping comfy parse test: pwsh not found on PATH");
        return;
    };
    let scratch = Scratch::new();
    for action in [
        &["status"][..],
        &["restart"],
        INSTALL,
        &["uninstall-service"],
    ] {
        compose(&scratch, FULL_COMFY, action);
        let path = scratch.0.join("composed.ps1");
        let command = format!(
            "$errors = $null; \
             [System.Management.Automation.Language.Parser]::ParseFile('{}', [ref]$null, [ref]$errors) > $null; \
             if ($errors.Count -gt 0) {{ $errors | ForEach-Object {{ Write-Error $_ }}; exit 1 }}",
            path.display()
        );
        let output = Command::new(&pwsh)
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"])
            .arg(command)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{action:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
