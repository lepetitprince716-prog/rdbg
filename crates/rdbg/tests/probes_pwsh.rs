#![cfg(unix)]

//! Probe scripts under a local PowerShell 7 with mocked Windows cmdlets.
//!
//! Each test composes the exact script with `rdbg doctor ... --emit-script`, puts the
//! mocks in front of it, runs it under `pwsh`, and checks the observation against
//! `rdbg doctor validate`. Without `pwsh` on PATH the runtime tests print a skip line;
//! the structural checks always run.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("rdbg-pwsh-{}-{id}", std::process::id()));
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

fn probe_text(name: &str) -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("probes")
            .join(format!("{name}.ps1")),
    )
    .unwrap()
}

/// Compose `probe` for a host whose `[comfy]` table is `comfy_toml`.
fn compose(scratch: &Scratch, probe: &str, comfy_toml: &str) -> String {
    let config = scratch.0.join("hosts.toml");
    fs::write(
        &config,
        format!("[hosts.box-a]\nssh = \"box-a\"\n[hosts.box-a.comfy]\n{comfy_toml}\n"),
    )
    .unwrap();
    let script = scratch.0.join(format!("{probe}.composed.ps1"));
    let output = Command::new(env!("CARGO_BIN_EXE_rdbg"))
        .arg("doctor")
        .arg("--config")
        .arg(&config)
        .args(["box-a", probe, "--emit-script"])
        .arg(&script)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    fs::read_to_string(script).unwrap()
}

/// Run mocks + composed probe under pwsh; validate and return the observation.
fn run_probe(probe: &str, comfy_toml: &str, mocks: &str) -> Option<Value> {
    let Some(pwsh) = pwsh() else {
        println!("skipping {probe} probe runtime test: pwsh not found on PATH");
        return None;
    };
    let scratch = Scratch::new();
    let composed = compose(&scratch, probe, comfy_toml);
    let script = scratch.0.join(format!("{probe}.run.ps1"));
    fs::write(&script, format!("{mocks}\n{composed}")).unwrap();
    let output = Command::new(pwsh)
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
        .arg(&script)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "pwsh failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let last_line = stdout.trim().lines().last().unwrap().to_owned();

    // The probe output must satisfy the strict contract rdbg enforces.
    let saved = json!({
        "schema": "rdbg.result.v1", "ok": true, "error_class": null, "rdbg_exit_code": 0,
        "process_exit_code": 0, "target": "box-a", "mode": "file", "timeout_seconds": 20,
        "stdout": format!("{last_line}\n"), "stderr": "", "stdout_utf8_lossy": false,
        "stderr_utf8_lossy": false, "stdout_truncated": false, "stderr_truncated": false,
        "message": null
    });
    let saved_path = scratch.0.join("saved.json");
    fs::write(&saved_path, saved.to_string()).unwrap();
    let validated = Command::new(env!("CARGO_BIN_EXE_rdbg"))
        .args(["doctor", "validate", probe])
        .arg(&saved_path)
        .output()
        .unwrap();
    let result: Value = serde_json::from_slice(&validated.stdout).unwrap();
    assert_eq!(result["ok"], true, "{probe} contract: {result}");

    Some(serde_json::from_str(&last_line).unwrap())
}

const LISTENER_COMFY: &str =
    "port = 8188\nexpected_service = 'Svc'\npython = 'C:\\canonical\\python.exe'\n";

#[test]
fn listener_mixed_canonical_and_rogue_owners_is_rogue() {
    let Some(observation) = run_probe(
        "listener",
        LISTENER_COMFY,
        r#"
function Get-NetTCPConnection {
    @(
        [pscustomobject]@{ State = 'Listen'; LocalPort = 8188; OwningProcess = 100 },
        [pscustomobject]@{ State = 'Listen'; LocalPort = 8188; OwningProcess = 200 }
    )
}
$script:FakeProcesses = @{
    '100' = [pscustomobject]@{ ProcessId = 100; ParentProcessId = 10; Name = 'python.exe'; ExecutablePath = 'C:\canonical\python.exe' }
    '10' = [pscustomobject]@{ ProcessId = 10; ParentProcessId = 0; Name = 'service.exe'; ExecutablePath = 'C:\service.exe' }
    '200' = [pscustomobject]@{ ProcessId = 200; ParentProcessId = 20; Name = 'python.exe'; ExecutablePath = 'C:\rogue\python.exe' }
    '20' = [pscustomobject]@{ ProcessId = 20; ParentProcessId = 0; Name = 'launcher.exe'; ExecutablePath = 'C:\launcher.exe' }
}
function Get-CimInstance {
    param($ClassName, $Filter)
    if ($ClassName -eq 'Win32_Service') {
        return [pscustomobject]@{ Name = 'Svc'; State = 'Running'; ProcessId = 10 }
    }
    $processId = [regex]::Match([string]$Filter, '\d+').Value
    return $script:FakeProcesses[$processId]
}
"#,
    ) else {
        return;
    };
    assert_eq!(observation["verdict"], "rogue");
    assert_eq!(observation["healthy"], false);
    assert_eq!(observation["service_pid"], 10);
    assert_eq!(observation["all_owners_service_bound"], false);
    assert_eq!(observation["all_owners_canonical_python"], false);
    let processes = observation["processes"].as_array().unwrap();
    assert_eq!(processes.len(), 2);
    assert_eq!(processes[0]["service_bound"], true);
    assert_eq!(processes[0]["canonical_python_in_lineage"], true);
    assert_eq!(processes[1]["service_bound"], false);
}

const EMPTY_PORT_MOCKS: &str = r#"
function Get-NetTCPConnection { @() }
function Get-CimInstance {
    param($ClassName, $Filter)
    if ($ClassName -eq 'Win32_Service') {
        return [pscustomobject]@{ Name = 'Svc'; State = '__STATE__'; ProcessId = __PID__ }
    }
    return $null
}
"#;

#[test]
fn listener_empty_port_is_missing_without_exception_text_matching() {
    let mocks = EMPTY_PORT_MOCKS
        .replace("__STATE__", "Running")
        .replace("__PID__", "10");
    let Some(observation) = run_probe("listener", LISTENER_COMFY, &mocks) else {
        return;
    };
    assert_eq!(observation["verdict"], "missing");
    assert_eq!(observation["listening"], false);
    assert_eq!(observation["collection_error"], Value::Null);
}

#[test]
fn listener_empty_port_stays_missing_when_required_service_is_stopped() {
    let mocks = EMPTY_PORT_MOCKS
        .replace("__STATE__", "Stopped")
        .replace("__PID__", "0");
    let Some(observation) = run_probe("listener", LISTENER_COMFY, &mocks) else {
        return;
    };
    assert_eq!(observation["listening"], false);
    assert_eq!(observation["service"]["status"], "Stopped");
    assert_eq!(observation["verdict"], "missing");
    assert_eq!(observation["healthy"], false);
}

#[test]
fn listener_reports_inconsistent_table_when_port_has_unconnected_non_listen_rows() {
    let Some(observation) = run_probe(
        "listener",
        LISTENER_COMFY,
        r#"
function Get-NetTCPConnection {
    @(
        [pscustomobject]@{ State = 'FinWait1'; LocalPort = 8188; RemotePort = 0; OwningProcess = 100 },
        [pscustomobject]@{ State = ''; LocalPort = 8188; RemotePort = 0; OwningProcess = 100 },
        [pscustomobject]@{ State = 'Established'; LocalPort = 8188; RemotePort = 50000; OwningProcess = 100 },
        [pscustomobject]@{ State = 'Listen'; LocalPort = 22; RemotePort = 0; OwningProcess = 300 }
    )
}
function Get-CimInstance {
    param($ClassName, $Filter)
    if ($ClassName -eq 'Win32_Service') {
        return [pscustomobject]@{ Name = 'Svc'; State = 'Running'; ProcessId = 10 }
    }
    return $null
}
"#,
    ) else {
        return;
    };
    assert_eq!(observation["listening"], false);
    assert_eq!(observation["verdict"], "missing");
    assert_eq!(observation["healthy"], false);
    assert_eq!(observation["processes"], json!([]));
    assert_eq!(
        observation["collection_error"],
        "TCP table inconsistent: no Listen row on the port, but 2 row(s) without a remote \
         endpoint (state FinWait1,unnamed)"
    );
}

#[test]
fn overview_reports_stopped_expected_service_as_unhealthy() {
    let Some(observation) = run_probe(
        "overview",
        "expected_service = 'Svc'\n",
        r#"
function Get-CimInstance {
    param($ClassName)
    if ($ClassName -eq 'Win32_OperatingSystem') {
        return [pscustomobject]@{
            Caption = 'Windows'; Version = '1'; BuildNumber = '2'
            LastBootUpTime = [datetime]::UtcNow.AddHours(-1)
            TotalVisibleMemorySize = 2048; FreePhysicalMemory = 1024
        }
    }
    return [pscustomobject]@{ Name = 'CPU'; NumberOfLogicalProcessors = 4 }
}
function Get-Service {
    param($Name)
    if ($Name -eq 'sshd') {
        return [pscustomobject]@{ Name = 'sshd'; Status = 'Running' }
    }
    return [pscustomobject]@{ Name = 'Svc'; Status = 'Stopped' }
}
"#,
    ) else {
        return;
    };
    assert_eq!(observation["healthy"], false);
    assert_eq!(observation["services"][0]["running"], true);
    assert_eq!(observation["services"][1]["running"], false);
}

#[test]
fn transport_round_trips_quotes_and_unicode() {
    let Some(observation) = run_probe("transport", "", "") else {
        return;
    };
    assert_eq!(observation["healthy"], true);
    assert_eq!(observation["encoding_sentinel"], "中文 / テスト / ✓");
    assert_eq!(observation["apostrophe_sentinel"], "O'Reilly");
    assert_eq!(observation["dollar_sentinel"], "$notExpanded");
}

#[test]
fn comfyui_unreachable_reports_version_mismatch() {
    let Some(observation) = run_probe(
        "comfyui",
        "port = 9188\nexpected_version = '1.0.0'\n",
        r#"
function Invoke-RestMethod {
    param($Uri, $Method, $TimeoutSec)
    throw 'connection refused'
}
"#,
    ) else {
        return;
    };
    assert_eq!(observation["reachable"], false);
    assert_eq!(observation["healthy"], false);
    assert_eq!(observation["base_uri"], "http://127.0.0.1:9188");
    assert_eq!(observation["expected_version"], "1.0.0");
    assert_eq!(observation["version_matches"], false);
}

const NVIDIA_PRESENT: &str = r#"
function Get-Command {
    [CmdletBinding()]
    param([string]$Name)
    if ($Name -eq 'nvidia-smi') {
        return [pscustomobject]@{ Source = 'nvidia-smi' }
    }
    return $null
}
"#;

#[test]
fn gpu_mock_output_parses_multiple_devices_without_units() {
    let mocks = format!(
        "{NVIDIA_PRESENT}{}",
        r#"
function nvidia-smi {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    if ($Arguments -match 'query-compute-apps') {
        Write-Output '101,C:\\private\\SECRET\\python.exe,2048'
    }
    else {
        Write-Output '0,Test GPU,1.2,16000,1600,14400,1,2,50,59.53,300.5,P8'
        Write-Output '1,Test GPU,1.2,16000,100,15900,0,1,48,40,300.5,P8'
    }
    $global:LASTEXITCODE = 0
}
"#
    );
    let Some(observation) = run_probe("gpu", "", &mocks) else {
        return;
    };
    assert_eq!(observation["available"], true);
    assert_eq!(observation["devices"].as_array().unwrap().len(), 2);
    assert_eq!(observation["devices"][0]["memory_used_mb"], 1600);
    assert_eq!(observation["compute_processes"][0]["pid"], 101);
    assert_eq!(
        observation["compute_processes"][0]["process_name"],
        "python.exe"
    );
    assert!(!observation.to_string().contains("SECRET"));
}

#[test]
fn gpu_missing_tool_returns_warning_and_readable_error() {
    let Some(observation) = run_probe(
        "gpu",
        "",
        r#"
function Get-Command {
    [CmdletBinding()]
    param([string]$Name)
    return $null
}
"#,
    ) else {
        return;
    };
    assert_eq!(observation["available"], false);
    assert_eq!(observation["healthy"], false);
    assert_eq!(
        observation["warning"],
        "nvidia-smi is not available on the target"
    );
    assert_eq!(observation["error"], "nvidia-smi command not found");
}

#[test]
fn gpu_empty_query_returns_unavailable_with_readable_error() {
    let mocks = format!(
        "{NVIDIA_PRESENT}{}",
        r#"
function nvidia-smi {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $global:LASTEXITCODE = 0
}
"#
    );
    let Some(observation) = run_probe("gpu", "", &mocks) else {
        return;
    };
    assert_eq!(observation["available"], false);
    assert_eq!(observation["healthy"], false);
    assert_eq!(
        observation["error"],
        "nvidia-smi GPU query returned no GPU rows"
    );
    assert!(
        observation["warning"]
            .as_str()
            .unwrap()
            .contains("no GPU rows")
    );
}

#[test]
fn gpu_nonzero_query_keeps_error_readable_without_command_output() {
    let mocks = format!(
        "{NVIDIA_PRESENT}{}",
        r#"
function nvidia-smi {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    if ($Arguments -match 'query-gpu') {
        Write-Output 'C:\private\SECRET\driver-error'
        $global:LASTEXITCODE = 7
    }
    else {
        $global:LASTEXITCODE = 0
    }
}
"#
    );
    let Some(observation) = run_probe("gpu", "", &mocks) else {
        return;
    };
    assert_eq!(observation["available"], false);
    assert_eq!(
        observation["error"],
        "nvidia-smi GPU query exited with code 7"
    );
    assert!(!observation.to_string().contains("SECRET"));
}

#[test]
fn snapshot_mock_filters_fastfetch_identity_fields() {
    let Some(observation) = run_probe(
        "snapshot",
        "",
        r#"
function Get-Command {
    [CmdletBinding()]
    param([string]$Name)
    if ($Name -eq 'fastfetch') {
        return [pscustomobject]@{ Source = 'fastfetch' }
    }
    return $null
}
function fastfetch {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    if ($Arguments -contains '--version') {
        Write-Output 'fastfetch 2.0.0'
    }
    else {
        Write-Output '[{"type":"Title","result":{"userName":"SECRET","homeDir":"C:\\private\\SECRET"}},{"type":"OS","result":{"prettyName":"Windows","version":"10","buildID":"26100","serial":"SECRET"}},{"type":"Kernel","result":{"name":"Windows NT","release":"10","architecture":"x86_64","uuid":"SECRET"}},{"type":"CPU","result":{"cpu":"Test CPU","vendor":"Vendor","cores":{"physical":8,"logical":16},"frequency":{"max":5000}}},{"type":"GPU","result":[{"name":"Test GPU","vendor":"Vendor","driver":"1.2","type":"Discrete"}]},{"type":"Memory","result":{"total":34359738368,"used":17179869184}},{"type":"Packages","result":{"all":42}},{"type":"Disk","result":[]}]'
    }
    $global:LASTEXITCODE = 0
}
"#,
    ) else {
        return;
    };
    assert_eq!(observation["collector"], "fastfetch");
    assert_eq!(observation["fastfetch_version"], "fastfetch 2.0.0");
    assert!(!observation.to_string().contains("SECRET"));
    assert_eq!(observation["gpus"][0]["name"], "Test GPU");
}

#[test]
fn snapshot_missing_fastfetch_uses_cim_fallback_with_warning() {
    let Some(observation) = run_probe(
        "snapshot",
        "",
        r#"
function Get-Command {
    [CmdletBinding()]
    param([string]$Name)
    return $null
}
function Get-CimInstance {
    param($ClassName, $Filter, $OperationTimeoutSec)
    if ($ClassName -eq 'Win32_OperatingSystem') {
        return [pscustomobject]@{
            Caption = 'Windows'; Version = '10.0'; BuildNumber = '26100'
            OSArchitecture = '64-bit'; TotalVisibleMemorySize = 32768000
            FreePhysicalMemory = 16384000
        }
    }
    if ($ClassName -eq 'Win32_Processor') {
        return [pscustomobject]@{
            Name = 'CPU'; Manufacturer = 'Vendor'; NumberOfCores = 8
            NumberOfLogicalProcessors = 16; MaxClockSpeed = 5000
        }
    }
    if ($ClassName -eq 'Win32_VideoController') {
        return [pscustomobject]@{
            Name = 'GPU'; AdapterCompatibility = 'Vendor'; DriverVersion = '1.2'
        }
    }
    return [pscustomobject]@{
        FileSystem = 'NTFS'; Size = 1000000000; FreeSpace = 400000000
    }
}
"#,
    ) else {
        return;
    };
    assert_eq!(observation["collector"], "powershell");
    assert_eq!(observation["fastfetch_available"], false);
    assert!(
        observation["warning"]
            .as_str()
            .is_some_and(|warning| !warning.is_empty())
    );
    assert_eq!(observation["memory_total_mb"], 32000);
    assert_eq!(observation["gpus"][0]["name"], "GPU");
}

#[test]
fn every_composed_probe_parses() {
    let Some(pwsh) = pwsh() else {
        println!("skipping probe parse test: pwsh not found on PATH");
        return;
    };
    let scratch = Scratch::new();
    for probe in [
        "transport",
        "overview",
        "network",
        "comfyui",
        "listener",
        "gpu",
        "snapshot",
    ] {
        compose(
            &scratch,
            probe,
            "expected_service = \"Svc's\"\npython = 'C:\\a b\\python.exe'\n",
        );
        let path = scratch.0.join(format!("{probe}.composed.ps1"));
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
            "{probe}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

// Structural checks that hold without a PowerShell runtime.

#[test]
fn listener_uses_local_filter_and_requires_every_owner_to_match() {
    let script = probe_text("listener");
    assert!(script.contains("Get-NetTCPConnection -ErrorAction Stop"));
    assert!(!script.contains("Get-NetTCPConnection -State"));
    assert!(script.contains("LocalPort") && script.contains("Where-Object"));
    assert!(script.contains("[string]$_.State -eq 'Listen'"));
    assert!(script.contains("TCP table inconsistent"));
    assert!(!script.contains("No MSFT_NetTCPConnection objects found"));
    assert!(!script.contains(".Exception.Message.Contains("));
    for needle in [
        "service_pid = $servicePid",
        "lineage = $lineage",
        "service_bound = $serviceBound",
        "canonical_python_in_lineage = $canonicalInLineage",
        "all_owners_service_bound = $allOwnersServiceBound",
        "all_owners_canonical_python = $allOwnersCanonical",
        "$processes | Where-Object { $_.service_bound -ne $true }",
        "$processes | Where-Object { $_.canonical_python_in_lineage -ne $true }",
    ] {
        assert!(script.contains(needle), "missing: {needle}");
    }
    let start = script.find("$verdict = 'listener-present'").unwrap();
    let missing = start + script[start..].find("if (-not $listening)").unwrap();
    let service = missing
        + script[missing..]
            .find("elseif ($null -ne $ExpectedService)")
            .unwrap();
    let health = service + script[service..].find("if (-not $serviceRunning)").unwrap();
    assert!(script[health..].contains("elseif ($allOwnersServiceBound -and $allOwnersCanonical)"));
}

#[test]
fn overview_health_is_derived_from_all_required_services() {
    let script = probe_text("overview");
    assert!(script.contains("$serviceNames = @('sshd')"));
    assert!(script.contains("$serviceNames += [string]$ExpectedService"));
    assert!(
        script
            .contains("$services | Where-Object { $_.present -ne $true -or $_.running -ne $true }")
    );
    assert!(script.contains("healthy = ($unhealthyServices.Count -eq 0)"));
    assert!(!script.contains("healthy = $true"));
}

#[test]
fn network_probe_uses_bounded_local_calls_and_full_health_expression() {
    let script = probe_text("network");
    assert!(script.contains("NetworkInterface]::GetAllNetworkInterfaces()"));
    assert!(script.contains("BeginConnect('127.0.0.1'"));
    assert!(script.contains("WaitOne($TimeoutMs"));
    assert!(!script.contains("Get-NetIPConfiguration"));
    assert!(!script.contains("Test-NetConnection"));
    let start = script.find("healthy = (").unwrap();
    let end = start + script[start..].find("computer_name =").unwrap();
    let health = &script[start..end];
    for needle in [
        "$adapters.Count -gt 0",
        "[bool]$sshListening",
        "[bool]$comfyListening",
        "$null -eq $networkError",
    ] {
        assert!(health.contains(needle), "missing: {needle}");
    }
    assert_eq!(health.matches("-and").count(), 3);
}

#[test]
fn gpu_and_snapshot_keep_their_bounded_contracts() {
    let gpu = probe_text("gpu");
    for needle in [
        "--query-gpu=",
        "--query-compute-apps=pid,process_name,used_memory",
        "--format=csv,noheader,nounits",
        "nvidia-smi is not available on the target",
        "nvidia-smi command not found",
        "nvidia-smi GPU query returned no GPU rows",
        "ConvertFrom-Csv",
    ] {
        assert!(gpu.contains(needle), "gpu missing: {needle}");
    }

    let snapshot = probe_text("snapshot");
    for needle in [
        "os_name",
        "kernel_release",
        "fastfetch_available",
        "collector",
        "PowerShell/CIM fallback used",
        "PowerShell/CIM fallback failed",
    ] {
        assert!(snapshot.contains(needle), "snapshot missing: {needle}");
    }
    let lower = snapshot.to_lowercase();
    let words: Vec<&str> = lower
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .collect();
    for forbidden in ["serial", "uuid", "sid", "username", "homedir"] {
        assert!(!words.contains(&forbidden), "snapshot contains {forbidden}");
    }
    assert!(!lower.contains("mountpoint"));
    assert!(!snapshot.contains("Exception.Message"));
}
