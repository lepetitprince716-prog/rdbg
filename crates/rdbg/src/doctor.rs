//! `rdbg doctor`: fixed, read-only diagnostic probes with strict observation contracts.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;

use serde_json::{Value, json};

use crate::hosts::{self, ComfyEntry};
use crate::{Config, ScriptSource, contracts};

pub const EXIT_CONFIG: i32 = 30;
pub const EXIT_UNKNOWN_TARGET: i32 = 31;
pub const EXIT_UNKNOWN_PROBE: i32 = 32;
pub const EXIT_BUSY: i32 = 33;
pub const EXIT_PROBE_PROTOCOL: i32 = 34;
pub const EXIT_RESULT_PROTOCOL: i32 = 35;
pub const EXIT_LOCAL_IO: i32 = 36;

/// Output text limit, counted in Unicode code points.
pub const MAX_OUTPUT_CHARS: usize = 32_000;
const TRUNCATION_MARKER: &str = "\n...[truncated]";

pub const DOCTOR_HELP: &str = r#"rdbg doctor - fixed read-only diagnostics for a configured Windows host

Usage:
  rdbg doctor [--config PATH] list
  rdbg doctor [--config PATH] ALIAS PROBE
  rdbg doctor [--config PATH] ALIAS PROBE --emit-script PATH
  rdbg doctor validate PROBE FILE [--stderr FILE]

PROBE is one of: transport, overview, network, comfyui, listener, gpu, snapshot.

ALIAS names a [hosts.ALIAS] table in hosts.toml, looked up in this order:
--config PATH, $RDBG_CONFIG, ${XDG_CONFIG_HOME:-$HOME/.config}/rdbg/hosts.toml.

Every command except --emit-script prints one JSON object on stdout.
--emit-script writes the composed probe script and does not run ssh.
validate reads a saved `rdbg --json ps ... --file` result and applies the same checks
as a live run; --stderr FILE supplies the local stderr captured with it.
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeId {
    Transport,
    Overview,
    Network,
    Comfyui,
    Listener,
    Gpu,
    Snapshot,
}

impl ProbeId {
    pub(crate) const ALL: [Self; 7] = [
        Self::Transport,
        Self::Overview,
        Self::Network,
        Self::Comfyui,
        Self::Listener,
        Self::Gpu,
        Self::Snapshot,
    ];

    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Overview => "overview",
            Self::Network => "network",
            Self::Comfyui => "comfyui",
            Self::Listener => "listener",
            Self::Gpu => "gpu",
            Self::Snapshot => "snapshot",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|probe| probe.id() == value)
    }

    pub(crate) fn schema(self) -> String {
        format!("rdbg.doctor.{}.v1", self.id())
    }

    fn label(self) -> &'static str {
        match self {
            Self::Transport => "PowerShell",
            Self::Overview => "System overview",
            Self::Network => "Network",
            Self::Comfyui => "ComfyUI",
            Self::Listener => "Listener identity",
            Self::Gpu => "GPU",
            Self::Snapshot => "Snapshot",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Transport => "SSH, PowerShell 5.1 and Unicode/quoting transport",
            Self::Overview => "Windows, memory, CPU and key services",
            Self::Network => "Active adapters and local SSH/ComfyUI listeners",
            Self::Comfyui => "Loopback system_stats, queue and version",
            Self::Listener => "ComfyUI port owner PID, executable, parent chain and service",
            Self::Gpu => "nvidia-smi memory, utilization, temperature, power and compute processes",
            Self::Snapshot => "Redacted Fastfetch system snapshot with PowerShell/CIM fallback",
        }
    }

    pub(crate) fn timeout_seconds(self) -> u64 {
        match self {
            Self::Transport | Self::Comfyui => 20,
            Self::Network | Self::Listener | Self::Gpu => 25,
            Self::Overview | Self::Snapshot => 30,
        }
    }

    pub(crate) fn body(self) -> &'static str {
        match self {
            Self::Transport => include_str!("../probes/transport.ps1"),
            Self::Overview => include_str!("../probes/overview.ps1"),
            Self::Network => include_str!("../probes/network.ps1"),
            Self::Comfyui => include_str!("../probes/comfyui.ps1"),
            Self::Listener => include_str!("../probes/listener.ps1"),
            Self::Gpu => include_str!("../probes/gpu.ps1"),
            Self::Snapshot => include_str!("../probes/snapshot.ps1"),
        }
    }
}

/// Quote a configured constant as a PowerShell single-quoted string.
fn ps_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn ps_literal(value: Option<&str>) -> String {
    value.map_or_else(|| "$null".to_owned(), ps_single_quote)
}

/// Prefix the probe body with the host's fixed constants.
pub(crate) fn compose_script(comfy: &ComfyEntry, probe: ProbeId) -> String {
    format!(
        "$ComfyPort = {}\n$ExpectedService = {}\n$ExpectedComfyVersion = {}\n$CanonicalPython = {}\n{}",
        comfy.port,
        ps_literal(comfy.expected_service.as_deref()),
        ps_literal(comfy.expected_version.as_deref()),
        ps_literal(comfy.python.as_deref()),
        probe.body(),
    )
}

/// Everything a doctor result reports besides target, probe and duration.
#[derive(Debug, Default)]
struct Outcome {
    ok: bool,
    error_class: Option<String>,
    message: Option<String>,
    process_exit_code: Option<i64>,
    rdbg_exit_code: Option<i64>,
    observation: Option<Value>,
    stdout: Option<String>,
    stderr: Option<String>,
    stdout_already_truncated: bool,
    stderr_already_truncated: bool,
}

impl Outcome {
    fn failure(class: &str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error_class: Some(class.to_owned()),
            message: Some(message.into()),
            ..Self::default()
        }
    }

    /// The doctor process exit code: 0, a doctor class code, or the rdbg code of the run.
    fn exit_code(&self) -> i32 {
        if self.ok {
            return crate::EXIT_OK;
        }
        match self.error_class.as_deref() {
            Some("config") => EXIT_CONFIG,
            Some("unknown_target") => EXIT_UNKNOWN_TARGET,
            Some("unknown_probe") => EXIT_UNKNOWN_PROBE,
            Some("busy") => EXIT_BUSY,
            Some("probe_protocol") => EXIT_PROBE_PROTOCOL,
            Some("result_protocol") => EXIT_RESULT_PROTOCOL,
            Some("local_io") => EXIT_LOCAL_IO,
            Some("usage") => crate::EXIT_USAGE,
            Some("local_input") => crate::EXIT_LOCAL_INPUT,
            _ => self
                .rdbg_exit_code
                .and_then(|code| i32::try_from(code).ok())
                .filter(|code| *code != crate::EXIT_OK)
                .unwrap_or(EXIT_RESULT_PROTOCOL),
        }
    }
}

/// Cut text to `MAX_OUTPUT_CHARS` code points, never inside a UTF-8 sequence.
pub(crate) fn clip(value: Option<String>) -> (Option<String>, bool) {
    let Some(mut text) = value else {
        return (None, false);
    };
    match text.char_indices().nth(MAX_OUTPUT_CHARS) {
        None => (Some(text), false),
        Some((cut, _)) => {
            text.truncate(cut);
            text.push_str(TRUNCATION_MARKER);
            (Some(text), true)
        }
    }
}

fn result_document(
    target: Option<&str>,
    probe: Option<&str>,
    duration_ms: u128,
    outcome: Outcome,
) -> Value {
    let (stdout, stdout_clipped) = clip(outcome.stdout);
    let (stderr, stderr_clipped) = clip(outcome.stderr);
    let healthy = outcome
        .observation
        .as_ref()
        .and_then(|observation| observation.get("healthy"))
        .and_then(Value::as_bool);
    let warning = outcome
        .observation
        .as_ref()
        .and_then(|observation| observation.get("warning"))
        .and_then(Value::as_str)
        .is_some_and(|warning| !warning.is_empty());
    let summary = if outcome.ok && healthy == Some(false) {
        "probe completed; unhealthy observation".to_owned()
    } else if outcome.ok && warning {
        "probe completed; warning".to_owned()
    } else if outcome.ok {
        "ready".to_owned()
    } else {
        outcome
            .message
            .clone()
            .filter(|message| !message.is_empty())
            .or_else(|| outcome.error_class.clone())
            .unwrap_or_else(|| "diagnostic failed".to_owned())
    };
    json!({
        "schema": "rdbg.doctor.result.v1",
        "target": target,
        "probe": probe,
        "ok": outcome.ok,
        "healthy": healthy,
        "summary": summary,
        "error_class": outcome.error_class,
        "message": outcome.message,
        "duration_ms": u64::try_from(duration_ms).unwrap_or(u64::MAX),
        "process_exit_code": outcome.process_exit_code,
        "rdbg_exit_code": outcome.rdbg_exit_code,
        "observation": outcome.observation,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": stdout_clipped || outcome.stdout_already_truncated,
        "stderr_truncated": stderr_clipped || outcome.stderr_already_truncated,
    })
}

fn emit(document: &Value) {
    let mut stdout = io::stdout().lock();
    let _ = serde_json::to_writer(&mut stdout, document);
    let _ = stdout.write_all(b"\n");
}

fn finish(target: Option<&str>, probe: Option<&str>, started: Instant, outcome: Outcome) -> i32 {
    let code = outcome.exit_code();
    emit(&result_document(
        target,
        probe,
        started.elapsed().as_millis(),
        outcome,
    ));
    code
}

/// What the caller expects the `rdbg.result.v1` document to describe.
#[derive(Debug, Default)]
struct Expect<'a> {
    target: Option<&'a str>,
    timeout_seconds: Option<u64>,
    actual_exit_code: Option<i32>,
}

fn is_int(value: Option<&Value>) -> bool {
    value.is_some_and(|value| value.is_i64() || value.is_u64())
}

/// Validate the complete `rdbg.result.v1` success/failure envelope.
fn validate_document(document: &Value, expect: &Expect<'_>) -> Result<(), String> {
    let Some(map) = document.as_object() else {
        return Err("rdbg returned a non-object result".to_owned());
    };
    if map.get("schema").and_then(Value::as_str) != Some("rdbg.result.v1") {
        return Err("rdbg returned an unexpected schema".to_owned());
    }
    let Some(ok) = map.get("ok").and_then(Value::as_bool) else {
        return Err("rdbg result field ok must be boolean".to_owned());
    };

    if !is_int(map.get("rdbg_exit_code")) {
        return Err("rdbg result field rdbg_exit_code must be an integer".to_owned());
    }
    let rdbg_exit_code = map["rdbg_exit_code"].as_i64().unwrap_or(i64::MAX);
    if let Some(actual) = expect.actual_exit_code
        && rdbg_exit_code != i64::from(actual)
    {
        return Err("rdbg reported an exit code inconsistent with the adapter process".to_owned());
    }
    if ok != (rdbg_exit_code == 0) {
        return Err("rdbg result field ok is inconsistent with its exit code".to_owned());
    }

    let process_exit_code = map.get("process_exit_code").unwrap_or(&Value::Null);
    if !process_exit_code.is_null() && !is_int(Some(process_exit_code)) {
        return Err("rdbg result field process_exit_code must be an integer or null".to_owned());
    }
    let process_exit_code = process_exit_code.as_i64();
    if ok && process_exit_code != Some(0) {
        return Err("successful rdbg result must report remote process exit code 0".to_owned());
    }

    match expect.target {
        Some(target) if map.get("target").and_then(Value::as_str) != Some(target) => {
            return Err("rdbg result target does not match the requested target".to_owned());
        }
        None if !map.get("target").is_some_and(Value::is_string) => {
            return Err("rdbg result field target must be a string".to_owned());
        }
        _ => {}
    }
    if map.get("mode").and_then(Value::as_str) != Some("file") {
        return Err("rdbg result mode does not match the fixed file transport".to_owned());
    }
    let timeout_seconds = map.get("timeout_seconds");
    match expect.timeout_seconds {
        Some(expected)
            if !is_int(timeout_seconds)
                || timeout_seconds.and_then(Value::as_u64) != Some(expected) =>
        {
            return Err("rdbg result timeout does not match the fixed probe timeout".to_owned());
        }
        None if !(is_int(timeout_seconds) || timeout_seconds.is_some_and(Value::is_null)) => {
            return Err("rdbg result field timeout_seconds must be an integer or null".to_owned());
        }
        _ => {}
    }

    for field in ["stdout", "stderr"] {
        if !map.get(field).is_some_and(Value::is_string) {
            return Err(format!("rdbg result field {field} must be a string"));
        }
    }
    for field in [
        "stdout_utf8_lossy",
        "stderr_utf8_lossy",
        "stdout_truncated",
        "stderr_truncated",
    ] {
        if !map.get(field).is_some_and(Value::is_boolean) {
            return Err(format!("rdbg result field {field} must be boolean"));
        }
    }

    let error_class = map.get("error_class").unwrap_or(&Value::Null);
    let message = map.get("message").unwrap_or(&Value::Null);
    if !error_class.is_null() && !error_class.is_string() {
        return Err("rdbg result field error_class must be a string or null".to_owned());
    }
    if !message.is_null() && !message.is_string() {
        return Err("rdbg result field message must be a string or null".to_owned());
    }
    if ok && (!error_class.is_null() || !message.is_null()) {
        return Err("successful rdbg result must not report an error".to_owned());
    }
    if !ok && error_class.as_str().is_none_or(str::is_empty) {
        return Err("failed rdbg result must report an error class".to_owned());
    }
    if !ok && message.as_str().is_none_or(str::is_empty) {
        return Err("failed rdbg result must report an error message".to_owned());
    }

    let error_class = error_class.as_str();
    let class_matches = match rdbg_exit_code {
        0 => error_class.is_none(),
        2 => error_class == Some("usage"),
        10 => error_class == Some("local_input"),
        20 => error_class == Some("ssh_launch"),
        21 => error_class == Some("ssh_io"),
        22 => matches!(
            error_class,
            Some(
                "cloudflared_handshake"
                    | "ssh_hostkey"
                    | "ssh_auth"
                    | "ssh_timeout"
                    | "dns_resolution"
                    | "connection_refused"
                    | "ssh_transport"
            )
        ),
        23 => error_class == Some("remote_command"),
        24 => error_class == Some("ssh_terminated"),
        25 => error_class == Some("execution_timeout"),
        _ => false,
    };
    if !class_matches {
        return Err("rdbg error class is inconsistent with its exit code".to_owned());
    }
    if matches!(rdbg_exit_code, 2 | 10 | 20 | 24 | 25) && process_exit_code.is_some() {
        return Err(
            "rdbg remote process exit code is inconsistent with its adapter exit code".to_owned(),
        );
    }
    if rdbg_exit_code == 22 && process_exit_code != Some(255) {
        return Err("rdbg transport failure must report remote process exit code 255".to_owned());
    }
    if rdbg_exit_code == 23 && matches!(process_exit_code, None | Some(0 | 255)) {
        return Err(
            "rdbg remote-command failure must report its nonzero remote exit code".to_owned(),
        );
    }
    if ok
        && (map["stdout_utf8_lossy"] == Value::Bool(true)
            || map["stderr_utf8_lossy"] == Value::Bool(true))
    {
        return Err("successful rdbg result must contain lossless UTF-8 output".to_owned());
    }
    Ok(())
}

fn validate_probe_observation(remote_stdout: &str, probe: ProbeId) -> Result<Value, String> {
    if remote_stdout.chars().count() > MAX_OUTPUT_CHARS {
        return Err("remote probe output exceeded the observation limit".to_owned());
    }
    contracts::validate_observation(remote_stdout, probe).map_err(|detail| {
        format!("remote probe observation violated its versioned contract: {detail}")
    })
}

/// Turn a parsed `rdbg.result.v1` document into a doctor outcome.
fn postprocess_document(
    document: &Value,
    raw: &str,
    local_stderr: &str,
    probe: ProbeId,
    expect: &Expect<'_>,
) -> Outcome {
    if let Err(message) = validate_document(document, expect) {
        return Outcome {
            stdout: Some(raw.to_owned()),
            stderr: Some(local_stderr.to_owned()),
            ..Outcome::failure("result_protocol", message)
        };
    }

    // validate_document established the type of every field read below.
    let remote_stdout = document["stdout"].as_str().unwrap_or_default();
    let remote_stderr = document["stderr"].as_str().unwrap_or_default();
    let stdout_truncated = document["stdout_truncated"].as_bool().unwrap_or(false);
    let stderr_truncated = document["stderr_truncated"].as_bool().unwrap_or(false);
    let mut ok = document["ok"].as_bool().unwrap_or(false) && local_stderr.is_empty();
    let mut error_class = document["error_class"].as_str().map(ToOwned::to_owned);
    let mut message = document["message"].as_str().map(ToOwned::to_owned);
    let mut observation = None;

    if !local_stderr.is_empty() {
        ok = false;
        error_class = Some("result_protocol".to_owned());
        message = Some("rdbg wrote to local stderr in JSON mode".to_owned());
    } else if ok && (stdout_truncated || stderr_truncated) {
        ok = false;
        error_class = Some("probe_protocol".to_owned());
        message = Some("remote probe output was truncated".to_owned());
    } else if ok {
        match validate_probe_observation(remote_stdout, probe) {
            Ok(value) => observation = Some(value),
            Err(probe_error) => {
                ok = false;
                error_class = Some("probe_protocol".to_owned());
                message = Some(probe_error);
            }
        }
    }

    let stderr = if remote_stderr.is_empty() {
        local_stderr
    } else {
        remote_stderr
    };
    Outcome {
        ok,
        error_class,
        message,
        process_exit_code: document["process_exit_code"].as_i64(),
        rdbg_exit_code: document["rdbg_exit_code"].as_i64(),
        stdout: observation.is_none().then(|| remote_stdout.to_owned()),
        observation,
        stderr: Some(stderr.to_owned()),
        stdout_already_truncated: stdout_truncated,
        stderr_already_truncated: stderr_truncated,
    }
}

/// Parse saved runner stdout and post-process it.
fn postprocess_text(
    runner_stdout: &str,
    local_stderr: &str,
    probe: ProbeId,
    expect: &Expect<'_>,
) -> Outcome {
    let raw = runner_stdout.trim();
    match serde_json::from_str::<Value>(raw) {
        Ok(document) => postprocess_document(&document, raw, local_stderr, probe, expect),
        Err(_) => Outcome {
            stdout: Some(raw.to_owned()),
            stderr: Some(local_stderr.to_owned()),
            ..Outcome::failure("result_protocol", "rdbg returned invalid JSON")
        },
    }
}

#[derive(Debug)]
enum Command {
    Help,
    List,
    Run {
        alias: String,
        probe: String,
        emit_script: Option<PathBuf>,
    },
    Validate {
        probe: String,
        file: PathBuf,
        stderr_file: Option<PathBuf>,
    },
}

#[derive(Debug)]
struct Parsed {
    config: Option<OsString>,
    command: Command,
}

fn parse(args: &[OsString]) -> Result<Parsed, String> {
    let mut config = None;
    let mut emit_script = None;
    let mut stderr_file = None;
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index]
            .to_str()
            .ok_or("arguments must be valid Unicode")?;
        match arg {
            "-h" | "--help" => {
                return Ok(Parsed {
                    config,
                    command: Command::Help,
                });
            }
            "--config" | "--emit-script" | "--stderr" => {
                let value = args
                    .get(index + 1)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| format!("{arg} requires a path"))?
                    .clone();
                let slot = match arg {
                    "--config" => &mut config,
                    "--emit-script" => &mut emit_script,
                    _ => &mut stderr_file,
                };
                if slot.replace(value).is_some() {
                    return Err(format!("{arg} given more than once"));
                }
                index += 2;
            }
            _ if arg.starts_with('-') => return Err(format!("unknown option: {arg}")),
            _ => {
                positionals.push(arg.to_owned());
                index += 1;
            }
        }
    }

    let command = match positionals.as_slice() {
        [list] if list == "list" && emit_script.is_none() && stderr_file.is_none() => Command::List,
        [validate, probe, file]
            if validate == "validate" && emit_script.is_none() && config.is_none() =>
        {
            Command::Validate {
                probe: probe.clone(),
                file: PathBuf::from(file),
                stderr_file: stderr_file.map(PathBuf::from),
            }
        }
        [alias, probe] if alias != "list" && alias != "validate" && stderr_file.is_none() => {
            Command::Run {
                alias: alias.clone(),
                probe: probe.clone(),
                emit_script: emit_script.map(PathBuf::from),
            }
        }
        _ => return Err("expected 'list', 'ALIAS PROBE' or 'validate PROBE FILE'".to_owned()),
    };
    Ok(Parsed { config, command })
}

fn capabilities(hosts: &hosts::Hosts) -> Value {
    json!({
        "schema": "rdbg.doctor.capabilities.v1",
        "transport": "rdbg/system-ssh/powershell-encoded-stdin",
        "arbitrary_script": false,
        "config_loaded": hosts.loaded,
        "targets": hosts.hosts.keys().map(|alias| json!({"id": alias})).collect::<Vec<_>>(),
        "probes": ProbeId::ALL.iter().map(|probe| json!({
            "id": probe.id(),
            "label": probe.label(),
            "description": probe.description(),
            "timeout_s": probe.timeout_seconds(),
        })).collect::<Vec<_>>(),
    })
}

fn lock_path(alias: &str) -> Result<PathBuf, String> {
    let base = match std::env::var_os("XDG_STATE_HOME").filter(|value| !value.is_empty()) {
        Some(base) => PathBuf::from(base),
        None => match std::env::var_os("HOME").filter(|value| !value.is_empty()) {
            Some(home) => PathBuf::from(home).join(".local").join("state"),
            None => {
                return Err(
                    "cannot locate the lock directory: set XDG_STATE_HOME or HOME".to_owned(),
                );
            }
        },
    };
    Ok(base
        .join("rdbg")
        .join("locks")
        .join(format!("{alias}.lock")))
}

/// A local failure before any result exists: error class and message.
type LocalFailure = (&'static str, String);

fn local_failure(failure: LocalFailure) -> Outcome {
    Outcome::failure(failure.0, failure.1)
}

/// Take the per-alias single-flight lock. The OS releases it when the process exits.
fn acquire_lock(alias: &str) -> Result<File, LocalFailure> {
    let path = lock_path(alias).map_err(|message| ("local_io", message))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            (
                "local_io",
                format!("failed to create lock directory: {error}"),
            )
        })?;
    }
    let file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|error| ("local_io", format!("failed to open lock file: {error}")))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(fs::TryLockError::WouldBlock) => Err((
            "busy",
            format!("{alias} already has a diagnostic in progress"),
        )),
        Err(fs::TryLockError::Error(error)) => {
            Err(("local_io", format!("failed to lock {alias}: {error}")))
        }
    }
}

fn run_probe(
    config_path: Option<&OsString>,
    alias: &str,
    probe_name: &str,
    emit_script: Option<PathBuf>,
    started: Instant,
) -> i32 {
    let target = Some(alias);
    let probe_label = Some(probe_name);
    let hosts = match hosts::load(config_path) {
        Ok(hosts) => hosts,
        Err(message) => {
            return finish(
                target,
                probe_label,
                started,
                Outcome::failure("config", message),
            );
        }
    };
    let Some(host) = hosts.hosts.get(alias) else {
        return finish(
            target,
            probe_label,
            started,
            Outcome::failure("unknown_target", format!("unknown target: {alias}")),
        );
    };
    let Some(probe) = ProbeId::parse(probe_name) else {
        return finish(
            target,
            probe_label,
            started,
            Outcome::failure("unknown_probe", format!("unknown probe: {probe_name}")),
        );
    };

    let script = compose_script(&host.comfy, probe);
    if let Some(path) = emit_script {
        return match fs::write(&path, script.as_bytes()) {
            Ok(()) => crate::EXIT_OK,
            Err(error) => finish(
                target,
                probe_label,
                started,
                Outcome::failure(
                    "local_io",
                    format!("failed to write '{}': {error}", path.display()),
                ),
            ),
        };
    }

    let _lock = match acquire_lock(alias) {
        Ok(lock) => lock,
        Err(failure) => return finish(target, probe_label, started, local_failure(failure)),
    };

    let config = Config {
        json: true,
        ssh: OsString::from(&host.ssh_bin),
        no_ssh_opts: host.no_ssh_opts,
        timeout_seconds: Some(probe.timeout_seconds()),
        target: host.ssh.clone(),
        source: ScriptSource::Stdin,
    };
    let (document, code) = match crate::execute(&config, &script) {
        Ok(result) => crate::process_result_document(&result),
        Err(failure) => crate::failure_document(&failure),
    };
    let expect = Expect {
        target: Some(&host.ssh),
        timeout_seconds: Some(probe.timeout_seconds()),
        actual_exit_code: Some(code),
    };
    let raw = document.to_string();
    let outcome = postprocess_document(&document, &raw, "", probe, &expect);
    finish(target, probe_label, started, outcome)
}

fn read_text(path: &PathBuf) -> Result<String, LocalFailure> {
    fs::read(path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .map_err(|error| {
            (
                "local_input",
                format!("failed to read '{}': {error}", path.display()),
            )
        })
}

fn validate_saved(
    probe_name: &str,
    file: &PathBuf,
    stderr_file: Option<&PathBuf>,
    started: Instant,
) -> i32 {
    let probe_label = Some(probe_name);
    let Some(probe) = ProbeId::parse(probe_name) else {
        return finish(
            None,
            probe_label,
            started,
            Outcome::failure("unknown_probe", format!("unknown probe: {probe_name}")),
        );
    };
    let runner_stdout = match read_text(file) {
        Ok(text) => text,
        Err(failure) => return finish(None, probe_label, started, local_failure(failure)),
    };
    let local_stderr = match stderr_file.map(read_text).transpose() {
        Ok(text) => text.unwrap_or_default(),
        Err(failure) => return finish(None, probe_label, started, local_failure(failure)),
    };
    let target = serde_json::from_str::<Value>(runner_stdout.trim())
        .ok()
        .and_then(|document| document.get("target")?.as_str().map(ToOwned::to_owned));
    let outcome = postprocess_text(&runner_stdout, &local_stderr, probe, &Expect::default());
    finish(target.as_deref(), probe_label, started, outcome)
}

pub(crate) fn main(args: &[OsString]) -> i32 {
    let started = Instant::now();
    let parsed = match parse(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            let message = format!("{message}; try 'rdbg doctor --help'");
            return finish(None, None, started, Outcome::failure("usage", message));
        }
    };
    match parsed.command {
        Command::Help => {
            let _ = io::stdout().write_all(DOCTOR_HELP.as_bytes());
            crate::EXIT_OK
        }
        Command::List => match hosts::load(parsed.config.as_ref()) {
            Ok(hosts) => {
                emit(&capabilities(&hosts));
                crate::EXIT_OK
            }
            Err(message) => finish(None, None, started, Outcome::failure("config", message)),
        },
        Command::Run {
            alias,
            probe,
            emit_script,
        } => run_probe(parsed.config.as_ref(), &alias, &probe, emit_script, started),
        Command::Validate {
            probe,
            file,
            stderr_file,
        } => validate_saved(&probe, &file, stderr_file.as_ref(), started),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_quote_escaping_matches_powershell() {
        assert_eq!(ps_single_quote("O'Reilly"), "'O''Reilly'");
        assert_eq!(ps_literal(None), "$null");
        assert_eq!(ps_literal(Some(r"C:\a b\$x")), r"'C:\a b\$x'");
    }

    #[test]
    fn compose_prefixes_constants_in_fixed_order() {
        let comfy = ComfyEntry {
            port: 9188,
            expected_service: None,
            expected_version: Some("1.0.0".to_owned()),
            python: None,
        };
        let script = compose_script(&comfy, ProbeId::Comfyui);
        assert!(script.starts_with(
            "$ComfyPort = 9188\n$ExpectedService = $null\n$ExpectedComfyVersion = '1.0.0'\n$CanonicalPython = $null\n$ErrorActionPreference"
        ));
        assert!(script.contains("Invoke-RestMethod"));
    }

    #[test]
    fn probe_files_carry_their_versioned_schema() {
        for probe in ProbeId::ALL {
            assert!(
                probe.body().contains(&format!("'{}'", probe.schema())),
                "{}",
                probe.id()
            );
        }
    }

    #[test]
    fn clip_counts_code_points() {
        let text = "中".repeat(MAX_OUTPUT_CHARS);
        assert_eq!(clip(Some(text.clone())), (Some(text.clone()), false));
        let (clipped, truncated) = clip(Some(format!("{text}文🙂")));
        assert!(truncated);
        assert_eq!(clipped.unwrap(), format!("{text}{TRUNCATION_MARKER}"));
        assert_eq!(clip(None), (None, false));
    }

    fn ok_document(stdout: &str, stderr: &str) -> Value {
        json!({
            "schema": "rdbg.result.v1", "ok": true, "error_class": null, "rdbg_exit_code": 0,
            "process_exit_code": 0, "target": "box-a", "mode": "file", "timeout_seconds": 20,
            "stdout": stdout, "stderr": stderr, "stdout_utf8_lossy": false,
            "stderr_utf8_lossy": false, "stdout_truncated": false, "stderr_truncated": false,
            "message": null
        })
    }

    #[test]
    fn stderr_prefers_remote_then_local() {
        let expect = Expect::default();
        let document = ok_document("not json", "remote warning");
        let outcome = postprocess_document(&document, "", "", ProbeId::Transport, &expect);
        assert_eq!(outcome.stderr.as_deref(), Some("remote warning"));

        let document = ok_document("not json", "");
        let outcome = postprocess_document(&document, "", "local", ProbeId::Transport, &expect);
        assert_eq!(outcome.stderr.as_deref(), Some("local"));
        assert_eq!(outcome.error_class.as_deref(), Some("result_protocol"));
    }

    #[test]
    fn envelope_checks_mirror_the_reference_driver() {
        let expect = Expect {
            target: Some("box-a"),
            timeout_seconds: Some(20),
            actual_exit_code: Some(0),
        };
        assert!(validate_document(&ok_document("", ""), &expect).is_ok());

        let mutations: &[(&str, Value)] = &[
            ("schema", json!("other")),
            ("ok", json!(false)),
            ("rdbg_exit_code", json!(7)),
            ("process_exit_code", json!(1)),
            ("target", json!("box-b")),
            ("mode", json!("eval")),
            ("timeout_seconds", json!(21)),
            ("stdout", json!(null)),
            ("stdout_truncated", json!(null)),
            ("stderr_utf8_lossy", json!(true)),
            ("error_class", json!("ssh_io")),
            ("message", json!("x")),
        ];
        for (key, value) in mutations {
            let mut document = ok_document("", "");
            document[*key] = value.clone();
            assert!(
                validate_document(&document, &expect).is_err(),
                "accepted {key} = {value}"
            );
        }

        let mut auth_with_code_zero = ok_document("partial", "");
        auth_with_code_zero["ok"] = json!(false);
        auth_with_code_zero["rdbg_exit_code"] = json!(25);
        auth_with_code_zero["error_class"] = json!("ssh_auth");
        auth_with_code_zero["message"] = json!("timed out");
        auth_with_code_zero["process_exit_code"] = Value::Null;
        let expect_25 = Expect {
            actual_exit_code: Some(25),
            ..expect
        };
        let error = validate_document(&auth_with_code_zero, &expect_25).unwrap_err();
        assert!(error.contains("inconsistent"), "{error}");
    }

    #[test]
    fn exit_codes_are_distinct() {
        let codes = [
            crate::EXIT_OK,
            crate::EXIT_USAGE,
            crate::EXIT_LOCAL_INPUT,
            crate::EXIT_SSH_LAUNCH,
            crate::EXIT_SSH_IO,
            crate::EXIT_SSH_TRANSPORT,
            crate::EXIT_REMOTE_COMMAND,
            crate::EXIT_SSH_TERMINATED,
            crate::EXIT_EXECUTION_TIMEOUT,
            EXIT_CONFIG,
            EXIT_UNKNOWN_TARGET,
            EXIT_UNKNOWN_PROBE,
            EXIT_BUSY,
            EXIT_PROBE_PROTOCOL,
            EXIT_RESULT_PROTOCOL,
            EXIT_LOCAL_IO,
        ];
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
    }
}
