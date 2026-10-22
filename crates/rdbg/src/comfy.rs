//! `rdbg comfy`: manage an already installed ComfyUI as a Windows service.
//!
//! One fixed remote script (`remote/comfy-service.ps1`) runs one of four actions.
//! rdbg never installs ComfyUI itself; `install-service` only wraps an existing
//! installation with a pinned shawl.exe.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;

use serde_json::{Value, json};

use crate::comfy_contracts::{self, ActionOutcome};
use crate::envelope::{
    self, Expect, LocalFailure, MAX_OUTPUT_CHARS, Outcome, acquire_lock, clip, emit, local_failure,
    ps_literal, ps_single_quote, read_text,
};
use crate::hosts::{self, HostEntry};
use crate::{Config, ScriptSource};

/// The shawl release `install-service` expects.
pub const SHAWL_VERSION: &str = "v1.9.0";
/// SHA-256 of `shawl-v1.9.0-win64.zip` as published with the release.
pub const SHAWL_WIN64_ZIP_SHA256: &str =
    "f883c5d09c9beae2efaeabd8513e7d3f57cd1d0864cec3df4f4a7b6ee904351c";
// Placeholder: must be replaced with the hash of shawl.exe from the pinned zip before release.
pub const SHAWL_EXE_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

pub(crate) const SCRIPT_BODY: &str = include_str!("../remote/comfy-service.ps1");

const TRUNCATED_MESSAGE: &str = "remote action output was truncated";

pub const COMFY_HELP: &str = r#"rdbg comfy - manage an installed ComfyUI as a Windows service

Usage:
  rdbg comfy [--config PATH] ALIAS status
  rdbg comfy [--config PATH] ALIAS restart
  rdbg comfy [--config PATH] ALIAS install-service --shawl-exe REMOTE_PATH [--start-type auto|manual]
  rdbg comfy [--config PATH] ALIAS uninstall-service
  rdbg comfy [--config PATH] ALIAS ACTION [ACTION OPTIONS] --emit-script PATH
  rdbg comfy validate ACTION FILE [--stderr FILE]
  rdbg comfy shawl

ALIAS names a [hosts.ALIAS] table in hosts.toml, found as for rdbg doctor.
The [hosts.ALIAS.comfy] table supplies port, expected_service, expected_version,
python, root, listen and args.

status is read-only. restart, install-service and uninstall-service need an
administrator session and refuse, changing nothing, when a guard fails.
rdbg never installs ComfyUI; install-service wraps an existing installation in a
service with the pinned shawl.exe that `rdbg comfy shawl` describes.

Every command except --emit-script and --help prints one JSON object on stdout.
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActionId {
    Status,
    Restart,
    InstallService,
    UninstallService,
}

impl ActionId {
    pub(crate) const ALL: [Self; 4] = [
        Self::Status,
        Self::Restart,
        Self::InstallService,
        Self::UninstallService,
    ];

    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Restart => "restart",
            Self::InstallService => "install-service",
            Self::UninstallService => "uninstall-service",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|action| action.id() == value)
    }

    pub(crate) fn schema(self) -> String {
        format!("rdbg.comfy.{}.v1", self.id())
    }

    pub(crate) fn timeout_seconds(self) -> u64 {
        match self {
            Self::Status => 30,
            Self::Restart => 150,
            Self::InstallService => 210,
            Self::UninstallService => 90,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartType {
    Auto,
    Manual,
}

impl StartType {
    fn id(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
        }
    }
}

/// Options that only `install-service` takes.
#[derive(Debug, Clone, Default)]
struct InstallOptions {
    shawl_exe: Option<String>,
    start_type: Option<StartType>,
}

/// A PowerShell array literal of single-quoted strings.
fn ps_array(values: &[String]) -> String {
    let items: Vec<String> = values.iter().map(|value| ps_single_quote(value)).collect();
    format!("@({})", items.join(", "))
}

fn compose_script(host: &HostEntry, action: ActionId, install: &InstallOptions) -> String {
    let start_type = (action == ActionId::InstallService)
        .then(|| install.start_type.unwrap_or(StartType::Auto).id());
    format!(
        "{}$Action = {}\n$ComfyRoot = {}\n$ComfyListen = {}\n$ComfyArgs = {}\n$ShawlExe = {}\n\
         $ShawlSha256 = {}\n$StartType = {}\n{}",
        crate::doctor::constants_prefix(&host.comfy),
        ps_single_quote(action.id()),
        ps_literal(host.service.root.as_deref()),
        ps_single_quote(&host.service.listen),
        ps_array(&host.service.args),
        ps_literal(install.shawl_exe.as_deref()),
        ps_single_quote(SHAWL_EXE_SHA256),
        ps_literal(start_type),
        SCRIPT_BODY,
    )
}

/// The per-action configuration checks that run before any ssh process starts.
fn check_config(alias: &str, host: &HostEntry, action: ActionId) -> Result<(), String> {
    let key = |name: &str| format!("hosts.{alias}.comfy.{name}");
    if let Some(service) = &host.comfy.expected_service
        && !hosts::is_valid_service_name(service)
    {
        return Err(format!(
            "{} must be 1-64 characters of A-Z a-z 0-9 . _ - for rdbg comfy",
            key("expected_service")
        ));
    }
    let needs_service = action != ActionId::Status;
    if needs_service && host.comfy.expected_service.is_none() {
        return Err(format!(
            "{} is required for {}",
            key("expected_service"),
            action.id()
        ));
    }
    if action == ActionId::InstallService {
        for (name, value) in [
            ("root", host.service.root.as_deref()),
            ("python", host.comfy.python.as_deref()),
        ] {
            match value {
                None => return Err(format!("{} is required for install-service", key(name))),
                Some(value) if !hosts::is_command_line_safe(value) => {
                    return Err(format!(
                        "{} must be non-empty and contain no '\"' or control characters",
                        key(name)
                    ));
                }
                Some(_) => {}
            }
        }
        let listen = &host.service.listen;
        if !hosts::is_command_line_safe(listen) || listen.chars().any(char::is_whitespace) {
            return Err(format!(
                "{} must be a non-empty address without spaces, '\"' or control characters",
                key("listen")
            ));
        }
    }
    Ok(())
}

fn validate_action_observation(
    remote_stdout: &str,
    action: ActionId,
) -> Result<(Value, ActionOutcome), String> {
    if remote_stdout.chars().count() > MAX_OUTPUT_CHARS {
        return Err("remote action output exceeded the observation limit".to_owned());
    }
    comfy_contracts::validate_observation(remote_stdout, action).map_err(|detail| {
        format!("remote action observation violated its versioned contract: {detail}")
    })
}

/// Validate one action's observation against its contract.
fn observe(text: &str, action: ActionId) -> Result<Value, String> {
    validate_action_observation(text, action).map(|(value, _)| value)
}

fn apply_action_outcome(mut outcome: Outcome) -> Outcome {
    let Some(observation) = &outcome.observation else {
        return outcome;
    };
    let reasons = observation["reasons"]
        .as_array()
        .map(|reasons| {
            reasons
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let (class, verb) = match observation["outcome"].as_str() {
        Some("refused") => ("refused", "refused"),
        Some("failed") => ("action_failed", "failed"),
        _ => return outcome,
    };
    outcome.ok = false;
    outcome.error_class = Some(class.to_owned());
    outcome.message = Some(format!("action {verb}: {reasons}"));
    outcome
}

fn postprocess_document(
    document: &Value,
    raw: &str,
    local_stderr: &str,
    action: ActionId,
    expect: &Expect<'_>,
) -> Outcome {
    apply_action_outcome(envelope::postprocess_document(
        document,
        raw,
        local_stderr,
        expect,
        TRUNCATED_MESSAGE,
        |text| observe(text, action),
    ))
}

fn postprocess_text(
    runner_stdout: &str,
    local_stderr: &str,
    action: ActionId,
    expect: &Expect<'_>,
) -> Outcome {
    apply_action_outcome(envelope::postprocess_text(
        runner_stdout,
        local_stderr,
        expect,
        TRUNCATED_MESSAGE,
        |text| observe(text, action),
    ))
}

fn result_document(
    target: Option<&str>,
    action: Option<&str>,
    duration_ms: u128,
    outcome: Outcome,
) -> Value {
    let (stdout, stdout_clipped) = clip(outcome.stdout);
    let (stderr, stderr_clipped) = clip(outcome.stderr);
    let action_outcome = outcome
        .observation
        .as_ref()
        .and_then(|observation| observation.get("outcome"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let summary = if outcome.ok {
        let changed = outcome
            .observation
            .as_ref()
            .and_then(|observation| observation["changed"].as_bool())
            .unwrap_or(false);
        if changed { "done; changed" } else { "done" }.to_owned()
    } else {
        outcome
            .message
            .clone()
            .filter(|message| !message.is_empty())
            .or_else(|| outcome.error_class.clone())
            .unwrap_or_else(|| "action failed".to_owned())
    };
    json!({
        "schema": "rdbg.comfy.result.v1",
        "target": target,
        "action": action,
        "ok": outcome.ok,
        "outcome": action_outcome,
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

fn finish(target: Option<&str>, action: Option<&str>, started: Instant, outcome: Outcome) -> i32 {
    let code = outcome.exit_code();
    emit(&result_document(
        target,
        action,
        started.elapsed().as_millis(),
        outcome,
    ));
    code
}

fn shawl_pins() -> Value {
    json!({
        "schema": "rdbg.comfy.shawl.v1",
        "version": SHAWL_VERSION,
        "win64_zip_sha256": SHAWL_WIN64_ZIP_SHA256,
        "exe_sha256": SHAWL_EXE_SHA256,
    })
}

#[derive(Debug)]
enum Command {
    Help,
    Shawl,
    Run {
        alias: String,
        action: ActionId,
        install: InstallOptions,
        emit_script: Option<PathBuf>,
    },
    Validate {
        action: ActionId,
        file: PathBuf,
        stderr_file: Option<PathBuf>,
    },
}

#[derive(Debug)]
struct Parsed {
    config: Option<OsString>,
    command: Command,
}

fn parse_action(value: &str) -> Result<ActionId, String> {
    ActionId::parse(value).ok_or_else(|| {
        format!(
            "unknown action: {value}; expected one of {}",
            ActionId::ALL.map(ActionId::id).join(", ")
        )
    })
}

fn parse(args: &[OsString]) -> Result<Parsed, String> {
    let mut config = None;
    let mut emit_script = None;
    let mut stderr_file = None;
    let mut shawl_exe: Option<OsString> = None;
    let mut start_type: Option<OsString> = None;
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
            "--config" | "--emit-script" | "--stderr" | "--shawl-exe" | "--start-type" => {
                let value = args
                    .get(index + 1)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| format!("{arg} requires a value"))?
                    .clone();
                let slot = match arg {
                    "--config" => &mut config,
                    "--emit-script" => &mut emit_script,
                    "--stderr" => &mut stderr_file,
                    "--shawl-exe" => &mut shawl_exe,
                    _ => &mut start_type,
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

    let install_flags = shawl_exe.is_some() || start_type.is_some();
    let command = match positionals.as_slice() {
        [shawl]
            if shawl == "shawl"
                && config.is_none()
                && emit_script.is_none()
                && stderr_file.is_none()
                && !install_flags =>
        {
            Command::Shawl
        }
        [validate, action, file]
            if validate == "validate"
                && config.is_none()
                && emit_script.is_none()
                && !install_flags =>
        {
            Command::Validate {
                action: parse_action(action)?,
                file: PathBuf::from(file),
                stderr_file: stderr_file.map(PathBuf::from),
            }
        }
        [alias, action] if alias != "validate" && stderr_file.is_none() => {
            let action = parse_action(action)?;
            let install = if action == ActionId::InstallService {
                let shawl_exe = shawl_exe
                    .ok_or("install-service requires --shawl-exe REMOTE_PATH")?
                    .into_string()
                    .map_err(|_| "arguments must be valid Unicode")?;
                if !hosts::is_command_line_safe(&shawl_exe) {
                    return Err("--shawl-exe must contain no '\"' or control characters".to_owned());
                }
                let start_type = match start_type.as_ref().map(|value| value.to_str()) {
                    None => None,
                    Some(Some("auto")) => Some(StartType::Auto),
                    Some(Some("manual")) => Some(StartType::Manual),
                    Some(_) => return Err("--start-type must be auto or manual".to_owned()),
                };
                InstallOptions {
                    shawl_exe: Some(shawl_exe),
                    start_type,
                }
            } else if install_flags {
                return Err("--shawl-exe and --start-type apply only to install-service".to_owned());
            } else {
                InstallOptions::default()
            };
            Command::Run {
                alias: alias.clone(),
                action,
                install,
                emit_script: emit_script.map(PathBuf::from),
            }
        }
        _ => {
            return Err("expected 'ALIAS ACTION', 'validate ACTION FILE' or 'shawl'".to_owned());
        }
    };
    Ok(Parsed { config, command })
}

fn run_action(
    config_path: Option<&OsString>,
    alias: &str,
    action: ActionId,
    install: &InstallOptions,
    emit_script: Option<PathBuf>,
    started: Instant,
) -> i32 {
    let target = Some(alias);
    let label = Some(action.id());
    let fail = |outcome: Outcome| finish(target, label, started, outcome);
    let hosts = match hosts::load(config_path) {
        Ok(hosts) => hosts,
        Err(message) => return fail(Outcome::failure("config", message)),
    };
    let Some(host) = hosts.hosts.get(alias) else {
        return fail(Outcome::failure(
            "unknown_target",
            format!("unknown target: {alias}"),
        ));
    };
    if let Err(message) = check_config(alias, host, action) {
        return fail(Outcome::failure("config", message));
    }

    let script = compose_script(host, action, install);
    if let Some(path) = emit_script {
        return match fs::write(&path, script.as_bytes()) {
            Ok(()) => crate::EXIT_OK,
            Err(error) => fail(Outcome::failure(
                "local_io",
                format!("failed to write '{}': {error}", path.display()),
            )),
        };
    }

    let _lock = match acquire_lock(alias, "a remote operation in progress") {
        Ok(lock) => lock,
        Err(failure) => return fail(local_failure(failure)),
    };

    let config = Config {
        json: true,
        ssh: OsString::from(&host.ssh_bin),
        no_ssh_opts: host.no_ssh_opts,
        timeout_seconds: Some(action.timeout_seconds()),
        target: host.ssh.clone(),
        source: ScriptSource::Stdin,
    };
    let (document, code) = match crate::execute(&config, &script) {
        Ok(result) => crate::process_result_document(&result),
        Err(failure) => crate::failure_document(&failure),
    };
    let expect = Expect {
        target: Some(&host.ssh),
        timeout_seconds: Some(action.timeout_seconds()),
        actual_exit_code: Some(code),
    };
    let raw = document.to_string();
    let outcome = postprocess_document(&document, &raw, "", action, &expect);
    finish(target, label, started, outcome)
}

fn validate_saved(
    action: ActionId,
    file: &PathBuf,
    stderr_file: Option<&PathBuf>,
    started: Instant,
) -> i32 {
    let label = Some(action.id());
    let read = |path: &PathBuf| -> Result<String, LocalFailure> { read_text(path) };
    let runner_stdout = match read(file) {
        Ok(text) => text,
        Err(failure) => return finish(None, label, started, local_failure(failure)),
    };
    let local_stderr = match stderr_file.map(read).transpose() {
        Ok(text) => text.unwrap_or_default(),
        Err(failure) => return finish(None, label, started, local_failure(failure)),
    };
    let target = serde_json::from_str::<Value>(runner_stdout.trim())
        .ok()
        .and_then(|document| document.get("target")?.as_str().map(ToOwned::to_owned));
    let outcome = postprocess_text(&runner_stdout, &local_stderr, action, &Expect::default());
    finish(target.as_deref(), label, started, outcome)
}

pub(crate) fn main(args: &[OsString]) -> i32 {
    let started = Instant::now();
    let parsed = match parse(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            let message = format!("{message}; try 'rdbg comfy --help'");
            return finish(None, None, started, Outcome::failure("usage", message));
        }
    };
    match parsed.command {
        Command::Help => {
            let _ = io::stdout().write_all(COMFY_HELP.as_bytes());
            crate::EXIT_OK
        }
        Command::Shawl => {
            emit(&shawl_pins());
            crate::EXIT_OK
        }
        Command::Run {
            alias,
            action,
            install,
            emit_script,
        } => run_action(
            parsed.config.as_ref(),
            &alias,
            action,
            &install,
            emit_script,
            started,
        ),
        Command::Validate {
            action,
            file,
            stderr_file,
        } => validate_saved(action, &file, stderr_file.as_ref(), started),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(toml: &str) -> HostEntry {
        let text = format!("[hosts.box-a]\nssh = \"box-a\"\n[hosts.box-a.comfy]\n{toml}");
        hosts::parse(&text).unwrap().hosts.remove("box-a").unwrap()
    }

    #[test]
    fn array_literal_quotes_each_element() {
        assert_eq!(ps_array(&[]), "@()");
        assert_eq!(
            ps_array(&["--a".to_owned(), "it's x".to_owned()]),
            "@('--a', 'it''s x')"
        );
    }

    #[test]
    fn compose_prefixes_every_constant_in_fixed_order() {
        let host = host("expected_service = \"Svc\"\nroot = 'C:\\Comfy UI'\n");
        let install = InstallOptions {
            shawl_exe: Some(r"C:\tools\shawl.exe".to_owned()),
            start_type: Some(StartType::Manual),
        };
        let script = compose_script(&host, ActionId::InstallService, &install);
        let expected_prefix = format!(
            "$ComfyPort = 8188\n$ExpectedService = 'Svc'\n$ExpectedComfyVersion = $null\n\
             $CanonicalPython = $null\n$Action = 'install-service'\n$ComfyRoot = 'C:\\Comfy UI'\n\
             $ComfyListen = '127.0.0.1'\n$ComfyArgs = @()\n$ShawlExe = 'C:\\tools\\shawl.exe'\n\
             $ShawlSha256 = '{SHAWL_EXE_SHA256}'\n$StartType = 'manual'\nSet-StrictMode"
        );
        assert!(script.starts_with(&expected_prefix), "{script}");

        let script = compose_script(&host, ActionId::Status, &InstallOptions::default());
        assert!(script.contains("$ShawlExe = $null\n"));
        assert!(script.contains("$StartType = $null\n"));
    }

    #[test]
    fn per_action_config_requirements() {
        let bare = host("");
        assert!(check_config("box-a", &bare, ActionId::Status).is_ok());
        for action in [
            ActionId::Restart,
            ActionId::InstallService,
            ActionId::UninstallService,
        ] {
            let error = check_config("box-a", &bare, action).unwrap_err();
            assert!(error.contains("expected_service"), "{error}");
        }
        let service = host("expected_service = \"Svc\"\n");
        assert!(check_config("box-a", &service, ActionId::Restart).is_ok());
        let error = check_config("box-a", &service, ActionId::InstallService).unwrap_err();
        assert!(error.contains("comfy.root"), "{error}");
        let no_python = host("expected_service = \"Svc\"\nroot = 'C:\\ComfyUI'\n");
        let error = check_config("box-a", &no_python, ActionId::InstallService).unwrap_err();
        assert!(error.contains("comfy.python"), "{error}");
        let bad_name = host("expected_service = \"Svc's\"\n");
        for action in ActionId::ALL {
            assert!(check_config("box-a", &bad_name, action).is_err());
        }
        let bad_listen = host(
            "expected_service = \"Svc\"\nroot = 'C:\\ComfyUI'\npython = 'C:\\p.exe'\nlisten = \"a b\"\n",
        );
        assert!(check_config("box-a", &bad_listen, ActionId::InstallService).is_err());
        assert!(check_config("box-a", &bad_listen, ActionId::Restart).is_ok());
    }

    #[test]
    fn exit_codes_cover_the_new_classes() {
        assert_eq!(
            Outcome::failure("refused", "x").exit_code(),
            crate::EXIT_REFUSED
        );
        assert_eq!(
            Outcome::failure("action_failed", "x").exit_code(),
            crate::EXIT_ACTION_FAILED
        );
        let codes = [
            crate::EXIT_CONFIG,
            crate::EXIT_UNKNOWN_TARGET,
            crate::EXIT_UNKNOWN_PROBE,
            crate::EXIT_BUSY,
            crate::EXIT_PROBE_PROTOCOL,
            crate::EXIT_RESULT_PROTOCOL,
            crate::EXIT_LOCAL_IO,
            crate::EXIT_REFUSED,
            crate::EXIT_ACTION_FAILED,
        ];
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
        assert_eq!(crate::EXIT_REFUSED, 37);
        assert_eq!(crate::EXIT_ACTION_FAILED, 38);
    }

    #[test]
    fn script_carries_every_schema_and_constant() {
        for action in ActionId::ALL {
            assert!(SCRIPT_BODY.contains(&format!("'{}'", action.id())));
        }
        assert!(SCRIPT_BODY.contains("'rdbg.comfy.' + [string]$Action + '.v1'"));
        assert!(SCRIPT_BODY.contains("Set-StrictMode -Version 2.0"));
        for forbidden in ["Stop-Process", "taskkill", "Start-Process", "-Verb RunAs"] {
            assert!(!SCRIPT_BODY.contains(forbidden), "{forbidden}");
        }
        assert_eq!(SHAWL_EXE_SHA256.len(), 64);
        assert_eq!(SHAWL_WIN64_ZIP_SHA256.len(), 64);
    }
}
