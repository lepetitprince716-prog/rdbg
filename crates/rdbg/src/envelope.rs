//! Pieces shared by `rdbg doctor` and `rdbg comfy`: constant quoting, the
//! `rdbg.result.v1` envelope checks, output clipping, the per-alias lock and the
//! post-processing of a run into an outcome.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::PathBuf;

use serde_json::Value;

pub const EXIT_CONFIG: i32 = 30;
pub const EXIT_UNKNOWN_TARGET: i32 = 31;
pub const EXIT_UNKNOWN_PROBE: i32 = 32;
pub const EXIT_BUSY: i32 = 33;
pub const EXIT_PROBE_PROTOCOL: i32 = 34;
pub const EXIT_RESULT_PROTOCOL: i32 = 35;
pub const EXIT_LOCAL_IO: i32 = 36;
pub const EXIT_REFUSED: i32 = 37;
pub const EXIT_ACTION_FAILED: i32 = 38;

/// Output text limit, counted in Unicode code points.
pub const MAX_OUTPUT_CHARS: usize = 32_000;
pub(crate) const TRUNCATION_MARKER: &str = "\n...[truncated]";

/// Quote a configured constant as a PowerShell single-quoted string.
pub(crate) fn ps_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

pub(crate) fn ps_literal(value: Option<&str>) -> String {
    value.map_or_else(|| "$null".to_owned(), ps_single_quote)
}

/// Everything a result reports besides target, probe or action, and duration.
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    pub(crate) ok: bool,
    pub(crate) error_class: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) process_exit_code: Option<i64>,
    pub(crate) rdbg_exit_code: Option<i64>,
    pub(crate) observation: Option<Value>,
    pub(crate) stdout: Option<String>,
    pub(crate) stderr: Option<String>,
    pub(crate) stdout_already_truncated: bool,
    pub(crate) stderr_already_truncated: bool,
}

impl Outcome {
    pub(crate) fn failure(class: &str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error_class: Some(class.to_owned()),
            message: Some(message.into()),
            ..Self::default()
        }
    }

    /// The process exit code: 0, a class code, or the rdbg code of the run.
    pub(crate) fn exit_code(&self) -> i32 {
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
            Some("refused") => EXIT_REFUSED,
            Some("action_failed") => EXIT_ACTION_FAILED,
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

pub(crate) fn emit(document: &Value) {
    let mut stdout = io::stdout().lock();
    let _ = serde_json::to_writer(&mut stdout, document);
    let _ = stdout.write_all(b"\n");
}

/// What the caller expects the `rdbg.result.v1` document to describe.
#[derive(Debug, Default)]
pub(crate) struct Expect<'a> {
    pub(crate) target: Option<&'a str>,
    pub(crate) timeout_seconds: Option<u64>,
    pub(crate) actual_exit_code: Option<i32>,
}

fn is_int(value: Option<&Value>) -> bool {
    value.is_some_and(|value| value.is_i64() || value.is_u64())
}

/// Validate the complete `rdbg.result.v1` success/failure envelope.
pub(crate) fn validate_document(document: &Value, expect: &Expect<'_>) -> Result<(), String> {
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

/// Turn a parsed `rdbg.result.v1` document into an outcome. `observe` validates the
/// remote stdout of a successful run; `truncated_message` names a truncated one.
pub(crate) fn postprocess_document(
    document: &Value,
    raw: &str,
    local_stderr: &str,
    expect: &Expect<'_>,
    truncated_message: &str,
    observe: impl FnOnce(&str) -> Result<Value, String>,
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
        message = Some(truncated_message.to_owned());
    } else if ok {
        match observe(remote_stdout) {
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
pub(crate) fn postprocess_text(
    runner_stdout: &str,
    local_stderr: &str,
    expect: &Expect<'_>,
    truncated_message: &str,
    observe: impl FnOnce(&str) -> Result<Value, String>,
) -> Outcome {
    let raw = runner_stdout.trim();
    match serde_json::from_str::<Value>(raw) {
        Ok(document) => postprocess_document(
            &document,
            raw,
            local_stderr,
            expect,
            truncated_message,
            observe,
        ),
        Err(_) => Outcome {
            stdout: Some(raw.to_owned()),
            stderr: Some(local_stderr.to_owned()),
            ..Outcome::failure("result_protocol", "rdbg returned invalid JSON")
        },
    }
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
pub(crate) type LocalFailure = (&'static str, String);

pub(crate) fn local_failure(failure: LocalFailure) -> Outcome {
    Outcome::failure(failure.0, failure.1)
}

/// Take the per-alias single-flight lock. The OS releases it when the process exits.
/// `busy_message` completes "ALIAS already has ..." when another process holds it.
pub(crate) fn acquire_lock(alias: &str, busy_message: &str) -> Result<File, LocalFailure> {
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
        Err(fs::TryLockError::WouldBlock) => {
            Err(("busy", format!("{alias} already has {busy_message}")))
        }
        Err(fs::TryLockError::Error(error)) => {
            Err(("local_io", format!("failed to lock {alias}: {error}")))
        }
    }
}

pub(crate) fn read_text(path: &PathBuf) -> Result<String, LocalFailure> {
    fs::read(path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .map_err(|error| {
            (
                "local_input",
                format!("failed to read '{}': {error}", path.display()),
            )
        })
}
