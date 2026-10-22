#![cfg(unix)]

//! `rdbg doctor` end to end against a fake ssh executable.

use std::fs::{self, File};
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Value, json};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

const TRUNCATION_MARKER: &str = "\n...[truncated]";

struct Fixture {
    root: PathBuf,
    fake_ssh: PathBuf,
    argv_log: PathBuf,
    stdin_log: PathBuf,
    config_home: PathBuf,
    state_home: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("rdbg-doctor-{}-{id}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let config_home = root.join("config");
        let state_home = root.join("state");
        fs::create_dir_all(config_home.join("rdbg")).unwrap();

        let fake_ssh = root.join("fake ssh");
        fs::write(
            &fake_ssh,
            r#"#!/bin/sh
set -eu
: > "$RDBG_FAKE_ARGV"
for arg in "$@"; do
    printf '%s\n' "$arg" >> "$RDBG_FAKE_ARGV"
done
cat > "$RDBG_FAKE_STDIN"
printf '%s' "${RDBG_FAKE_STDOUT-}"
printf '%s' "${RDBG_FAKE_STDERR-}" >&2
if [ -n "${RDBG_FAKE_STDOUT_BYTES-}" ]; then
    dd if=/dev/zero bs="$RDBG_FAKE_STDOUT_BYTES" count=1 2>/dev/null | tr '\000' x
fi
exit "${RDBG_FAKE_EXIT-0}"
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&fake_ssh).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_ssh, permissions).unwrap();
        warmup(&fake_ssh, &root);

        Self {
            argv_log: root.join("argv.log"),
            stdin_log: root.join("stdin.log"),
            root,
            fake_ssh,
            config_home,
            state_home,
        }
    }

    fn default_config_path(&self) -> PathBuf {
        self.config_home.join("rdbg").join("hosts.toml")
    }

    /// Write the default hosts.toml with two aliases that use the fake ssh.
    fn write_default_config(&self, box_a_extra: &str) {
        let ssh_bin = self.fake_ssh.to_str().unwrap();
        fs::write(
            self.default_config_path(),
            format!(
                "[hosts.box-a]\nssh = \"box-a-ssh\"\nssh_bin = '{ssh_bin}'\n{box_a_extra}\n\
                 [hosts.box-b]\nssh = \"box-b-ssh\"\nssh_bin = '{ssh_bin}'\nno_ssh_opts = true\n"
            ),
        )
        .unwrap();
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rdbg"));
        command
            .arg("doctor")
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_STATE_HOME", &self.state_home)
            .env_remove("RDBG_CONFIG")
            .env("RDBG_FAKE_ARGV", &self.argv_log)
            .env("RDBG_FAKE_STDIN", &self.stdin_log)
            .env_remove("RDBG_FAKE_STDOUT")
            .env_remove("RDBG_FAKE_STDERR")
            .env_remove("RDBG_FAKE_STDOUT_BYTES")
            .env_remove("RDBG_FAKE_EXIT")
            .stdin(Stdio::null());
        command
    }

    fn argv(&self) -> Vec<String> {
        fs::read_to_string(&self.argv_log)
            .unwrap()
            .lines()
            .map(ToOwned::to_owned)
            .collect()
    }

    fn ssh_was_launched(&self) -> bool {
        self.argv_log.exists()
    }

    fn payload(&self) -> String {
        let encoded = fs::read(&self.stdin_log).unwrap();
        let bytes = BASE64.decode(encoded).unwrap();
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// See tests/cli.rs: pay the first-exec cost and retry ETXTBSY races.
fn warmup(fake_ssh: &Path, root: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let launched = Command::new(fake_ssh)
            .env("RDBG_FAKE_ARGV", root.join("warmup-argv.log"))
            .env("RDBG_FAKE_STDIN", root.join("warmup-stdin.log"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match launched {
            Ok(status) => {
                assert!(status.success(), "fake ssh warmup failed: {status:?}");
                return;
            }
            Err(error)
                if error.kind() == ErrorKind::ExecutableFileBusy && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => panic!("fake ssh warmup could not launch: {error}"),
        }
    }
}

fn probe_body(name: &str) -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("probes")
            .join(format!("{name}.ps1")),
    )
    .unwrap()
}

fn doctor_json(output: &Output) -> Value {
    assert!(
        output.stderr.is_empty(),
        "local stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout.clone()).unwrap();
    assert_eq!(text.lines().count(), 1, "stdout: {text}");
    serde_json::from_str(&text).unwrap()
}

fn assert_doctor_failure(output: &Output, code: i32, class: &str) -> Value {
    assert_eq!(output.status.code(), Some(code), "{output:?}");
    let result = doctor_json(output);
    assert_eq!(result["schema"], "rdbg.doctor.result.v1");
    assert_eq!(result["ok"], false);
    assert_eq!(result["error_class"], class, "{result}");
    assert!(result["message"].as_str().is_some_and(|m| !m.is_empty()));
    result
}

fn transport_observation() -> Value {
    json!({
        "schema": "rdbg.doctor.transport.v1",
        "healthy": true,
        "computer_name": "BOX-A",
        "powershell_version": "5.1",
        "powershell_edition": "Desktop",
        "remote_time_utc": "2026-01-01T00:00:00Z",
        "encoding_sentinel": "中文 / テスト / ✓",
        "apostrophe_sentinel": "O'Reilly",
        "dollar_sentinel": "$notExpanded",
        "json_literal_ok": true,
        "multiline_ok": true
    })
}

fn saved_result(stdout: &str, stderr: &str) -> Value {
    json!({
        "schema": "rdbg.result.v1",
        "ok": true,
        "error_class": null,
        "rdbg_exit_code": 0,
        "process_exit_code": 0,
        "target": "box-a-ssh",
        "mode": "file",
        "timeout_seconds": 20,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_utf8_lossy": false,
        "stderr_utf8_lossy": false,
        "stdout_truncated": false,
        "stderr_truncated": false,
        "message": null
    })
}

#[test]
fn list_reports_aliases_and_fixed_probes_without_paths() {
    let fixture = Fixture::new();
    fixture.write_default_config("");
    let output = fixture.command().arg("list").output().unwrap();

    assert_eq!(output.status.code(), Some(rdbg::EXIT_OK));
    let body = doctor_json(&output);
    assert_eq!(body["schema"], "rdbg.doctor.capabilities.v1");
    assert_eq!(body["config_loaded"], true);
    assert_eq!(body["arbitrary_script"], false);
    assert_eq!(body["targets"], json!([{"id": "box-a"}, {"id": "box-b"}]));
    let probes: Vec<(&str, u64)> = body["probes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|probe| {
            assert!(probe["label"].is_string() && probe["description"].is_string());
            (
                probe["id"].as_str().unwrap(),
                probe["timeout_s"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        probes,
        [
            ("transport", 20),
            ("overview", 30),
            ("network", 25),
            ("comfyui", 20),
            ("listener", 25),
            ("gpu", 25),
            ("snapshot", 30),
        ]
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains(fixture.root.to_str().unwrap()));
    assert!(!text.contains("box-a-ssh"));
}

#[test]
fn list_without_a_default_config_is_empty_but_explicit_missing_path_fails() {
    let fixture = Fixture::new();
    let output = fixture.command().arg("list").output().unwrap();
    assert_eq!(output.status.code(), Some(rdbg::EXIT_OK));
    let body = doctor_json(&output);
    assert_eq!(body["config_loaded"], false);
    assert_eq!(body["targets"], json!([]));

    let missing = fixture.root.join("missing.toml");
    let output = fixture
        .command()
        .arg("--config")
        .arg(&missing)
        .arg("list")
        .output()
        .unwrap();
    assert_doctor_failure(&output, rdbg::EXIT_CONFIG, "config");

    let output = fixture
        .command()
        .env("RDBG_CONFIG", &missing)
        .arg("list")
        .output()
        .unwrap();
    assert_doctor_failure(&output, rdbg::EXIT_CONFIG, "config");
}

#[test]
fn config_lookup_prefers_flag_then_env_then_default() {
    let fixture = Fixture::new();
    fixture.write_default_config("");
    let flag = fixture.root.join("flag.toml");
    let env = fixture.root.join("env.toml");
    fs::write(&flag, "[hosts.from-flag]\nssh = \"x\"\n").unwrap();
    fs::write(&env, "[hosts.from-env]\nssh = \"x\"\n").unwrap();

    let ids = |output: Output| {
        doctor_json(&output)["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|target| target["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    let both = fixture
        .command()
        .env("RDBG_CONFIG", &env)
        .arg("--config")
        .arg(&flag)
        .arg("list")
        .output()
        .unwrap();
    assert_eq!(ids(both), ["from-flag"]);
    let env_only = fixture
        .command()
        .env("RDBG_CONFIG", &env)
        .arg("list")
        .output()
        .unwrap();
    assert_eq!(ids(env_only), ["from-env"]);
}

#[test]
fn malformed_config_is_a_config_error_and_never_launches_ssh() {
    let fixture = Fixture::new();
    for text in [
        "[hosts.box-a]\nssh = \"box-a\"\nport = 22\n",
        "[hosts.box-a]\nssh = \"box-a\"\n[hosts.box-a.comfy]\nunknown = true\n",
        "[hosts.box-a]\nno_ssh_opts = true\n",
        "not toml at all [",
    ] {
        fs::write(fixture.default_config_path(), text).unwrap();
        let output = fixture
            .command()
            .args(["box-a", "transport"])
            .output()
            .unwrap();
        assert_doctor_failure(&output, rdbg::EXIT_CONFIG, "config");
        assert!(!fixture.ssh_was_launched(), "config: {text}");
    }
}

#[test]
fn unknown_alias_and_probe_have_fixed_classes() {
    let fixture = Fixture::new();
    fixture.write_default_config("");

    let output = fixture
        .command()
        .args(["box-z", "transport"])
        .output()
        .unwrap();
    let result = assert_doctor_failure(&output, rdbg::EXIT_UNKNOWN_TARGET, "unknown_target");
    assert_eq!(result["target"], "box-z");

    let output = fixture
        .command()
        .args(["box-a", "run-anything"])
        .output()
        .unwrap();
    assert_doctor_failure(&output, rdbg::EXIT_UNKNOWN_PROBE, "unknown_probe");

    let output = fixture
        .command()
        .args(["validate", "run-anything", "/nonexistent"])
        .output()
        .unwrap();
    assert_doctor_failure(&output, rdbg::EXIT_UNKNOWN_PROBE, "unknown_probe");
    assert!(!fixture.ssh_was_launched());
}

#[test]
fn bad_arguments_are_usage_errors() {
    let fixture = Fixture::new();
    for args in [
        &[][..],
        &["box-a"],
        &["box-a", "transport", "extra"],
        &["box-a", "transport", "--script", "x"],
        &["list", "--emit-script", "x"],
        &["box-a", "transport", "--emit-script"],
    ] {
        let output = fixture.command().args(args).output().unwrap();
        assert_doctor_failure(&output, rdbg::EXIT_USAGE, "usage");
    }
    assert!(!fixture.ssh_was_launched());
}

#[test]
fn emit_script_writes_quoted_constants_and_the_probe_body() {
    let fixture = Fixture::new();
    fixture.write_default_config(
        "[hosts.box-a.comfy]\nport = 9188\nexpected_service = \"Svc's\"\n\
         python = 'C:\\canonical dir\\python.exe'\n",
    );
    let script_path = fixture.root.join("listener script.ps1");
    let output = fixture
        .command()
        .args(["box-a", "listener", "--emit-script"])
        .arg(&script_path)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(rdbg::EXIT_OK), "{output:?}");
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert!(!fixture.ssh_was_launched());
    let expected = format!(
        "$ComfyPort = 9188\n$ExpectedService = 'Svc''s'\n$ExpectedComfyVersion = $null\n\
         $CanonicalPython = 'C:\\canonical dir\\python.exe'\n{}",
        probe_body("listener")
    );
    assert_eq!(fs::read_to_string(&script_path).unwrap(), expected);

    // Defaults: port 8188 and $null for every optional constant.
    let output = fixture
        .command()
        .args(["box-b", "comfyui", "--emit-script"])
        .arg(&script_path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(rdbg::EXIT_OK));
    let script = fs::read_to_string(&script_path).unwrap();
    assert!(script.starts_with(
        "$ComfyPort = 8188\n$ExpectedService = $null\n$ExpectedComfyVersion = $null\n$CanonicalPython = $null\n"
    ));
}

#[test]
fn valid_observation_replaces_stdout_and_sends_the_composed_script() {
    let fixture = Fixture::new();
    fixture.write_default_config("[hosts.box-a.comfy]\nexpected_version = \"1.0.0\"\n");
    let observation = transport_observation().to_string();
    let output = fixture
        .command()
        .env("RDBG_FAKE_STDOUT", format!("{observation}\r\n"))
        .args(["box-a", "transport"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(rdbg::EXIT_OK), "{output:?}");
    let result = doctor_json(&output);
    assert_eq!(result["ok"], true);
    assert_eq!(result["healthy"], true);
    assert_eq!(result["summary"], "ready");
    assert_eq!(result["target"], "box-a");
    assert_eq!(result["probe"], "transport");
    assert_eq!(result["stdout"], Value::Null);
    assert_eq!(result["stderr"], "");
    assert_eq!(result["observation"], transport_observation());
    assert_eq!(result["rdbg_exit_code"], 0);
    assert_eq!(result["process_exit_code"], 0);
    assert!(result["duration_ms"].is_u64());

    let argv = fixture.argv();
    assert!(argv.contains(&"BatchMode=yes".to_owned()), "{argv:?}");
    assert!(argv.contains(&"box-a-ssh".to_owned()));
    let payload = fixture.payload();
    assert!(payload.starts_with(
        "$ComfyPort = 8188\n$ExpectedService = $null\n$ExpectedComfyVersion = '1.0.0'\n"
    ));
    assert!(payload.ends_with(&probe_body("transport")));
}

#[test]
fn no_ssh_opts_from_config_reaches_ssh() {
    let fixture = Fixture::new();
    fixture.write_default_config("");
    let output = fixture
        .command()
        .env("RDBG_FAKE_STDOUT", transport_observation().to_string())
        .args(["box-b", "transport"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(rdbg::EXIT_OK));
    let argv = fixture.argv();
    assert_eq!(&argv[..3], ["-T", "box-b-ssh", "powershell.exe"]);
}

#[test]
fn unhealthy_observation_is_ok_with_summary() {
    let fixture = Fixture::new();
    fixture.write_default_config("");
    let mut observation = transport_observation();
    observation["healthy"] = json!(false);
    let output = fixture
        .command()
        .env("RDBG_FAKE_STDOUT", observation.to_string())
        .args(["box-a", "transport"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(rdbg::EXIT_OK));
    let result = doctor_json(&output);
    assert_eq!(result["healthy"], false);
    assert_eq!(result["summary"], "probe completed; unhealthy observation");
}

#[test]
fn contract_violation_is_probe_protocol_and_keeps_stdout() {
    let fixture = Fixture::new();
    fixture.write_default_config("");
    for stdout in [
        json!({"schema": "rdbg.doctor.overview.v1", "healthy": true}).to_string(),
        json!({"schema": "rdbg.doctor.transport.v1", "healthy": "yes"}).to_string(),
        {
            let mut extra = transport_observation();
            extra["extra"] = json!(1);
            extra.to_string()
        },
        "not json".to_owned(),
    ] {
        let output = fixture
            .command()
            .env("RDBG_FAKE_STDOUT", &stdout)
            .args(["box-a", "transport"])
            .output()
            .unwrap();
        let result = assert_doctor_failure(&output, rdbg::EXIT_PROBE_PROTOCOL, "probe_protocol");
        assert!(result["message"].as_str().unwrap().contains("contract"));
        assert_eq!(result["healthy"], Value::Null);
        assert_eq!(result["observation"], Value::Null);
        assert_eq!(result["stdout"], stdout);
    }
}

#[test]
fn multibyte_output_is_clipped_by_code_points() {
    let fixture = Fixture::new();
    fixture.write_default_config("");
    let remote = "中".repeat(rdbg::MAX_OUTPUT_CHARS + 500);
    let output = fixture
        .command()
        .env("RDBG_FAKE_STDOUT", &remote)
        .args(["box-a", "transport"])
        .output()
        .unwrap();

    let result = assert_doctor_failure(&output, rdbg::EXIT_PROBE_PROTOCOL, "probe_protocol");
    assert!(
        result["message"]
            .as_str()
            .unwrap()
            .contains("observation limit")
    );
    let stdout = result["stdout"].as_str().unwrap();
    assert_eq!(
        stdout,
        format!("{}{TRUNCATION_MARKER}", "中".repeat(rdbg::MAX_OUTPUT_CHARS))
    );
    assert_eq!(result["stdout_truncated"], true);
    assert_eq!(result["stderr_truncated"], false);
}

#[test]
fn runner_truncation_of_an_ok_run_is_probe_protocol() {
    let fixture = Fixture::new();
    fixture.write_default_config("");
    let output = fixture
        .command()
        .env("RDBG_FAKE_STDOUT_BYTES", (1024 * 1024 + 10).to_string())
        .args(["box-a", "transport"])
        .output()
        .unwrap();

    let result = assert_doctor_failure(&output, rdbg::EXIT_PROBE_PROTOCOL, "probe_protocol");
    assert_eq!(result["message"], "remote probe output was truncated");
    assert_eq!(result["stdout_truncated"], true);
    let stdout = result["stdout"].as_str().unwrap();
    assert_eq!(
        stdout.chars().count(),
        rdbg::MAX_OUTPUT_CHARS + TRUNCATION_MARKER.chars().count()
    );
}

#[test]
fn remote_failure_keeps_rdbg_class_exit_code_and_output() {
    let fixture = Fixture::new();
    fixture.write_default_config("");
    let output = fixture
        .command()
        .env("RDBG_FAKE_STDOUT", "partial")
        .env("RDBG_FAKE_STDERR", "remote error")
        .env("RDBG_FAKE_EXIT", "3")
        .args(["box-a", "transport"])
        .output()
        .unwrap();

    let result = assert_doctor_failure(&output, rdbg::EXIT_REMOTE_COMMAND, "remote_command");
    assert_eq!(result["rdbg_exit_code"], 23);
    assert_eq!(result["process_exit_code"], 3);
    assert_eq!(result["stdout"], "partial");
    assert_eq!(result["stderr"], "remote error");
}

#[test]
fn ssh_launch_failure_is_reported_through_the_doctor_envelope() {
    let fixture = Fixture::new();
    fs::write(
        fixture.default_config_path(),
        "[hosts.box-a]\nssh = \"box-a\"\nssh_bin = \"/nonexistent/ssh-binary\"\n",
    )
    .unwrap();
    let output = fixture
        .command()
        .args(["box-a", "transport"])
        .output()
        .unwrap();
    assert_doctor_failure(&output, rdbg::EXIT_SSH_LAUNCH, "ssh_launch");
}

#[test]
fn busy_alias_never_launches_ssh_and_other_aliases_still_run() {
    let fixture = Fixture::new();
    fixture.write_default_config("");
    let lock_dir = fixture.state_home.join("rdbg").join("locks");
    fs::create_dir_all(&lock_dir).unwrap();
    let held = File::create(lock_dir.join("box-a.lock")).unwrap();
    held.lock().unwrap();

    let output = fixture
        .command()
        .args(["box-a", "transport"])
        .output()
        .unwrap();
    assert_doctor_failure(&output, rdbg::EXIT_BUSY, "busy");
    assert!(!fixture.ssh_was_launched());

    let output = fixture
        .command()
        .env("RDBG_FAKE_STDOUT", transport_observation().to_string())
        .args(["box-b", "transport"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(rdbg::EXIT_OK));

    drop(held);
    let output = fixture
        .command()
        .env("RDBG_FAKE_STDOUT", transport_observation().to_string())
        .args(["box-a", "transport"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(rdbg::EXIT_OK));
}

fn validate(fixture: &Fixture, probe: &str, document: &str, stderr: Option<&str>) -> Output {
    let path = fixture.root.join("saved.json");
    fs::write(&path, document).unwrap();
    let mut command = fixture.command();
    command.args(["validate", probe]).arg(&path);
    if let Some(stderr) = stderr {
        let stderr_path = fixture.root.join("saved.stderr");
        fs::write(&stderr_path, stderr).unwrap();
        command.arg("--stderr").arg(stderr_path);
    }
    command.output().unwrap()
}

#[test]
fn validate_accepts_a_good_saved_result() {
    let fixture = Fixture::new();
    let document = saved_result(&transport_observation().to_string(), "");
    let output = validate(&fixture, "transport", &format!("{document}\n"), None);
    assert_eq!(output.status.code(), Some(rdbg::EXIT_OK), "{output:?}");
    let result = doctor_json(&output);
    assert_eq!(result["ok"], true);
    assert_eq!(result["target"], "box-a-ssh");
    assert_eq!(result["stdout"], Value::Null);
    assert_eq!(result["observation"]["schema"], "rdbg.doctor.transport.v1");
    assert!(!fixture.ssh_was_launched());
}

#[test]
fn validate_rejects_bad_saved_results() {
    let fixture = Fixture::new();
    let output = validate(&fixture, "transport", "not json", None);
    let result = assert_doctor_failure(&output, rdbg::EXIT_RESULT_PROTOCOL, "result_protocol");
    assert_eq!(result["stdout"], "not json");

    let mut inconsistent = saved_result(&transport_observation().to_string(), "");
    inconsistent["rdbg_exit_code"] = json!(25);
    let output = validate(&fixture, "transport", &inconsistent.to_string(), None);
    assert_doctor_failure(&output, rdbg::EXIT_RESULT_PROTOCOL, "result_protocol");

    let mut lossy = saved_result(&transport_observation().to_string(), "");
    lossy["stdout_utf8_lossy"] = json!(true);
    let output = validate(&fixture, "transport", &lossy.to_string(), None);
    assert_doctor_failure(&output, rdbg::EXIT_RESULT_PROTOCOL, "result_protocol");

    let wrong_probe = saved_result(&transport_observation().to_string(), "");
    let output = validate(&fixture, "gpu", &wrong_probe.to_string(), None);
    assert_doctor_failure(&output, rdbg::EXIT_PROBE_PROTOCOL, "probe_protocol");

    let output = fixture
        .command()
        .args(["validate", "transport"])
        .arg(fixture.root.join("missing.json"))
        .output()
        .unwrap();
    assert_doctor_failure(&output, rdbg::EXIT_LOCAL_INPUT, "local_input");
}

#[test]
fn validate_preserves_a_failed_run() {
    let fixture = Fixture::new();
    let mut timed_out = saved_result("partial", "");
    timed_out["ok"] = json!(false);
    timed_out["rdbg_exit_code"] = json!(25);
    timed_out["process_exit_code"] = Value::Null;
    timed_out["error_class"] = json!("execution_timeout");
    timed_out["message"] = json!("timed out");
    let output = validate(&fixture, "transport", &timed_out.to_string(), None);
    let result = assert_doctor_failure(&output, rdbg::EXIT_EXECUTION_TIMEOUT, "execution_timeout");
    assert_eq!(result["stdout"], "partial");
    assert_eq!(result["rdbg_exit_code"], 25);
}

#[test]
fn stderr_prefers_remote_and_falls_back_to_local() {
    let fixture = Fixture::new();
    let observation = transport_observation().to_string();

    let remote = saved_result(&observation, "remote note");
    let output = validate(&fixture, "transport", &remote.to_string(), None);
    assert_eq!(output.status.code(), Some(rdbg::EXIT_OK));
    assert_eq!(doctor_json(&output)["stderr"], "remote note");

    let output = validate(
        &fixture,
        "transport",
        &remote.to_string(),
        Some("local note"),
    );
    let result = assert_doctor_failure(&output, rdbg::EXIT_RESULT_PROTOCOL, "result_protocol");
    assert_eq!(result["stderr"], "remote note");

    let quiet = saved_result(&observation, "");
    let output = validate(
        &fixture,
        "transport",
        &quiet.to_string(),
        Some("local note"),
    );
    let result = assert_doctor_failure(&output, rdbg::EXIT_RESULT_PROTOCOL, "result_protocol");
    assert_eq!(result["stderr"], "local note");
}
