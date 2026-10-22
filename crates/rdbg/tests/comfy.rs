#![cfg(unix)]

//! `rdbg comfy` end to end against a fake ssh executable.

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
        let root = std::env::temp_dir().join(format!("rdbg-comfy-{}-{id}", std::process::id()));
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

    fn config_path(&self) -> PathBuf {
        self.config_home.join("rdbg").join("hosts.toml")
    }

    /// Write hosts.toml with box-a (comfy table `comfy`) and box-b (no comfy table).
    fn write_config(&self, comfy: &str) {
        let ssh_bin = self.fake_ssh.to_str().unwrap();
        fs::write(
            self.config_path(),
            format!(
                "[hosts.box-a]\nssh = \"box-a-ssh\"\nssh_bin = '{ssh_bin}'\n\
                 [hosts.box-a.comfy]\n{comfy}\n\
                 [hosts.box-b]\nssh = \"box-b-ssh\"\nssh_bin = '{ssh_bin}'\n"
            ),
        )
        .unwrap();
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rdbg"));
        command
            .arg("comfy")
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_STATE_HOME", &self.state_home)
            .env_remove("RDBG_CONFIG")
            .env("RDBG_FAKE_ARGV", &self.argv_log)
            .env("RDBG_FAKE_STDIN", &self.stdin_log)
            .env_remove("RDBG_FAKE_STDOUT")
            .env_remove("RDBG_FAKE_STDERR")
            .env_remove("RDBG_FAKE_EXIT")
            .stdin(Stdio::null());
        command
    }

    fn ssh_was_launched(&self) -> bool {
        self.argv_log.exists()
    }

    fn argv(&self) -> Vec<String> {
        fs::read_to_string(&self.argv_log)
            .unwrap()
            .lines()
            .map(ToOwned::to_owned)
            .collect()
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

    fn emit(&self, args: &[&str]) -> String {
        let path = self.root.join("emitted.ps1");
        let output = self
            .command()
            .args(args)
            .arg("--emit-script")
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(rdbg::EXIT_OK), "{output:?}");
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        fs::read_to_string(path).unwrap()
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

fn script_body() -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("remote")
            .join("comfy-service.ps1"),
    )
    .unwrap()
}

fn comfy_json(output: &Output) -> Value {
    assert!(
        output.stderr.is_empty(),
        "local stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout.clone()).unwrap();
    assert_eq!(text.lines().count(), 1, "stdout: {text}");
    serde_json::from_str(&text).unwrap()
}

fn assert_failure(output: &Output, code: i32, class: &str) -> Value {
    assert_eq!(output.status.code(), Some(code), "{output:?}");
    let result = comfy_json(output);
    assert_eq!(result["schema"], "rdbg.comfy.result.v1");
    assert_eq!(result["ok"], false);
    assert_eq!(result["error_class"], class, "{result}");
    assert!(result["message"].as_str().is_some_and(|m| !m.is_empty()));
    result
}

const SERVICE_COMFY: &str = "expected_service = \"Svc\"\nroot = 'C:\\ComfyUI'\n\
     python = 'C:\\ComfyUI\\.venv\\Scripts\\python.exe'\n";

const INSTALL: &[&str] = &[
    "box-a",
    "install-service",
    "--shawl-exe",
    "C:\\tools\\shawl.exe",
];

fn observation(action: &str, outcome: &str, reasons: &[&str]) -> Value {
    let done = outcome == "done";
    let mut value = json!({
        "schema": format!("rdbg.comfy.{action}.v1"),
        "outcome": outcome,
        "changed": done && action != "status",
        "reasons": reasons,
        "service": {
            "name": "Svc", "present": true, "status": "Running", "pid": 10,
            "start_type": "Auto", "error": null
        },
        "listener": {
            "port": 8188, "listening": true, "owner_pids": [100],
            "all_owners_service_bound": true, "error": null
        },
        "live": {
            "reachable": true, "base_uri": "http://127.0.0.1:8188", "version": "1.0.0",
            "expected_version": null, "version_matches": null, "error": null
        }
    });
    let map = value.as_object_mut().unwrap();
    match action {
        "restart" => {
            map.insert("ready".to_owned(), json!(done));
        }
        "install-service" => {
            map.insert("ready".to_owned(), json!(done));
            map.insert("rolled_back".to_owned(), json!(false));
            map.insert("start_type".to_owned(), json!("auto"));
            map.insert("log_dir".to_owned(), Value::Null);
            map.insert("conflicts".to_owned(), json!([]));
        }
        "uninstall-service" => {
            map.insert("removed".to_owned(), json!(done));
        }
        _ => {}
    }
    value
}

fn saved_result(stdout: &str) -> Value {
    json!({
        "schema": "rdbg.result.v1", "ok": true, "error_class": null, "rdbg_exit_code": 0,
        "process_exit_code": 0, "target": "box-a-ssh", "mode": "file", "timeout_seconds": 210,
        "stdout": stdout, "stderr": "", "stdout_utf8_lossy": false, "stderr_utf8_lossy": false,
        "stdout_truncated": false, "stderr_truncated": false, "message": null
    })
}

#[test]
fn help_lists_every_command() {
    let fixture = Fixture::new();
    let output = fixture.command().arg("--help").output().unwrap();
    assert_eq!(output.status.code(), Some(rdbg::EXIT_OK));
    let text = String::from_utf8(output.stdout).unwrap();
    for needle in [
        "ALIAS status",
        "ALIAS restart",
        "install-service --shawl-exe REMOTE_PATH [--start-type auto|manual]",
        "ALIAS uninstall-service",
        "--emit-script PATH",
        "validate ACTION FILE [--stderr FILE]",
        "rdbg comfy shawl",
    ] {
        assert!(text.contains(needle), "help missing: {needle}");
    }

    let top = Command::new(env!("CARGO_BIN_EXE_rdbg"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(
        String::from_utf8(top.stdout)
            .unwrap()
            .contains("rdbg comfy --help")
    );
}

#[test]
fn shawl_prints_the_pins() {
    let fixture = Fixture::new();
    let output = fixture.command().arg("shawl").output().unwrap();
    assert_eq!(output.status.code(), Some(rdbg::EXIT_OK));
    assert_eq!(
        comfy_json(&output),
        json!({
            "schema": "rdbg.comfy.shawl.v1",
            "version": "v1.9.0",
            "win64_zip_sha256": "f883c5d09c9beae2efaeabd8513e7d3f57cd1d0864cec3df4f4a7b6ee904351c",
            "exe_sha256": rdbg::SHAWL_EXE_SHA256,
        })
    );
    assert_eq!(rdbg::SHAWL_VERSION, "v1.9.0");
    assert_eq!(
        rdbg::SHAWL_WIN64_ZIP_SHA256,
        "f883c5d09c9beae2efaeabd8513e7d3f57cd1d0864cec3df4f4a7b6ee904351c"
    );
}

#[test]
fn bad_arguments_are_usage_errors_and_never_launch_ssh() {
    let fixture = Fixture::new();
    fixture.write_config(SERVICE_COMFY);
    for args in [
        &[][..],
        &["box-a"],
        &["box-a", "start"],
        &["box-a", "status", "extra"],
        &["box-a", "install-service"],
        &["box-a", "install-service", "--shawl-exe"],
        &["box-a", "install-service", "--shawl-exe", "C:\\a\"b.exe"],
        &[
            "box-a",
            "install-service",
            "--shawl-exe",
            "x",
            "--start-type",
            "delayed",
        ],
        &["box-a", "status", "--shawl-exe", "x"],
        &["box-a", "restart", "--start-type", "auto"],
        &["box-a", "status", "--stderr", "x"],
        &["box-a", "status", "--unknown"],
        &["validate", "status"],
        &["validate", "start", "file"],
        &["validate", "status", "file", "--config", "x"],
        &["shawl", "--config", "x"],
        &["shawl", "extra", "more"],
        &["box-a", "status", "--config", "a", "--config", "b"],
    ] {
        let output = fixture.command().args(args).output().unwrap();
        let result = assert_failure(&output, rdbg::EXIT_USAGE, "usage");
        assert!(
            result["message"]
                .as_str()
                .unwrap()
                .contains("rdbg comfy --help"),
            "{args:?}"
        );
    }
    assert!(!fixture.ssh_was_launched());
}

#[test]
fn per_action_config_errors_never_launch_ssh() {
    let fixture = Fixture::new();
    let cases: &[(&str, &[&str], &str)] = &[
        ("", &["box-a", "restart"], "expected_service"),
        ("", &["box-a", "uninstall-service"], "expected_service"),
        ("", INSTALL, "expected_service"),
        ("expected_service = \"Svc\"\n", INSTALL, "comfy.root"),
        (
            "expected_service = \"Svc\"\nroot = 'C:\\ComfyUI'\n",
            INSTALL,
            "comfy.python",
        ),
        (
            "expected_service = \"Svc's\"\n",
            &["box-a", "status"],
            "expected_service",
        ),
        (
            "expected_service = \"Svc\"\nroot = 'C:\\Comfy\"UI'\npython = 'C:\\p.exe'\n",
            INSTALL,
            "comfy.root",
        ),
        (
            "expected_service = \"Svc\"\nroot = 'C:\\ComfyUI'\npython = 'C:\\p.exe'\nlisten = \"\"\n",
            INSTALL,
            "comfy.listen",
        ),
        ("args = [\"--a\\\"b\"]\n", &["box-a", "status"], "args[0]"),
        ("args = [\"\"]\n", &["box-a", "status"], "args[0]"),
        ("unknown = 1\n", &["box-a", "status"], "unknown"),
    ];
    for (comfy, args, needle) in cases {
        fixture.write_config(comfy);
        let output = fixture.command().args(*args).output().unwrap();
        let result = assert_failure(&output, rdbg::EXIT_CONFIG, "config");
        assert!(
            result["message"].as_str().unwrap().contains(needle),
            "{comfy} {args:?}: {result}"
        );
        assert!(!fixture.ssh_was_launched(), "{comfy}");

        // --emit-script applies the same checks.
        let output = fixture
            .command()
            .args(*args)
            .arg("--emit-script")
            .arg(fixture.root.join("never.ps1"))
            .output()
            .unwrap();
        assert_failure(&output, rdbg::EXIT_CONFIG, "config");
        assert!(!fixture.root.join("never.ps1").exists());
    }

    // status needs nothing beyond the host.
    fixture.write_config("");
    fixture.emit(&["box-a", "status"]);
    let output = fixture
        .command()
        .args(["box-z", "status"])
        .output()
        .unwrap();
    assert_failure(&output, rdbg::EXIT_UNKNOWN_TARGET, "unknown_target");
}

#[test]
fn emit_script_quotes_root_python_and_args() {
    let fixture = Fixture::new();
    fixture.write_config(
        "port = 9188\nexpected_service = \"Svc\"\nexpected_version = \"1.0.0\"\n\
         root = \"C:\\\\Comfy UI\\\\it's\"\npython = 'C:\\Comfy UI\\py thon\\python.exe'\n\
         listen = \"0.0.0.0\"\nargs = [\"--output-directory\", 'D:\\out dir', \"it's\"]\n",
    );
    let script = fixture.emit(&[
        "box-a",
        "install-service",
        "--shawl-exe",
        "C:\\tools dir\\shawl's.exe",
        "--start-type",
        "manual",
    ]);
    let expected = format!(
        "$ComfyPort = 9188\n$ExpectedService = 'Svc'\n$ExpectedComfyVersion = '1.0.0'\n\
         $CanonicalPython = 'C:\\Comfy UI\\py thon\\python.exe'\n$Action = 'install-service'\n\
         $ComfyRoot = 'C:\\Comfy UI\\it''s'\n$ComfyListen = '0.0.0.0'\n\
         $ComfyArgs = @('--output-directory', 'D:\\out dir', 'it''s')\n\
         $ShawlExe = 'C:\\tools dir\\shawl''s.exe'\n$ShawlSha256 = '{}'\n$StartType = 'manual'\n{}",
        rdbg::SHAWL_EXE_SHA256,
        script_body()
    );
    assert_eq!(script, expected);
    assert!(!fixture.ssh_was_launched());

    fixture.write_config("expected_service = \"Svc\"\n");
    let script = fixture.emit(&["box-a", "uninstall-service"]);
    assert!(script.starts_with(
        "$ComfyPort = 8188\n$ExpectedService = 'Svc'\n$ExpectedComfyVersion = $null\n\
         $CanonicalPython = $null\n$Action = 'uninstall-service'\n$ComfyRoot = $null\n\
         $ComfyListen = '127.0.0.1'\n$ComfyArgs = @()\n$ShawlExe = $null\n"
    ));
    assert!(script.contains("\n$StartType = $null\n"));
    let script = fixture.emit(&["box-a", "status"]);
    assert!(script.contains("\n$Action = 'status'\n"));
}

#[test]
fn install_defaults_to_auto_start() {
    let fixture = Fixture::new();
    fixture.write_config(SERVICE_COMFY);
    let script = fixture.emit(INSTALL);
    assert!(script.contains("\n$StartType = 'auto'\n"));
}

/// CLI args, action, outcome, reasons, exit code, error class.
type OutcomeCase<'a> = (
    &'a [&'a str],
    &'a str,
    &'a str,
    &'a [&'a str],
    i32,
    Option<&'a str>,
);

#[test]
fn each_outcome_maps_to_its_exit_code() {
    let fixture = Fixture::new();
    fixture.write_config(SERVICE_COMFY);
    let cases: &[OutcomeCase<'_>] = &[
        (&["box-a", "status"], "status", "done", &[], 0, None),
        (&["box-a", "restart"], "restart", "done", &[], 0, None),
        (
            &["box-a", "restart"],
            "restart",
            "refused",
            &["rogue_listener"],
            rdbg::EXIT_REFUSED,
            Some("refused"),
        ),
        (
            &["box-a", "restart"],
            "restart",
            "failed",
            &["not_ready_timeout", "comfy_unreachable"],
            rdbg::EXIT_ACTION_FAILED,
            Some("action_failed"),
        ),
        (INSTALL, "install-service", "done", &[], 0, None),
        (
            INSTALL,
            "install-service",
            "refused",
            &["port_in_use", "launcher_conflict"],
            rdbg::EXIT_REFUSED,
            Some("refused"),
        ),
        (
            &["box-a", "uninstall-service"],
            "uninstall-service",
            "failed",
            &["port_still_busy"],
            rdbg::EXIT_ACTION_FAILED,
            Some("action_failed"),
        ),
        (
            &["box-a", "uninstall-service"],
            "uninstall-service",
            "done",
            &[],
            0,
            None,
        ),
    ];
    for (args, action, outcome, reasons, code, class) in cases {
        let observed = observation(action, outcome, reasons);
        let output = fixture
            .command()
            .env("RDBG_FAKE_STDOUT", format!("{observed}\r\n"))
            .args(*args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(*code), "{action} {outcome}");
        let result = comfy_json(&output);
        assert_eq!(result["schema"], "rdbg.comfy.result.v1");
        assert_eq!(result["target"], "box-a");
        assert_eq!(result["action"], *action);
        assert_eq!(result["outcome"], *outcome);
        assert_eq!(result["ok"], *outcome == "done");
        assert_eq!(result["error_class"], json!(class));
        assert_eq!(result["observation"], observed);
        assert_eq!(result["stdout"], Value::Null);
        assert_eq!(result["rdbg_exit_code"], 0);
        if class.is_some() {
            let message = result["message"].as_str().unwrap();
            assert!(message.contains(&reasons.join(", ")), "{message}");
            assert_eq!(result["summary"], message);
        } else {
            let changed = *action != "status";
            assert_eq!(
                result["summary"],
                if changed { "done; changed" } else { "done" }
            );
        }

        // The payload is exactly the composed script for that action.
        let payload = fixture.payload();
        assert_eq!(payload, fixture.emit(args));
        assert!(fixture.argv().contains(&"box-a-ssh".to_owned()));
    }
}

#[test]
fn contract_violation_and_remote_failure_keep_their_classes() {
    let fixture = Fixture::new();
    fixture.write_config(SERVICE_COMFY);
    for stdout in [
        observation("restart", "done", &[]).to_string(),
        "not json".to_owned(),
        {
            let mut extra = observation("status", "done", &[]);
            extra["listener"]["extra"] = json!(1);
            extra.to_string()
        },
    ] {
        let output = fixture
            .command()
            .env("RDBG_FAKE_STDOUT", &stdout)
            .args(["box-a", "status"])
            .output()
            .unwrap();
        let result = assert_failure(&output, rdbg::EXIT_PROBE_PROTOCOL, "probe_protocol");
        assert!(result["message"].as_str().unwrap().contains("contract"));
        assert_eq!(result["outcome"], Value::Null);
        assert_eq!(result["stdout"], stdout);
    }

    let output = fixture
        .command()
        .env("RDBG_FAKE_STDOUT", "partial")
        .env("RDBG_FAKE_STDERR", "PowerShell error: x")
        .env("RDBG_FAKE_EXIT", "1")
        .args(["box-a", "restart"])
        .output()
        .unwrap();
    let result = assert_failure(&output, rdbg::EXIT_REMOTE_COMMAND, "remote_command");
    assert_eq!(result["stderr"], "PowerShell error: x");
}

#[test]
fn busy_alias_never_launches_ssh() {
    let fixture = Fixture::new();
    fixture.write_config(SERVICE_COMFY);
    let lock_dir = fixture.state_home.join("rdbg").join("locks");
    fs::create_dir_all(&lock_dir).unwrap();
    let held = File::create(lock_dir.join("box-a.lock")).unwrap();
    held.lock().unwrap();

    let output = fixture
        .command()
        .args(["box-a", "restart"])
        .output()
        .unwrap();
    assert_failure(&output, rdbg::EXIT_BUSY, "busy");
    assert!(!fixture.ssh_was_launched());

    // --emit-script needs no lock.
    fixture.emit(&["box-a", "restart"]);

    // The doctor shares the lock.
    let output = Command::new(env!("CARGO_BIN_EXE_rdbg"))
        .args(["doctor", "box-a", "transport"])
        .env("XDG_CONFIG_HOME", &fixture.config_home)
        .env("XDG_STATE_HOME", &fixture.state_home)
        .env_remove("RDBG_CONFIG")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(rdbg::EXIT_BUSY));
    assert!(!fixture.ssh_was_launched());

    drop(held);
    let output = fixture
        .command()
        .env(
            "RDBG_FAKE_STDOUT",
            observation("restart", "done", &[]).to_string(),
        )
        .args(["box-a", "restart"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(rdbg::EXIT_OK), "{output:?}");
}

fn validate(fixture: &Fixture, action: &str, document: &str, stderr: Option<&str>) -> Output {
    let path = fixture.root.join("saved.json");
    fs::write(&path, document).unwrap();
    let mut command = fixture.command();
    command.args(["validate", action]).arg(&path);
    if let Some(stderr) = stderr {
        let stderr_path = fixture.root.join("saved.stderr");
        fs::write(&stderr_path, stderr).unwrap();
        command.arg("--stderr").arg(stderr_path);
    }
    command.output().unwrap()
}

#[test]
fn validate_checks_saved_results() {
    let fixture = Fixture::new();
    let done = observation("install-service", "done", &[]).to_string();
    let output = validate(
        &fixture,
        "install-service",
        &saved_result(&done).to_string(),
        None,
    );
    assert_eq!(output.status.code(), Some(rdbg::EXIT_OK), "{output:?}");
    let result = comfy_json(&output);
    assert_eq!(result["target"], "box-a-ssh");
    assert_eq!(result["action"], "install-service");
    assert_eq!(result["outcome"], "done");

    let refused = observation("install-service", "refused", &["not_administrator"]).to_string();
    let output = validate(
        &fixture,
        "install-service",
        &saved_result(&refused).to_string(),
        None,
    );
    assert_failure(&output, rdbg::EXIT_REFUSED, "refused");

    let output = validate(&fixture, "status", &saved_result(&done).to_string(), None);
    assert_failure(&output, rdbg::EXIT_PROBE_PROTOCOL, "probe_protocol");

    let output = validate(&fixture, "status", "not json", None);
    assert_failure(&output, rdbg::EXIT_RESULT_PROTOCOL, "result_protocol");

    let output = validate(
        &fixture,
        "install-service",
        &saved_result(&done).to_string(),
        Some("local note"),
    );
    let result = assert_failure(&output, rdbg::EXIT_RESULT_PROTOCOL, "result_protocol");
    assert_eq!(result["stderr"], "local note");

    let output = fixture
        .command()
        .args(["validate", "status"])
        .arg(fixture.root.join("missing.json"))
        .output()
        .unwrap();
    assert_failure(&output, rdbg::EXIT_LOCAL_INPUT, "local_input");
    assert!(!fixture.ssh_was_launched());
}
