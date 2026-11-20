#![cfg(unix)]

//! Every value rdbg writes into a remote script header must reach PowerShell as the
//! same string. PowerShell's tokenizer treats U+2018, U+2019, U+201A and U+201B as
//! single quotes, exactly like `'` (`CharExtensions.IsSingleQuote` in
//! `System.Management.Automation/engine/parser/CharTraits.cs`), so each of them can end
//! a single-quoted literal. These tests compose scripts through the real CLI entry
//! points (`rdbg doctor ... --emit-script`, `rdbg comfy ... --emit-script`), evaluate
//! only the composed header under `pwsh`, and compare every constant with the raw
//! configured value. Without `pwsh` on PATH each test prints a skip line.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

/// ASCII `'` and the four Unicode characters PowerShell also reads as a single quote.
const QUOTES: [char; 5] = ['\'', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'];

/// Exit code the injected statement would produce if a value escaped its literal.
const INJECTED_EXIT: i32 = 7;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("rdbg-quoting-pwsh-{}-{id}", std::process::id()));
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

/// A value that closes a literal ended by `quote` and runs `exit(7)` if it is not escaped.
/// It holds no whitespace, `"` or control characters, so every config key and
/// `--shawl-exe` accept it.
fn payload(quote: char, field: &str) -> String {
    format!("X{field}{quote};exit({INJECTED_EXIT});#{quote}")
}

/// A TOML basic string for `value` (escapes only what TOML requires here).
fn toml_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn write_config(scratch: &Scratch, comfy: &str) -> PathBuf {
    let config = scratch.0.join("hosts.toml");
    fs::write(
        &config,
        format!("[hosts.box-a]\nssh = \"box-a\"\n[hosts.box-a.comfy]\n{comfy}"),
    )
    .unwrap();
    config
}

fn emit(command: &str, config: &Path, args: &[&str], script: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_rdbg"))
        .arg(command)
        .arg("--config")
        .arg(config)
        .args(args)
        .arg("--emit-script")
        .arg(script)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    fs::read_to_string(script).unwrap()
}

/// The composed header: every line up to and including the one assigning `last`.
fn header(script: &str, last: &str) -> String {
    let mut lines = Vec::new();
    for line in script.lines() {
        lines.push(line);
        if line.starts_with(last) {
            return lines.join("\n") + "\n";
        }
    }
    panic!("no line starting with {last} in:\n{script}");
}

/// Run `header` followed by `report` under pwsh and parse the JSON it prints.
fn evaluate(pwsh: &Path, scratch: &Scratch, header: &str, report: &str) -> Value {
    let path = scratch.0.join("header.ps1");
    // A BOM makes Windows PowerShell and pwsh both read the file as UTF-8.
    let mut bytes = "\u{feff}".as_bytes().to_vec();
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(report.as_bytes());
    fs::write(&path, bytes).unwrap();
    let output = Command::new(pwsh)
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
        .arg(&path)
        .output()
        .unwrap();
    assert_ne!(
        output.status.code(),
        Some(INJECTED_EXIT),
        "an injected statement ran:\n{header}"
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}\n{header}");
    assert!(output.stderr.is_empty(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}: {}\n{header}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

#[test]
fn doctor_constants_reach_powershell_unchanged_for_every_single_quote() {
    let Some(pwsh) = pwsh() else {
        println!("skipping doctor quoting test: pwsh not found on PATH");
        return;
    };
    for quote in QUOTES {
        let scratch = Scratch::new();
        let version = payload(quote, "version");
        let python = payload(quote, "python");
        let config = write_config(
            &scratch,
            &format!(
                "expected_service = \"Svc\"\nexpected_version = {}\npython = {}\n",
                toml_string(&version),
                toml_string(&python)
            ),
        );
        let script = emit(
            "doctor",
            &config,
            &["box-a", "transport"],
            &scratch.0.join("doctor.ps1"),
        );
        let observed = evaluate(
            &pwsh,
            &scratch,
            &header(&script, "$CanonicalPython = "),
            "[ordered]@{ service = $ExpectedService; version = $ExpectedComfyVersion; \
             python = $CanonicalPython } | ConvertTo-Json -Compress\n",
        );
        assert_eq!(
            observed,
            json!({"service": "Svc", "version": version, "python": python}),
            "U+{:04X}",
            u32::from(quote)
        );
    }
}

#[test]
fn comfy_constants_reach_powershell_unchanged_for_every_single_quote() {
    let Some(pwsh) = pwsh() else {
        println!("skipping comfy quoting test: pwsh not found on PATH");
        return;
    };
    for quote in QUOTES {
        let scratch = Scratch::new();
        let version = payload(quote, "version");
        let python = payload(quote, "python");
        let root = payload(quote, "root");
        let listen = payload(quote, "listen");
        let args = [payload(quote, "arg0"), payload(quote, "arg1")];
        let shawl = payload(quote, "shawl");
        let config = write_config(
            &scratch,
            &format!(
                "expected_service = \"Svc\"\nexpected_version = {}\npython = {}\nroot = {}\n\
                 listen = {}\nargs = [{}, {}]\n",
                toml_string(&version),
                toml_string(&python),
                toml_string(&root),
                toml_string(&listen),
                toml_string(&args[0]),
                toml_string(&args[1]),
            ),
        );
        let script = emit(
            "comfy",
            &config,
            &["box-a", "install-service", "--shawl-exe", &shawl],
            &scratch.0.join("comfy.ps1"),
        );
        let observed = evaluate(
            &pwsh,
            &scratch,
            &header(&script, "$StartType = "),
            "[ordered]@{ version = $ExpectedComfyVersion; python = $CanonicalPython; \
             action = $Action; root = $ComfyRoot; listen = $ComfyListen; \
             args = @($ComfyArgs); shawl = $ShawlExe; start = $StartType } \
             | ConvertTo-Json -Compress\n",
        );
        assert_eq!(
            observed,
            json!({
                "version": version,
                "python": python,
                "action": "install-service",
                "root": root,
                "listen": listen,
                "args": args,
                "shawl": shawl,
                "start": "auto",
            }),
            "U+{:04X}",
            u32::from(quote)
        );
    }
}
