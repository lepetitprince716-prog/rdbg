//! `hosts.toml`: the per-alias settings used by `rdbg doctor` and `rdbg comfy`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

pub(crate) const CONFIG_ENV: &str = "RDBG_CONFIG";
pub(crate) const DEFAULT_COMFY_PORT: u16 = 8188;

/// Aliases that would collide with `rdbg doctor` subcommands.
const RESERVED_ALIASES: &[&str] = &["list", "validate"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostsFile {
    #[serde(default)]
    hosts: BTreeMap<String, RawHostEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHostEntry {
    ssh: String,
    #[serde(default = "default_ssh_bin")]
    ssh_bin: String,
    #[serde(default)]
    no_ssh_opts: bool,
    #[serde(default)]
    comfy: RawComfy,
}

/// The `[hosts.ALIAS.comfy]` table as written; split into the doctor constants and
/// the `rdbg comfy` service settings after parsing.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawComfy {
    #[serde(default = "default_comfy_port")]
    port: u16,
    expected_service: Option<String>,
    expected_version: Option<String>,
    python: Option<String>,
    root: Option<String>,
    #[serde(default = "default_comfy_listen")]
    listen: String,
    #[serde(default)]
    args: Vec<String>,
}

impl Default for RawComfy {
    fn default() -> Self {
        Self {
            port: DEFAULT_COMFY_PORT,
            expected_service: None,
            expected_version: None,
            python: None,
            root: None,
            listen: default_comfy_listen(),
            args: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HostEntry {
    pub(crate) ssh: String,
    pub(crate) ssh_bin: String,
    pub(crate) no_ssh_opts: bool,
    pub(crate) comfy: ComfyEntry,
    pub(crate) service: ComfyServiceEntry,
}

/// The constants every remote script receives.
#[derive(Debug, Clone)]
pub(crate) struct ComfyEntry {
    pub(crate) port: u16,
    pub(crate) expected_service: Option<String>,
    pub(crate) expected_version: Option<String>,
    pub(crate) python: Option<String>,
}

impl Default for ComfyEntry {
    fn default() -> Self {
        Self {
            port: DEFAULT_COMFY_PORT,
            expected_service: None,
            expected_version: None,
            python: None,
        }
    }
}

/// The extra settings used only by `rdbg comfy`.
#[derive(Debug, Clone)]
pub(crate) struct ComfyServiceEntry {
    pub(crate) root: Option<String>,
    pub(crate) listen: String,
    pub(crate) args: Vec<String>,
}

impl From<RawHostEntry> for HostEntry {
    fn from(raw: RawHostEntry) -> Self {
        Self {
            ssh: raw.ssh,
            ssh_bin: raw.ssh_bin,
            no_ssh_opts: raw.no_ssh_opts,
            comfy: ComfyEntry {
                port: raw.comfy.port,
                expected_service: raw.comfy.expected_service,
                expected_version: raw.comfy.expected_version,
                python: raw.comfy.python,
            },
            service: ComfyServiceEntry {
                root: raw.comfy.root,
                listen: raw.comfy.listen,
                args: raw.comfy.args,
            },
        }
    }
}

fn default_comfy_listen() -> String {
    "127.0.0.1".to_owned()
}

/// A value passed on the service command line: non-empty, no `"`, no control characters.
pub(crate) fn is_command_line_safe(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(|ch| ch == '"' || ch.is_control())
}

/// A Windows service name `rdbg comfy` may address: 1-64 of `A-Za-z0-9._-`.
pub(crate) fn is_valid_service_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

fn default_ssh_bin() -> String {
    "ssh".to_owned()
}

fn default_comfy_port() -> u16 {
    DEFAULT_COMFY_PORT
}

#[derive(Debug)]
pub(crate) struct Hosts {
    pub(crate) hosts: BTreeMap<String, HostEntry>,
    /// False only when no explicit path was given and the default file is absent.
    pub(crate) loaded: bool,
}

/// Where the configuration comes from, in lookup order.
fn config_path(explicit: Option<&OsString>) -> Result<(PathBuf, bool), String> {
    if let Some(path) = explicit {
        return Ok((PathBuf::from(path), true));
    }
    if let Some(path) = std::env::var_os(CONFIG_ENV).filter(|value| !value.is_empty()) {
        return Ok((PathBuf::from(path), true));
    }
    let base = match std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
        Some(base) => PathBuf::from(base),
        None => match std::env::var_os("HOME").filter(|value| !value.is_empty()) {
            Some(home) => PathBuf::from(home).join(".config"),
            None => {
                return Err(
                    "cannot locate hosts.toml: set --config, RDBG_CONFIG, XDG_CONFIG_HOME or HOME"
                        .to_owned(),
                );
            }
        },
    };
    Ok((base.join("rdbg").join("hosts.toml"), false))
}

/// Load and validate the hosts file. A missing default file yields an empty set;
/// a missing explicit file (`--config`, `RDBG_CONFIG`) is an error.
pub(crate) fn load(explicit: Option<&OsString>) -> Result<Hosts, String> {
    let (path, explicit) = config_path(explicit)?;
    let text = match fs::read(&path) {
        Ok(bytes) => String::from_utf8(bytes)
            .map_err(|_| format!("config '{}' is not valid UTF-8", path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !explicit => {
            return Ok(Hosts {
                hosts: BTreeMap::new(),
                loaded: false,
            });
        }
        Err(error) => {
            return Err(format!(
                "failed to read config '{}': {error}",
                path.display()
            ));
        }
    };
    parse(&text).map_err(|error| format!("invalid config '{}': {error}", path.display()))
}

pub(crate) fn parse(text: &str) -> Result<Hosts, String> {
    let file: HostsFile = toml::from_str(text).map_err(|error| error.message().to_owned())?;
    for (alias, entry) in &file.hosts {
        validate_alias(alias)?;
        if entry.ssh.is_empty() || entry.ssh.starts_with('-') {
            return Err(format!(
                "hosts.{alias}.ssh must be a non-empty ssh_config alias not starting with '-'"
            ));
        }
        if entry.ssh_bin.is_empty() {
            return Err(format!("hosts.{alias}.ssh_bin must not be empty"));
        }
        if entry.comfy.port == 0 {
            return Err(format!("hosts.{alias}.comfy.port must be 1-65535"));
        }
        if let Some(index) = entry
            .comfy
            .args
            .iter()
            .position(|arg| !is_command_line_safe(arg))
        {
            return Err(format!(
                "hosts.{alias}.comfy.args[{index}] must be non-empty and contain no '\"' \
                 or control characters"
            ));
        }
    }
    Ok(Hosts {
        hosts: file
            .hosts
            .into_iter()
            .map(|(alias, entry)| (alias, HostEntry::from(entry)))
            .collect(),
        loaded: true,
    })
}

/// An alias also names a lock file, so it is limited to a portable character set.
fn validate_alias(alias: &str) -> Result<(), String> {
    let valid_chars = alias
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'));
    if alias.is_empty()
        || alias.len() > 64
        || !valid_chars
        || alias.starts_with(['-', '.'])
        || RESERVED_ALIASES.contains(&alias)
    {
        return Err(format!(
            "host alias '{alias}' must be 1-64 characters of A-Z a-z 0-9 . _ -, \
             must not start with '-' or '.', and must not be 'list' or 'validate'"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply() {
        let hosts = parse("[hosts.box-a]\nssh = \"box-a\"\n").unwrap();
        let entry = &hosts.hosts["box-a"];
        assert_eq!(entry.ssh_bin, "ssh");
        assert!(!entry.no_ssh_opts);
        assert_eq!(entry.comfy.port, 8188);
        assert!(entry.comfy.expected_service.is_none());
    }

    #[test]
    fn full_entry_parses() {
        let hosts = parse(
            "[hosts.box-b]\nssh = \"box-b\"\nssh_bin = \"/opt/ssh\"\nno_ssh_opts = true\n\
             [hosts.box-b.comfy]\nport = 9188\nexpected_service = \"Svc\"\n\
             expected_version = \"1.0.0\"\npython = 'C:\\venv\\python.exe'\n",
        )
        .unwrap();
        let entry = &hosts.hosts["box-b"];
        assert!(entry.no_ssh_opts);
        assert_eq!(entry.comfy.port, 9188);
        assert_eq!(entry.comfy.python.as_deref(), Some(r"C:\venv\python.exe"));
    }

    #[test]
    fn example_file_parses() {
        let hosts = parse(include_str!("../../../hosts.example.toml")).unwrap();
        assert_eq!(hosts.hosts.keys().collect::<Vec<_>>(), ["box-a", "box-b"]);
        assert_eq!(hosts.hosts["box-a"].comfy.port, 8188);
    }

    #[test]
    fn service_keys_parse_with_defaults() {
        let hosts = parse("[hosts.box-a]\nssh = \"box-a\"\n").unwrap();
        let service = &hosts.hosts["box-a"].service;
        assert_eq!(service.listen, "127.0.0.1");
        assert!(service.root.is_none() && service.args.is_empty());

        let hosts = parse(
            "[hosts.box-a]\nssh = \"box-a\"\n[hosts.box-a.comfy]\nroot = 'C:\\ComfyUI'\n\
             listen = \"0.0.0.0\"\nargs = [\"--lowvram\", \"--output-directory\", 'D:\\out dir']\n",
        )
        .unwrap();
        let service = &hosts.hosts["box-a"].service;
        assert_eq!(service.root.as_deref(), Some(r"C:\ComfyUI"));
        assert_eq!(service.listen, "0.0.0.0");
        assert_eq!(
            service.args,
            ["--lowvram", "--output-directory", r"D:\out dir"]
        );
    }

    #[test]
    fn service_name_rule() {
        for good in ["Svc", "a.b_c-1", &"x".repeat(64)] {
            assert!(is_valid_service_name(good), "{good}");
        }
        for bad in ["", "Svc's", "a b", "a/b", &"x".repeat(65), "Ünï"] {
            assert!(!is_valid_service_name(bad), "{bad}");
        }
    }

    #[test]
    fn rejects_bad_configs() {
        for text in [
            "[hosts.box-a]\nssh = \"box-a\"\nunknown = 1\n",
            "[hosts.box-a]\nssh = \"box-a\"\n[hosts.box-a.comfy]\nport = 1\nextra = 2\n",
            "[hosts.box-a]\nssh_bin = \"ssh\"\n",
            "[hosts.box-a]\nssh = \"-oProxyCommand=x\"\n",
            "[hosts.list]\nssh = \"box-a\"\n",
            "[hosts.\"a/b\"]\nssh = \"box-a\"\n",
            "[hosts.box-a]\nssh = \"box-a\"\n[hosts.box-a.comfy]\nport = 70000\n",
            "top = 1\n",
            "[hosts.box-a]\nssh = \"\"\n",
            "[hosts.box-a]\nssh = \"a\"\n[hosts.box-a.comfy]\nargs = [\"\"]\n",
            "[hosts.box-a]\nssh = \"a\"\n[hosts.box-a.comfy]\nargs = [\"--x=\\\"y\\\"\"]\n",
            "[hosts.box-a]\nssh = \"a\"\n[hosts.box-a.comfy]\nargs = [\"a\\nb\"]\n",
            "[hosts.box-a]\nssh = \"a\"\n[hosts.box-a.comfy]\nargs = \"--x\"\n",
        ] {
            assert!(parse(text).is_err(), "accepted: {text}");
        }
    }
}
