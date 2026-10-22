# rdbg

`rdbg` runs PowerShell on a Windows host over the system `ssh`, without shell quoting problems.
The script travels as a UTF-16LE Base64 payload on stdin behind a small fixed bootstrap, so local
shell quoting, `cmd.exe` and the Windows command-line length limit cannot change it.

Status: early. The controller runs on macOS or Linux; the remote host is Windows with OpenSSH
Server. Diagnostics (`rdbg doctor`) are available; an optional ComfyUI service module is being
added.

## Usage

```text
rdbg [--json] [--ssh SSH] [--no-ssh-opts] [--timeout SECONDS] ps TARGET --eval SCRIPT
rdbg [--json] [--ssh SSH] [--no-ssh-opts] [--timeout SECONDS] ps TARGET --file PATH
rdbg [--json] [--ssh SSH] [--no-ssh-opts] [--timeout SECONDS] ps TARGET --file -
rdbg --version
```

`TARGET` is a host, `user@host`, or an alias from `ssh_config`. Keep addresses, users and keys in
`~/.ssh/config`; `rdbg` adds nothing beyond the alias.

```bash
rdbg ps box-a --eval '$PSVersionTable.PSVersion.ToString()'
rdbg --json --timeout 60 ps box-a --file ./check.ps1
```

By default `rdbg` passes `BatchMode`, strict host-key checking, a connect timeout and keep-alive
options to `ssh`. Use `--no-ssh-opts` when `--ssh` points at a wrapper that sets its own.

## JSON result

With `--json`, stdout holds one object with schema `rdbg.result.v1`: `ok`, `rdbg_exit_code`,
`process_exit_code`, `target`, `mode`, `timeout_seconds`, `stdout`, `stderr`, their
`*_truncated` and `*_utf8_lossy` flags, `error_class` and `message`. Each stream is capped at
1 MiB.

| Exit code | `error_class` | Meaning |
|---|---|---|
| 0 | none | Remote script exited 0 |
| 2 | `usage` | Bad arguments |
| 10 | `local_input` | Script file missing or not valid UTF-8/UTF-16 |
| 20 | `ssh_launch` | `ssh` could not start |
| 21 | `ssh_io` | Pipe or process-handling error while talking to `ssh` |
| 22 | `ssh_hostkey`, `ssh_auth`, `ssh_timeout`, `dns_resolution`, `connection_refused`, `cloudflared_handshake`, `ssh_transport` | `ssh` exited 255 |
| 23 | `remote_command` | Remote script exited nonzero |
| 24 | `ssh_terminated` | `ssh` was killed by a signal |
| 25 | `execution_timeout` | `--timeout` expired; the `ssh` process group was killed |

## Diagnostics

`rdbg doctor` runs one of seven fixed, read-only probes on a configured host and checks the
answer against a strict, versioned contract. It never runs an arbitrary script.

```text
rdbg doctor [--config PATH] list
rdbg doctor [--config PATH] ALIAS PROBE
rdbg doctor [--config PATH] ALIAS PROBE --emit-script PATH
rdbg doctor validate PROBE FILE [--stderr FILE]
```

| Probe | Timeout (s) | Observes |
|---|---|---|
| `transport` | 20 | SSH, PowerShell 5.1 and Unicode/quoting transport |
| `overview` | 30 | Windows, memory, CPU and key services |
| `network` | 25 | Active adapters and local SSH/ComfyUI listeners |
| `comfyui` | 20 | Loopback `system_stats`, queue and version |
| `listener` | 25 | ComfyUI port owner, parent chain and service |
| `gpu` | 25 | `nvidia-smi` memory, utilization, temperature, power and processes |
| `snapshot` | 30 | Redacted Fastfetch snapshot with a PowerShell/CIM fallback |

Hosts live in `hosts.toml`, found through `--config PATH`, then `$RDBG_CONFIG`, then
`${XDG_CONFIG_HOME:-$HOME/.config}/rdbg/hosts.toml`; see [hosts.example.toml](hosts.example.toml).
Each `[hosts.ALIAS]` table takes `ssh` (an ssh_config alias, required), `ssh_bin` (default
`ssh`) and `no_ssh_opts` (default `false`). An optional `[hosts.ALIAS.comfy]` table takes `port`
(default 8188), `expected_service`, `expected_version` and `python`. Unknown keys are rejected.
These values are prepended to the probe as `$ComfyPort`, `$ExpectedService`,
`$ExpectedComfyVersion` and `$CanonicalPython`, single-quoted, or `$null` when absent.

- `list` prints `rdbg.doctor.capabilities.v1`: the configured aliases and the probe table.
- `ALIAS PROBE` prints `rdbg.doctor.result.v1`. One probe runs per alias at a time; the lock is
  `${XDG_STATE_HOME:-$HOME/.local/state}/rdbg/locks/ALIAS.lock`.
- `--emit-script PATH` writes the composed script and exits without running `ssh`, so another
  transport can run it with `rdbg --json ps TARGET --file PATH`.
- `validate` reads that saved `rdbg.result.v1` JSON and applies the same checks as a live run.
  `--stderr FILE` supplies the local stderr captured with it.

The result carries `target`, `probe`, `ok`, `healthy`, `summary`, `error_class`, `message`,
`duration_ms`, `process_exit_code`, `rdbg_exit_code`, `observation`, `stdout`, `stderr` and their
`*_truncated` flags. When the observation validates, `stdout` is `null`. `stderr` is the remote
stderr, or the local stderr when the remote one is empty. Both are capped at 32000 Unicode code
points, followed by `\n...[truncated]` when cut. `ok` with `healthy: false` means the probe ran
and found a problem; the exit code is still 0.

Besides the codes above, `rdbg doctor` exits with:

| Exit code | `error_class` | Meaning |
|---|---|---|
| 30 | `config` | `hosts.toml` missing, unreadable or invalid |
| 31 | `unknown_target` | `ALIAS` is not configured |
| 32 | `unknown_probe` | `PROBE` is not one of the seven probes |
| 33 | `busy` | Another probe holds this alias's lock; `ssh` was not started |
| 34 | `probe_protocol` | The probe output was truncated or violated its contract |
| 35 | `result_protocol` | The `rdbg.result.v1` document is malformed or inconsistent, or local stderr was not empty |
| 36 | `local_io` | The lock file or the `--emit-script` file could not be created or written |

A failed run keeps the error class and exit code (20-25) of the underlying `rdbg ps` call.

## Build

```bash
cargo build --release --locked
cargo test --locked
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

## Privacy guard

This repository is public. `tools/privacy_scan.py` runs from the git hooks in `.githooks/` and in
CI; see [tools/README.md](tools/README.md). Enable the hooks once per clone with
`git config core.hooksPath .githooks`.
