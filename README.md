# rdbg

`rdbg` runs PowerShell on a Windows host over the system `ssh`, without shell quoting problems.
The script travels as a UTF-16LE Base64 payload on stdin behind a small fixed bootstrap, so local
shell quoting, `cmd.exe` and the Windows command-line length limit cannot change it.

Status: early. The controller runs on macOS or Linux; the remote host is Windows with OpenSSH
Server. Diagnostics (`rdbg doctor`) and an optional ComfyUI service module are being added.

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
