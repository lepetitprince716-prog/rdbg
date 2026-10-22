# rdbg

`rdbg` runs PowerShell on a Windows host over the system `ssh`, without shell quoting problems.
The script travels as a UTF-16LE Base64 payload on stdin behind a small fixed bootstrap, so local
shell quoting, `cmd.exe` and the Windows command-line length limit cannot change it.

Status: early. The controller runs on macOS or Linux; the remote host is Windows with OpenSSH
Server. Diagnostics (`rdbg doctor`) and an optional ComfyUI service module (`rdbg comfy`) are
available.

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

## ComfyUI service (optional)

`rdbg comfy` manages a ComfyUI that is already installed on the host. It never installs ComfyUI
itself; for that, use `comfy install` from [comfy-cli](https://github.com/Comfy-Org/comfy-cli).
comfy-cli is GPL-licensed: rdbg links to it and does not include or copy any of its code.

```text
rdbg comfy [--config PATH] ALIAS status
rdbg comfy [--config PATH] ALIAS restart
rdbg comfy [--config PATH] ALIAS install-service --shawl-exe REMOTE_PATH [--start-type auto|manual]
rdbg comfy [--config PATH] ALIAS uninstall-service
rdbg comfy [--config PATH] ALIAS ACTION [ACTION OPTIONS] --emit-script PATH
rdbg comfy validate ACTION FILE [--stderr FILE]
rdbg comfy shawl
```

Each action runs one fixed script, `crates/rdbg/remote/comfy-service.ps1`, under Windows
PowerShell 5.1. The script never prompts, never elevates through UAC and never kills a process.
It prints one observation with schema `rdbg.comfy.ACTION.v1`, carrying `outcome` (`done`,
`refused` or `failed`), `changed`, `reasons` (stable snake_case identifiers), `service` (`name`,
`present`, `status`, `pid`, `start_type`, `error`; `null` without `expected_service`), `listener`
(`port`, `listening`, `owner_pids`, `all_owners_service_bound`, `error`) and `live` (`reachable`,
`base_uri`, `version`, `expected_version`, `version_matches`, `error`). `restart` adds `ready`,
`install-service` adds `ready`, `rolled_back`, `start_type`, `log_dir` and `conflicts`, and
`uninstall-service` adds `removed`. rdbg wraps it in `rdbg.comfy.result.v1`, shaped like the
doctor result with `action` instead of `probe` and an `outcome` field; `ok` is true only for
outcome `done`. One remote operation runs per alias at a time, on the same lock as the doctor.

| Action | Timeout (s) | Needs | Does |
|---|---|---|---|
| `status` | 30 | `port` | Read-only: service state, port owners and their lineage, `GET http://127.0.0.1:PORT/system_stats` (4 s), version match |
| `restart` | 150 | `expected_service` | `Restart-Service`, then waits up to 120 s for `system_stats`, the expected version and a service-owned listener |
| `install-service` | 210 | `expected_service`, `root`, `python` | Registers the service with shawl, starts it and waits up to 120 s as for `restart` |
| `uninstall-service` | 90 | `expected_service` | Stops the service, waits up to 45 s until it is stopped and the port is free, then `sc.exe delete` |

The `[hosts.ALIAS.comfy]` table takes, besides the doctor keys: `root` (the directory holding
`main.py`), `listen` (default `127.0.0.1`) and `args` (extra ComfyUI arguments; each non-empty,
without `"` or control characters). `expected_service` names the Windows service and must be 1-64
characters of `A-Za-z0-9._-` for `rdbg comfy`. A key an action needs but lacks is a `config` error
before `ssh` starts.

`restart` refuses, changing nothing, when the session is not an administrator, when the service
is missing, or when a process outside the service's process tree holds the port (a rogue
listener is never stopped).

`install-service` checks all of the following first and reports every failure; if any fails it
refuses and touches nothing:

- the session is an administrator;
- `ROOT\main.py` and `python` exist;
- `--shawl-exe` exists and its SHA-256 equals the pinned `exe_sha256`;
- nothing listens on the port;
- no service named `expected_service` exists;
- no other service or scheduled task already starts ComfyUI on this port.

The launcher check reads every service `PathName` and every scheduled task action (`Execute` and
`Arguments`). Every token that names a `.bat`, `.cmd` or `.ps1` file under 64 KB has that file's
text read too. A text conflicts when it contains `--port P` or
`--port=P` for the configured port, or, for port 8188 only (ComfyUI's default), when it mentions
`main.py` without any `--port`. Conflicts are reported by service or task name in `conflicts`,
not by command line. Launchers hidden deeper than one wrapper file, or wrappers given by a
relative path, are not detected.

The service runs `PYTHON main.py --listen LISTEN --port PORT --disable-auto-launch ARGS...` in
`ROOT` through `shawl add --name SERVICE --cwd ROOT --stop-timeout 30000 --kill-process-tree --`,
then gets the start type from `--start-type` (default `auto`). If it is not ready in time, rdbg
stops and deletes the service it just created, and only that one; shawl's logs
(`shawl_for_SERVICE_*.log`) stay next to `shawl.exe`, as `log_dir` reports. `uninstall-service`
refuses any service whose command line is not a `shawl.exe` with `--name SERVICE`, and leaves the
service in place when the port stays busy.

A second instance from the same `ROOT` needs its own `--user-directory`, `--output-directory`,
`--input-directory` and `--temp-directory` in `args`: ComfyUI can clear its temp directory when it
starts, so a shared one could delete files the first instance is using.

shawl is pinned to `v1.9.0`; `rdbg comfy shawl` prints the pins (`rdbg.comfy.shawl.v1`: `version`,
`win64_zip_sha256`, `exe_sha256`). To put it on a host:

```bash
gh release download v1.9.0 --repo mtkennerly/shawl --pattern 'shawl-v1.9.0-win64.zip'
expected=$(rdbg comfy shawl | jq -r .win64_zip_sha256)
echo "$expected  shawl-v1.9.0-win64.zip" | shasum -a 256 -c -
unzip shawl-v1.9.0-win64.zip shawl.exe
scp shawl.exe box-a:C:/tools/shawl.exe
rdbg comfy box-a install-service --shawl-exe 'C:\tools\shawl.exe'
```

Besides the codes above, `rdbg comfy` exits with:

| Exit code | `error_class` | Meaning |
|---|---|---|
| 37 | `refused` | A preflight check or guard declined the action; nothing changed |
| 38 | `action_failed` | The action ran but its postcondition failed; see `changed` and `reasons` |

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
