# Installing rdbg

rdbg is a single binary (statically linked on Linux). Prebuilt releases exist for macOS on Apple silicon and for Linux on x86_64 and aarch64. There is no Windows or Intel Mac build.

`install.sh` picks the right archive, checks it, and puts `rdbg` in `~/.local/bin`.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/lepetitprince716-prog/rdbg/main/install.sh | sh
```

If you would rather read the script first, download it, look at it, then run it:

```sh
curl -fsSL -o install.sh https://raw.githubusercontent.com/lepetitprince716-prog/rdbg/main/install.sh
sh install.sh
```

Pin a release and a directory:

```sh
sh install.sh --version v0.1.0 --to /usr/local/bin
```

| Option | Meaning |
| --- | --- |
| `--version vX.Y.Z` | Release tag to install. Default: the latest release. |
| `--to DIR` | Install directory. Default: `$HOME/.local/bin`. |
| `--from DIR` | Offline mode: take the archive and `sha256.sum` from `DIR` instead of downloading. Cannot be combined with `--version`. |
| `--verify-attestation` | Also check the GitHub build attestation with `gh`. Needs `gh`, logged in, with network access to GitHub. |

If `DIR` is not on your `PATH`, the installer says so; add it to your shell profile.

## What the installer checks

1. It maps `uname` to a release target, or stops with a clear error on an unsupported machine.
2. It checks the archive against `sha256.sum` with `shasum` or `sha256sum`. If neither exists it stops: it never installs unchecked.
3. With `--verify-attestation` it runs `gh attestation verify` on the archive for this repository and stops if `gh` is missing or the check fails; this needs network access to GitHub and a logged-in `gh` (`gh auth status`). Without the flag it never runs `gh` and prints one line saying the attestation was not checked.
4. It installs `rdbg` with mode 0755 and runs `rdbg --version`.

A failed check installs nothing, and the installer removes its temporary files when it ends.

The checksum file comes from the same release as the archive, so step 2 catches a damaged download but not a replaced release. The attestation shows the archive was built by this repository's release workflow.

## Offline install

On a machine that can reach GitHub, fetch the archive for the target and the checksum file, then copy them over together with `install.sh` (`HOST` is a placeholder):

```sh
gh release download v0.1.0 --repo lepetitprince716-prog/rdbg \
  --pattern 'rdbg-x86_64-unknown-linux-musl.tar.gz' --pattern sha256.sum --dir rdbg-release
scp -r rdbg-release install.sh HOST:/tmp/
```

On the target machine:

```sh
sh /tmp/install.sh --from /tmp/rdbg-release
```

The target names are `aarch64-apple-darwin`, `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.

The attestation check needs GitHub, so on an offline machine leave out `--verify-attestation` and run `gh attestation verify` on the connected machine instead (see below).

## Verify a download by hand

```sh
grep 'rdbg-x86_64-unknown-linux-musl.tar.gz' sha256.sum | shasum -a 256 -c -    # or: sha256sum -c -
gh attestation verify rdbg-x86_64-unknown-linux-musl.tar.gz --repo lepetitprince716-prog/rdbg
```

The first command checks the file against the published checksum. The second proves the file was built by this repository's release workflow.

## Uninstall

```sh
rm ~/.local/bin/rdbg
```
