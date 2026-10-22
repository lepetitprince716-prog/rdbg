#!/bin/sh
# Install a prebuilt rdbg release.
#
#   install.sh [--version vX.Y.Z] [--to DIR] [--from DIR] [--verify-attestation]
#
# Gets rdbg-<target>.tar.gz and sha256.sum from the GitHub release, checks the
# SHA-256 (it fails when the machine has no checksum tool), checks the build
# attestation with the GitHub CLI when --verify-attestation is given, then
# installs rdbg with mode 0755 and runs `rdbg --version`. Nothing is installed
# unless every check passes.

set -eu

REPO="lepetitprince716-prog/rdbg"
RELEASES="https://github.com/${REPO}/releases"
APP="rdbg"
SUMS="sha256.sum"

work=""
staged=""

say() { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }
die() {
  printf 'install.sh: error: %s\n' "$*" >&2
  exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  if [ -n "$staged" ]; then rm -f "$staged"; fi
  if [ -n "$work" ]; then rm -rf "$work"; fi
}

usage() {
  cat <<'EOF'
Usage: install.sh [--version vX.Y.Z] [--to DIR] [--from DIR] [--verify-attestation]

Install the prebuilt rdbg binary for this machine.

  --version vX.Y.Z  release tag to install (default: the latest release)
  --to DIR          install directory (default: $HOME/.local/bin)
  --from DIR        offline mode: use the archive and sha256.sum found in DIR
                    instead of downloading them
  --verify-attestation
                    also check the GitHub build attestation; needs gh,
                    logged in, with network access to GitHub
  -h, --help        show this help

Prebuilt for macOS on Apple silicon and for Linux on x86_64 and aarch64.
EOF
}

detect_target() {
  os=$(uname -s)
  arch=$(uname -m)
  case "$os $arch" in
    "Darwin arm64") printf '%s\n' aarch64-apple-darwin ;;
    "Linux x86_64" | "Linux amd64") printf '%s\n' x86_64-unknown-linux-musl ;;
    "Linux aarch64" | "Linux arm64") printf '%s\n' aarch64-unknown-linux-musl ;;
    "Darwin x86_64") die "no prebuilt rdbg for Intel Macs (a shell running under Rosetta on Apple silicon also reports x86_64)" ;;
    *) die "unsupported platform: $os $arch (prebuilt: macOS arm64, Linux x86_64, Linux aarch64)" ;;
  esac
}

download() {
  if have curl; then
    curl --fail --silent --show-error --location --retry 3 \
      --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --output "$2" "$1"
  else
    wget -q -O "$2" "$1"
  fi
}

sha256_of() {
  if have shasum; then
    shasum -a 256 "$1" | awk '{ print $1 }'
  else
    sha256sum "$1" | awk '{ print $1 }'
  fi
}

main() {
  version=""
  dest=""
  from=""
  attest=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --version | --to | --from)
        if [ "$#" -lt 2 ] || [ -z "$2" ]; then die "$1 needs a value (see --help)"; fi
        case "$1" in
          --version) version=$2 ;;
          --to) dest=$2 ;;
          --from) from=$2 ;;
        esac
        shift 2
        ;;
      --verify-attestation)
        attest=1
        shift
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) die "unknown option: $1 (see --help)" ;;
    esac
  done

  if [ -n "$version" ]; then
    case "$version" in
      v[0-9]*) ;;
      *) die "--version must be a release tag like v1.2.3 (got: $version)" ;;
    esac
    case "$version" in
      *[!0-9A-Za-z.+-]*) die "--version has unexpected characters: $version" ;;
    esac
  fi
  if [ -n "$from" ] && [ -n "$version" ]; then
    die "--from and --version cannot be combined: the version is whatever DIR holds"
  fi
  if [ -z "$dest" ]; then
    if [ -z "${HOME:-}" ]; then die "HOME is not set; pass --to DIR"; fi
    dest="$HOME/.local/bin"
  fi

  target=$(detect_target) || exit 1
  archive="${APP}-${target}.tar.gz"

  have tar || die "tar not found"
  have gzip || die "gzip not found"
  if ! have shasum && ! have sha256sum; then
    die "no SHA-256 tool found (need shasum or sha256sum); refusing to install an unverified binary"
  fi
  if [ "$attest" = 1 ] && ! have gh; then
    die "--verify-attestation needs the GitHub CLI (gh); nothing was installed"
  fi
  if [ -z "$from" ] && ! have curl && ! have wget; then
    die "need curl or wget to download (or use --from DIR)"
  fi

  trap cleanup EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  work=$(mktemp -d "${TMPDIR:-/tmp}/rdbg-install.XXXXXX") || die "cannot create a temporary directory"

  if [ -n "$from" ]; then
    if [ ! -d "$from" ]; then die "--from: not a directory: $from"; fi
    for f in "$archive" "$SUMS"; do
      if [ ! -f "$from/$f" ]; then die "--from: $from/$f not found"; fi
      cp "$from/$f" "$work/$f" || die "cannot copy $from/$f"
    done
    say "Using $archive from $from"
  else
    if [ -n "$version" ]; then
      base="$RELEASES/download/$version"
    else
      base="$RELEASES/latest/download"
    fi
    for f in "$archive" "$SUMS"; do
      say "Downloading $base/$f"
      download "$base/$f" "$work/$f" || die "download failed: $base/$f"
    done
  fi

  # The checksum file lists "<hex> [*]<file name>"; take the line for our archive.
  expected=$(awk -v name="$archive" '{ n = $2; sub(/^\*/, "", n); if (n == name) { print $1; exit } }' "$work/$SUMS") ||
    die "cannot read $SUMS"
  expected=$(printf '%s' "$expected" | tr 'A-F' 'a-f')
  case "$expected" in
    "" | *[!0-9a-f]*) die "$SUMS has no valid SHA-256 for $archive; nothing was installed" ;;
  esac
  if [ "${#expected}" -ne 64 ]; then die "$SUMS has no valid SHA-256 for $archive; nothing was installed"; fi
  actual=$(sha256_of "$work/$archive") || die "cannot hash $archive"
  if [ "$actual" != "$expected" ]; then
    die "SHA-256 mismatch for $archive (expected $expected, got ${actual:-nothing}); nothing was installed"
  fi
  say "SHA-256 verified"

  if [ "$attest" = 1 ]; then
    say "Checking build attestation with gh"
    gh attestation verify "$work/$archive" --repo "$REPO" </dev/null ||
      die "attestation check failed (gh needs network access and a login, see: gh auth status); nothing was installed"
  else
    warn "Note: the build attestation was not checked; pass --verify-attestation to check it with gh."
  fi

  unpacked="$work/unpacked"
  mkdir "$unpacked" || die "cannot create $unpacked"
  (cd "$unpacked" && gzip -dc "$work/$archive" | tar -xf -) || die "cannot unpack $archive"
  bin="$unpacked/${archive%.tar.gz}/$APP"
  if [ ! -f "$bin" ]; then bin="$unpacked/$APP"; fi
  if [ ! -f "$bin" ] || [ -L "$bin" ]; then die "$archive has no regular file named $APP"; fi

  mkdir -p "$dest" || die "cannot create $dest"
  staged="$dest/.$APP.new.$$"
  cp "$bin" "$staged" || die "cannot write to $dest"
  chmod 0755 "$staged" || die "cannot set the mode of $staged"
  version_line=$("$staged" --version 2>&1 </dev/null) ||
    die "smoke check failed ($APP --version: $version_line); nothing was installed"
  mv -f "$staged" "$dest/$APP" || die "cannot move $APP into $dest"
  staged=""

  say "Installed $version_line at $dest/$APP"
  case ":${PATH:-}:" in
    *":$dest:"*) ;;
    *) say "Note: $dest is not on your PATH." ;;
  esac
}

main "$@"
