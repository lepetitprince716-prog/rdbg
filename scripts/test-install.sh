#!/bin/sh
# Offline tests for install.sh.
#
# Builds a fake release (tarballs shaped like dist's archives around a stub
# rdbg, plus a unified sha256.sum) and runs install.sh against it with a
# controlled PATH, so no network, real gh or real checksum tool leaks in.
#
#   sh scripts/test-install.sh
#   TEST_SH=/bin/dash sh scripts/test-install.sh   # run install.sh under dash
#
# Exits nonzero if any expectation fails.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
installer=$(cd "$here/.." && pwd)/install.sh
interp=${TEST_SH:-$(command -v sh)}
repo_slug="lepetitprince716-prog/rdbg"

COPYFILE_DISABLE=1
export COPYFILE_DISABLE

tmp=$(mktemp -d "${TMPDIR:-/tmp}/rdbg-test-install.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

setup_die() {
  printf 'test setup: %s\n' "$*" >&2
  exit 2
}

fails=0
check() { # description, then a command that must succeed
  check_what=$1
  shift
  if "$@"; then
    printf 'ok   %s\n' "$check_what"
  else
    printf 'FAIL %s\n' "$check_what"
    fails=$((fails + 1))
  fi
}

# --- tools -----------------------------------------------------------------

if command -v shasum >/dev/null 2>&1; then
  sumtool=shasum
elif command -v sha256sum >/dev/null 2>&1; then
  sumtool=sha256sum
else
  setup_die "need shasum or sha256sum to build the fake release"
fi

sum256() { # FILE -> hex digest
  if [ "$sumtool" = shasum ]; then shasum -a 256 "$1"; else sha256sum "$1"; fi | cut -d ' ' -f 1
}

mkbox() { # DIR [extra tool names]: a PATH directory holding only what install.sh needs
  box_dir=$1
  shift
  mkdir -p "$box_dir"
  for t in awk cat chmod cp gzip mkdir mktemp mv rm tar tr uname "$@"; do
    p=$(command -v "$t") || setup_die "$t not found"
    case "$p" in
      /*) ln -s "$p" "$box_dir/$t" ;;
      *) setup_die "$t is not an external program" ;;
    esac
  done
}

mkbox "$tmp/box-nosum"          # no checksum tool
mkbox "$tmp/box-sum" "$sumtool" # the same, plus one

run_install() { # PATH-value, then install.sh arguments; sets rc, output in $tmp/out
  rpath=$1
  shift
  rc=0
  env -i PATH="$rpath" HOME="$tmp/home" TMPDIR="$tmp/tmpdir" \
    "$interp" "$installer" "$@" >"$tmp/out" 2>&1 || rc=$?
}

mkdir "$tmp/tmpdir" "$tmp/home"

# --- fake release ----------------------------------------------------------

rel=$tmp/release
mkdir "$rel" "$tmp/stage"
for t in aarch64-apple-darwin x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  d=$tmp/stage/rdbg-$t
  mkdir "$d"
  cat >"$d/rdbg" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "--version" ]; then echo "rdbg 0.0.0-test"; exit 0; fi
echo "rdbg stub"
EOF
  chmod 0644 "$d/rdbg" # not executable in the archive, so the 0755 check passes only if install.sh sets it
  echo "stub readme for $t" >"$d/README.md"
  (cd "$tmp/stage" && tar -cf - "rdbg-$t" | gzip -n) >"$rel/rdbg-$t.tar.gz"
done
(
  cd "$rel"
  for f in rdbg-*.tar.gz; do printf '%s *%s\n' "$(sum256 "$f")" "$f"; done
) >"$rel/sha256.sum"

no_leftovers() { test -z "$(ls -A "$tmp/tmpdir")"; }
mode_is_0755() { test -n "$(find "$1" -type f -perm 755)"; } # exact match, not "at least"

# --- 1. success path -------------------------------------------------------

run_install "$tmp/box-sum" --from "$rel" --to "$tmp/t1/bin"
check "success: exit 0" test "$rc" -eq 0
check "success: rdbg is executable" test -x "$tmp/t1/bin/rdbg"
check "success: mode is exactly 0755" mode_is_0755 "$tmp/t1/bin/rdbg"
check "success: installed binary answers --version" \
  test "$("$tmp/t1/bin/rdbg" --version)" = "rdbg 0.0.0-test"
check "success: reports the checksum check" grep -q "SHA-256 verified" "$tmp/out"
check "success: says attestation was not checked without gh" \
  grep -q "attestation was not checked" "$tmp/out"
check "success: only rdbg is in the target dir" test "$(ls -A "$tmp/t1/bin")" = "rdbg"
check "success: no temp files left" no_leftovers

run_install "$tmp/box-sum" --from "$rel" --to "$tmp/t1/bin"
check "success: installing over an existing rdbg works" test "$rc" -eq 0

run_install "$tmp/box-sum" --from "$rel"
check "success: default target dir is HOME/.local/bin" test -x "$tmp/home/.local/bin/rdbg"

# --- 2. tampered archive ---------------------------------------------------

cp -R "$rel" "$tmp/release-tampered"
for f in "$tmp"/release-tampered/rdbg-*.tar.gz; do printf 'x' >>"$f"; done
run_install "$tmp/box-sum" --from "$tmp/release-tampered" --to "$tmp/t2/bin"
check "tampered archive: exit nonzero" test "$rc" -ne 0
check "tampered archive: reports the mismatch" grep -q "SHA-256 mismatch" "$tmp/out"
check "tampered archive: nothing installed" test ! -e "$tmp/t2"
check "tampered archive: no temp files left" no_leftovers

# --- 3. no checksum tool ---------------------------------------------------
# The same command passes in test 1 with box-sum, so the PATH is otherwise enough.

run_install "$tmp/box-nosum" --from "$rel" --to "$tmp/t3/bin"
check "no checksum tool: exit nonzero" test "$rc" -ne 0
check "no checksum tool: says so" grep -q "no SHA-256 tool" "$tmp/out"
check "no checksum tool: nothing installed" test ! -e "$tmp/t3"
check "no checksum tool: no temp files left" no_leftovers

# --- 4. checksum file without an entry for the archive ----------------------

mkdir "$tmp/release-nosum"
cp "$rel"/rdbg-*.tar.gz "$tmp/release-nosum/"
printf '%s *%s\n' "$(sum256 "$rel/sha256.sum")" "something-else.tar.gz" >"$tmp/release-nosum/sha256.sum"
run_install "$tmp/box-sum" --from "$tmp/release-nosum" --to "$tmp/t4/bin"
check "unlisted archive: exit nonzero" test "$rc" -ne 0
check "unlisted archive: nothing installed" test ! -e "$tmp/t4"

# --- 5. gh present: attestation is checked and must pass --------------------

mkgh() { # DIR EXIT-CODE LOG
  mkdir -p "$1"
  cat >"$1/gh" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>"$3"
exit $2
EOF
  chmod 0755 "$1/gh"
}

mkgh "$tmp/gh-ok" 0 "$tmp/gh-ok.log"
run_install "$tmp/gh-ok:$tmp/box-sum" --from "$rel" --to "$tmp/t5/bin"
check "gh ok: exit 0" test "$rc" -eq 0
check "gh ok: rdbg installed" test -x "$tmp/t5/bin/rdbg"
check "gh ok: verify was called once on the archive for this repo" \
  test "$(grep -c -E "^attestation verify .*/rdbg-[a-z0-9_-]+\.tar\.gz --repo $repo_slug\$" "$tmp/gh-ok.log")" = 1
check "gh ok: does not claim the attestation was skipped" \
  test "$(grep -c "attestation was not checked" "$tmp/out")" = 0

mkgh "$tmp/gh-bad" 1 "$tmp/gh-bad.log"
run_install "$tmp/gh-bad:$tmp/box-sum" --from "$rel" --to "$tmp/t6/bin"
check "gh fails: exit nonzero" test "$rc" -ne 0
check "gh fails: says the attestation check failed" grep -q "attestation check failed" "$tmp/out"
check "gh fails: nothing installed" test ! -e "$tmp/t6"
check "gh fails: no temp files left" no_leftovers

# --- 6. download path through a stub curl -----------------------------------

mkcurl() { # DIR LOG EXIT-CODE: records each URL, serves files from the fake release
  mkdir -p "$1"
  cat >"$1/curl" <<EOF
#!/bin/sh
out=""
url=""
while [ "\$#" -gt 0 ]; do
  case "\$1" in
    --output) out=\$2; shift 2 ;;
    -*) shift ;;
    *) url=\$1; shift ;;
  esac
done
printf '%s\n' "\$url" >>"$2"
if [ "$3" -ne 0 ]; then exit "$3"; fi
cp "$rel/\${url##*/}" "\$out"
EOF
  chmod 0755 "$1/curl"
}

base="https://github.com/$repo_slug/releases"
mkcurl "$tmp/curl-ok" "$tmp/curl-ok.log" 0
run_install "$tmp/curl-ok:$tmp/box-sum" --version v9.9.9 --to "$tmp/t7/bin"
check "download pinned: exit 0" test "$rc" -eq 0
check "download pinned: rdbg installed" test -x "$tmp/t7/bin/rdbg"
check "download pinned: archive comes from the tagged release" \
  grep -q -E "^$base/download/v9.9.9/rdbg-[a-z0-9_-]+\.tar\.gz\$" "$tmp/curl-ok.log"
check "download pinned: checksum file comes from the tagged release" \
  grep -q "^$base/download/v9.9.9/sha256.sum\$" "$tmp/curl-ok.log"

: >"$tmp/curl-ok.log"
run_install "$tmp/curl-ok:$tmp/box-sum" --to "$tmp/t8/bin"
check "download latest: exit 0" test "$rc" -eq 0
check "download latest: archive uses the latest/download URL" \
  grep -q -E "^$base/latest/download/rdbg-[a-z0-9_-]+\.tar\.gz\$" "$tmp/curl-ok.log"
check "download latest: checksum file uses the latest/download URL" \
  grep -q "^$base/latest/download/sha256.sum\$" "$tmp/curl-ok.log"
check "download latest: no other URL was requested" test "$(wc -l <"$tmp/curl-ok.log" | tr -d ' ')" = 2

mkcurl "$tmp/curl-bad" "$tmp/curl-bad.log" 22
run_install "$tmp/curl-bad:$tmp/box-sum" --to "$tmp/t9/bin"
check "download fails: exit nonzero" test "$rc" -ne 0
check "download fails: says so" grep -q "download failed" "$tmp/out"
check "download fails: nothing installed" test ! -e "$tmp/t9"
check "download fails: no temp files left" no_leftovers

mkwget() { # DIR LOG: same as mkcurl, for the wget fallback
  mkdir -p "$1"
  cat >"$1/wget" <<EOF
#!/bin/sh
out=""
url=""
while [ "\$#" -gt 0 ]; do
  case "\$1" in
    -O) out=\$2; shift 2 ;;
    -*) shift ;;
    *) url=\$1; shift ;;
  esac
done
printf '%s\n' "\$url" >>"$2"
cp "$rel/\${url##*/}" "\$out"
EOF
  chmod 0755 "$1/wget"
}

mkwget "$tmp/wget-ok" "$tmp/wget-ok.log"
run_install "$tmp/wget-ok:$tmp/box-sum" --version v9.9.9 --to "$tmp/t9w/bin"
check "wget fallback: exit 0" test "$rc" -eq 0
check "wget fallback: rdbg installed" test -x "$tmp/t9w/bin/rdbg"
check "wget fallback: archive comes from the tagged release" \
  grep -q -E "^$base/download/v9.9.9/rdbg-[a-z0-9_-]+\.tar\.gz\$" "$tmp/wget-ok.log"
check "wget fallback: checksum file comes from the tagged release" \
  grep -q "^$base/download/v9.9.9/sha256.sum\$" "$tmp/wget-ok.log"

run_install "$tmp/box-sum" --to "$tmp/t9b/bin"
check "no curl, wget or --from: exit nonzero" test "$rc" -ne 0
check "no curl, wget or --from: says what is needed" grep -q "need curl or wget" "$tmp/out"

# --- 7. platform detection and argument errors ------------------------------

mkuname() { # DIR SYSTEM MACHINE
  mkdir -p "$1"
  cat >"$1/uname" <<EOF
#!/bin/sh
case "\$1" in
  -s) echo "$2" ;;
  -m) echo "$3" ;;
esac
EOF
  chmod 0755 "$1/uname"
}

mkuname "$tmp/uname-odd" Plan9 mips
run_install "$tmp/uname-odd:$tmp/box-sum" --from "$rel" --to "$tmp/t10/bin"
check "unsupported platform: exit nonzero" test "$rc" -ne 0
check "unsupported platform: clear error" grep -q "unsupported platform: Plan9 mips" "$tmp/out"
check "unsupported platform: nothing installed" test ! -e "$tmp/t10"

mkuname "$tmp/uname-intel" Darwin x86_64
run_install "$tmp/uname-intel:$tmp/box-sum" --from "$rel" --to "$tmp/t11/bin"
check "Intel Mac: exit nonzero" test "$rc" -ne 0
check "Intel Mac: clear error" grep -q "no prebuilt rdbg for Intel Macs" "$tmp/out"

mkuname "$tmp/uname-arm-linux" Linux arm64
run_install "$tmp/uname-arm-linux:$tmp/box-sum" --from "$rel" --to "$tmp/t12/bin"
check "Linux arm64 is accepted as aarch64" test "$rc" -eq 0

run_install "$tmp/box-sum" --help
check "--help: exit 0" test "$rc" -eq 0
check "--help: prints usage" grep -q "^Usage: install.sh" "$tmp/out"

# The documented one-liner pipes the script into sh, so nothing the script runs
# may read its stdin, and the script must still run to the end.
rc=0
env -i PATH="$tmp/box-sum" HOME="$tmp/home" TMPDIR="$tmp/tmpdir" \
  "$interp" -s -- --from "$rel" --to "$tmp/t14/bin" <"$installer" >"$tmp/out" 2>&1 || rc=$?
check "piped into sh: exit 0" test "$rc" -eq 0
check "piped into sh: rdbg installed" test -x "$tmp/t14/bin/rdbg"
check "piped into sh: no temp files left" no_leftovers

bad_args() { # DESCRIPTION, then install.sh arguments that must be refused
  bad_what=$1
  shift
  run_install "$tmp/curl-ok:$tmp/box-sum" "$@"
  check "bad arguments ($bad_what): refused" test "$rc" -ne 0
  check "bad arguments ($bad_what): no temp files left" no_leftovers
}
: >"$tmp/curl-ok.log"
bad_args "version without v" --version 1.2.3 --to "$tmp/t13/bin"
bad_args "version with a path" --version v1.2.3/../x --to "$tmp/t13/bin"
bad_args "version with a query" --version 'v1.2.3?x=1' --to "$tmp/t13/bin"
bad_args "--from with --version" --from "$rel" --version v1.2.3 --to "$tmp/t13/bin"
bad_args "--from not a directory" --from "$tmp/nope" --to "$tmp/t13/bin"
bad_args "--to without value" --to
bad_args "unknown option" --frobnicate
check "bad arguments: nothing was requested" test ! -s "$tmp/curl-ok.log"
check "bad arguments: nothing was installed" test ! -e "$tmp/t13"

# --- result ----------------------------------------------------------------

if [ "$fails" -ne 0 ]; then
  printf '\n%s check(s) failed\n' "$fails"
  exit 1
fi
printf '\nall checks passed\n'
