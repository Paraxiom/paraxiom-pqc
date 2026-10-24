#!/usr/bin/env bash
# Fails when the library's dependency graph compiles C or C++, or wraps a C library.
# Checks the default, KEM-only (--no-default-features) and full feature sets, on every target
# platform, with build dependencies included (a C compiler such as `cc` is a build dependency).
# Dev-dependencies are left out: they never ship. The fuzz harness in fuzz/ is a separate
# workspace and not part of the library; its libFuzzer is C++ and stays out of this check.
set -euo pipefail
cd "$(dirname "$0")/.."

# Crates that compile C or C++ at build time, or bind a C library.
FORBIDDEN='^(cc|cmake|bindgen|pkg-config|vcpkg|openssl|openssl-sys|native-tls|ring|aws-lc-rs|aws-lc-sys|boring|boring-sys|pqcrypto[a-z0-9-]*|oqs|oqs-sys|libz-sys|zstd-sys|bzip2-sys|lz4-sys|libsqlite3-sys|blst|secp256k1-sys)$'

status=0
for features in "" "--no-default-features" "--all-features"; do
  label=${features:-default}
  crates=$(cargo tree --locked $features --target all -e normal,build --prefix none --format '{p}' \
    | awk '{print $1}' | sort -u)
  found=$(printf '%s\n' "$crates" | grep -E "$FORBIDDEN" || true)
  if [ -n "$found" ]; then
    echo "FAIL [$label]: C in the dependency graph:"
    for c in $found; do
      echo "  $c, pulled in by:"
      cargo tree --locked $features --target all -e normal,build -i "$c" | sed 's/^/    /'
    done
    status=1
  else
    echo "ok [$label]: $(printf '%s\n' "$crates" | wc -l | tr -d ' ') crates, none compiles or binds C"
  fi
done
exit $status
