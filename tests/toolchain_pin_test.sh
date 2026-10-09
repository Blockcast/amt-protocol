#!/usr/bin/env bash
# Holds rust-toolchain.toml (BLO-41503) to what it and ci.yml claim. Static, no
# PyYAML, no toolchain needed.
#
#   1. Every `uses: dtolnay/rust-toolchain@<rev>` in .github/workflows/ equals the
#      toml's `channel`. A floating `@stable` is the drift this exists for: the
#      toml silently outranks it, so the job stays green while its file names a
#      toolchain it does not use, and the next bump downloads two. `@nightly` is
#      the one exception -- the driad-parser fuzz job needs nightly and selects it
#      with RUSTUP_TOOLCHAIN, which outranks the toml.
#   2. .dockerignore excludes rust-toolchain.toml. The Dockerfile pins its own
#      compiler (`FROM rust:<ver>`) for the published amt-verify binary; with the
#      toml in the build context the image's rustup proxy honours the toml over
#      that pin. publish-amt-verify.yml runs only on push to main, so no PR check
#      would see the substitution.
#   3. The Dockerfile's `FROM rust:<ver>` equals the toml's `channel`, patch
#      included. That image builds the published amt-verify binary, so without
#      this the `lint (native)` / `test (native)` jobs are evidence about a
#      different compiler than the one that ships. Matched case-insensitively
#      because Docker accepts `from`, and a lowercased line escaping this check
#      is the subset match the count below cannot see. A non-numeric tag
#      (`rust:latest`) captures nothing and fails: it is not a pin.
#   4. Every dependency-resolving cargo call in ci.yml passes `--locked`, which
#      is what ci.yml's top-level env comment promises. `cargo fmt` resolves no
#      dependencies and takes no `--locked`, so it is not checked. The optional
#      leading `- ` matters: a one-line `- run: cargo build` step is the commonest
#      form, and without it that step escapes this check silently -- the count
#      below still reads 7, because it catches a pattern matching NOTHING, not one
#      matching a subset.
#
# Prints how many pins and cargo calls it checked, so a pattern that silently
# matches nothing reads as a failure, not a pass.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

fail=0

channel=$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' rust-toolchain.toml)
[ -n "$channel" ] || { echo "FAIL: no channel in rust-toolchain.toml"; exit 1; }

pins=0
while IFS= read -r hit; do
  rev=${hit##*dtolnay/rust-toolchain@}
  rev=${rev%%[[:space:]]*}
  pins=$((pins + 1))
  if [ "$rev" != "$channel" ] && [ "$rev" != "nightly" ]; then
    echo "FAIL: ${hit%%:[[:space:]]*} pins @$rev; rust-toolchain.toml channel is $channel"
    fail=1
  fi
done < <(grep -nE '^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*dtolnay/rust-toolchain@' .github/workflows/*.yml)
[ "$pins" -gt 0 ] || { echo "FAIL: matched no dtolnay/rust-toolchain pins"; fail=1; }

if ! grep -qxF 'rust-toolchain.toml' .dockerignore; then
  echo "FAIL: .dockerignore does not exclude rust-toolchain.toml; it would override the Dockerfile's FROM rust:<ver> pin"
  fail=1
fi

froms=0
while IFS= read -r hit; do
  froms=$((froms + 1))
  ver=$(printf '%s' "${hit#*:}" | tr 'A-Z' 'a-z' \
    | sed -n 's/.*from[[:space:]]\{1,\}rust:\([0-9][0-9.]*\).*/\1/p')
  if [ "$ver" != "$channel" ]; then
    echo "FAIL: Dockerfile:${hit%%:*} builds amt-verify with rust:${ver:-<non-numeric tag>}; rust-toolchain.toml channel is $channel"
    fail=1
  fi
done < <(grep -niE '^[[:space:]]*FROM[[:space:]]+rust:' Dockerfile)
[ "$froms" -gt 0 ] || { echo "FAIL: matched no FROM rust: pins in Dockerfile"; fail=1; }

calls=0
while IFS= read -r hit; do
  calls=$((calls + 1))
  case "$hit" in
    *--locked*) ;;
    *) echo "FAIL: .github/workflows/ci.yml:${hit%%:*} cargo call lacks --locked"; fail=1 ;;
  esac
done < <(grep -nE '^[[:space:]]*(-[[:space:]]+)?(run:[[:space:]]*)?cargo[[:space:]]+(build|check|clippy|test|run|doc|fetch|install)([[:space:]]|$)' .github/workflows/ci.yml)
[ "$calls" -gt 0 ] || { echo "FAIL: matched no cargo calls in ci.yml"; fail=1; }

echo "checked ${pins} toolchain pins and ${froms} Dockerfile FROM rust: pins against channel ${channel}, ${calls} ci.yml cargo calls"
[ "$fail" -eq 0 ] && echo PASS
exit "$fail"
