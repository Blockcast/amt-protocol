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
#   3. Every dependency-resolving cargo call in ci.yml passes `--locked`, which
#      is what ci.yml's top-level env comment promises. `cargo fmt` resolves no
#      dependencies and takes no `--locked`, so it is not checked.
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

calls=0
while IFS= read -r hit; do
  calls=$((calls + 1))
  case "$hit" in
    *--locked*) ;;
    *) echo "FAIL: .github/workflows/ci.yml:${hit%%:*} cargo call lacks --locked"; fail=1 ;;
  esac
done < <(grep -nE '^[[:space:]]*(run:[[:space:]]*)?cargo[[:space:]]+(build|check|clippy|test|run|doc|fetch|install)([[:space:]]|$)' .github/workflows/ci.yml)
[ "$calls" -gt 0 ] || { echo "FAIL: matched no cargo calls in ci.yml"; fail=1; }

echo "checked ${pins} toolchain pins against channel ${channel}, ${calls} ci.yml cargo calls"
[ "$fail" -eq 0 ] && echo PASS
exit "$fail"
