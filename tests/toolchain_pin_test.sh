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
#   4. Every dependency-resolving cargo call in .github/workflows/*.yml passes
#      `--locked`, which is what ci.yml's top-level env comment promises. `cargo
#      fmt` and `cargo fuzz` resolve no dependencies at that position and take no
#      `--locked`, so they are not checked. Two things this used to get wrong
#      (BLO-42496), neither visible from a green run because a missed call reads
#      exactly like no missed call:
#        - the pattern was anchored at line start, so `RUSTFLAGS=x cargo build`,
#          `cd fuzz && cargo test`, and anything after `&&` inside a `run: |`
#          block escaped it. It now matches `cargo` after any of ` =;&|(` too.
#        - the scan read ci.yml alone while the pin scan above globbed
#          `*.yml`, which is how driad-parser.yml carried three unlocked
#          `cargo test` calls. Both now glob.
#      `#` comments and YAML `name:` keys are blanked first: a step named
#      `- name: cargo test (lib)` is not an invocation and carries no `--locked`.
#      The per-file guard is what makes a broken pattern loud -- a file whose
#      blanked body still says `cargo` must yield at least one call, so a rename
#      or a bad regex fails instead of reading as "nothing to check". A file with
#      no cargo at all (publish-amt-verify.yml) is legitimately zero.
#   5. This script runs from ci.yml's `lint` job and from no other job there, and
#      any `if:` on that step names a leg `lint`'s matrix actually has. `lint
#      (<id>)` legs are required checks on `main`; `probe verdict logic` is not,
#      so while this ran there a red verdict stayed mergeable and 1-4 were
#      advisory. A gate naming a missing leg skips the step on every leg -- green,
#      enforcing nothing. (A typo'd gate also skips this check itself in CI;
#      running it anywhere else still catches that.)
#
# Prints how many pins and cargo calls it checked, so a pattern that silently
# matches nothing reads as a failure, not a pass.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

# `--self-test`: the failing mutations for check 4, in the repo rather than in a
# PR body. BLO-38880 is the same lesson on the sibling guard, and check 4 is the
# thing it happened to: the mutations that would have caught the anchored pattern
# and the ci.yml-only glob were described on #88 and never left runnable, so the
# next reader had a green run and no way to tell which arms were inert
# (BLO-42496). Each leg builds a minimal repo around a copy of this script,
# applies ONE mutation, and asserts the rc and the headline.
if [ "${1:-}" = --self-test ]; then
    tmp=$(mktemp -d) || exit 1
    trap 'rm -rf "$tmp"' EXIT
    me=${BASH_SOURCE[0]}; base=$(basename "$me"); legs=0 fails=0

    # leg <name> <want-rc> <want-text> [--no-cargo] -- extra workflow yaml is
    # read from stdin as driad.yml; `-` means write no second workflow at all.
    # `--no-cargo` drops the cargo step from the fixture ci.yml, which is the
    # only way to reach the global "matched nothing anywhere" arm: the per-file
    # guard below it only fires on a file that still says `cargo`.
    leg() {
        local name=$1 want=$2 text=$3 nocargo=${4:-} d=$tmp/$1 out rc
        mkdir -p "$d/tests" "$d/.github/workflows"; cp "$me" "$d/tests/$base"
        printf 'channel = "1.99.0"\n' >"$d/rust-toolchain.toml"
        printf 'rust-toolchain.toml\n' >"$d/.dockerignore"
        printf 'FROM rust:1.99.0\n' >"$d/Dockerfile"
        cat >"$d/.github/workflows/ci.yml" <<'CI'
jobs:
  lint:
    steps:
      - uses: dtolnay/rust-toolchain@1.99.0
      - name: tests/toolchain_pin_test.sh
        run: bash tests/toolchain_pin_test.sh
      - name: cargo clippy
        run: cargo clippy --all-targets --locked -- -D warnings
CI
        [ "$nocargo" = --no-cargo ] && sed -i '/clippy/d' "$d/.github/workflows/ci.yml"
        local extra; extra=$(cat)
        if [ "$extra" = - ]; then rm -f "$d/.github/workflows/ci.yml"
        elif [ -n "$extra" ]; then printf '%s\n' "$extra" >"$d/.github/workflows/driad.yml"; fi
        out=$(cd "$d" && bash "tests/$base" 2>&1); rc=$?
        legs=$((legs + 1))
        if [ "$rc" = "$want" ] && [[ $out == *"$text"* ]]; then return 0; fi
        fails=$((fails + 1))
        printf 'FAIL: --self-test leg %s: want rc=%s containing %s\n      got rc=%s: %s\n' \
            "$name" "$want" "$text" "$rc" "$(printf '%s' "$out" | tr '\n' ' ')"
    }

    # Anti-vacuity: the unmutated fixture must PASS, or every red below is the
    # fixture failing rather than the mutation landing.
    leg control 0 PASS <<'WF'
      - run: cargo test --locked
WF
    # The ci.yml-only glob. Pre-fix this leg PASSED.
    leg glob 1 'driad.yml:1 cargo call lacks --locked' <<'WF'
      - run: cargo test --lib
WF
    # The line-start anchor, in both idioms it used to miss. Pre-fix: PASS.
    leg unanchored-env 1 'driad.yml:1 cargo call lacks --locked' <<'WF'
      - run: RUSTFLAGS=-D warnings cargo build
WF
    leg unanchored-andand 1 'driad.yml:2 cargo call lacks --locked' <<'WF'
      - run: |
          cd fuzz && cargo test
WF
    # Every separator in the pattern's class other than whitespace, in one leg.
    # Without it the class is decorative: narrowing it to `[[:space:]]` alone
    # left all the other legs green, because each of them happens to put a
    # space before `cargo`.
    leg unanchored-nospace 1 'driad.yml:5 cargo call lacks --locked' <<'WF'
      - run: |
          cd fuzz&&cargo test
          (cargo build)
          RUSTFLAGS=-D warnings;cargo check
          true|cargo doc
WF
    # No false positive on a commented-out call, nor on a step TITLE -- a
    # `- name: cargo test (lib)` line carries no `--locked` and is not a call.
    leg comment 0 PASS <<'WF'
      # cargo build
      - name: cargo test (lib)
        run: cargo test --locked
WF
    # Fails closed: a file that says cargo but yields no call means the pattern
    # broke, not that there is nothing to check.
    leg pattern-broke 1 'driad.yml says cargo but the cargo-call pattern matched nothing' <<'WF'
      - run: cargo frobnicate
WF
    # Workflows exist but none of them calls cargo at all. The per-file guard
    # cannot see this -- it needs a file that still says `cargo` -- so the
    # global count is the only thing standing between a vanished check 4 and a
    # green run.
    leg no-cargo-anywhere 1 'matched no cargo calls in .github/workflows/*.yml' --no-cargo </dev/null
    # An empty workflow glob is a failure, not a silent pass. Caught by the pin
    # scan and the placement parser, not by a count check of its own -- see the
    # note where that check would have gone.
    leg no-workflows 1 'FAIL: matched no dtolnay/rust-toolchain pins' <<<-
    if [ "$fails" -eq 0 ]; then echo "PASS: ${legs} self-test legs"; exit 0; fi
    echo "FAIL: ${fails} of ${legs} self-test leg(s) diverged"; exit 1
fi

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

files=0
calls=0
for wf in .github/workflows/*.yml; do
  [ -e "$wf" ] || continue
  files=$((files + 1))
  # Line-numbered shell view: `#` comments and `name:` keys blanked, so a step
  # title never reads as an invocation. The ": " after the number is load-bearing
  # -- it supplies the leading separator a column-0 `cargo` would otherwise lack.
  shell=$(awk '{ l = $0; sub(/#.*/, "", l)
                 if (l ~ /^[[:space:]]*(-[[:space:]]+)?name:/) l = ""
                 printf "%s: %s\n", NR, l }' "$wf")
  found=0
  while IFS= read -r hit; do
    found=$((found + 1))
    calls=$((calls + 1))
    case "$hit" in
      *--locked*) ;;
      *) echo "FAIL: ${wf}:${hit%%:*} cargo call lacks --locked"; fail=1 ;;
    esac
  done < <(printf '%s\n' "$shell" | grep -E '(^|[[:space:]=;&|(])cargo[[:space:]]+(build|check|clippy|test|run|doc|fetch|install)([[:space:]]|$)')
  if [ "$found" -eq 0 ] && printf '%s\n' "$shell" | grep -q '[[:space:]]cargo[[:space:]]'; then
    echo "FAIL: $wf says cargo but the cargo-call pattern matched nothing in it"
    fail=1
  fi
done
# No `[ "$files" -gt 0 ]` here. An empty glob is already caught twice over --
# the pin scan above it and the placement parser below both fail on it (leg
# `no-workflows` asserts that) -- and a third check for it had no failing
# mutation: reverting it alone left every leg green. Adding one would be the
# subset-reads-as-coverage mistake this block exists to answer.
[ "$calls" -gt 0 ] || { echo "FAIL: matched no cargo calls in .github/workflows/*.yml"; fail=1; }

# job|gate|gate-names-a-leg-of-that-job, one line per step running this script.
placements=$(awk '
  function flush() {
    if (blk ~ /bash tests\/toolchain_pin_test\.sh/) {
      ok = "yes"
      if (gate != "") { ok = "no"; if (match(gate, /'"'"'[^'"'"']*'"'"'/) && index(ids[job] " ", " " substr(gate, RSTART + 1, RLENGTH - 2) " ")) ok = "yes" }
      print job "|" gate "|" ok
    }
    blk = ""; gate = ""
  }
  /^[^[:space:]#]/ { flush(); injobs = ($0 ~ /^jobs:/); job = ""; next }
  !injobs { next }
  /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { flush(); job = $1; sub(/:$/, "", job); next }
  /^      - / { flush() }
  /^          - id:/ { ids[job] = ids[job] " " $3 }
  /^        if:/ { gate = $0; sub(/^[[:space:]]*if:[[:space:]]*/, "", gate) }
  { blk = blk "\n" $0 }
  END { flush() }
' .github/workflows/ci.yml)
case "$placements" in
  *$'\n'*) echo "FAIL: tests/toolchain_pin_test.sh runs from more than one ci.yml step (job|if|gate-ok): $(echo "$placements" | tr '\n' ' ')"; fail=1 ;;
  lint\|*\|yes) ;;
  "") echo "FAIL: no ci.yml job runs tests/toolchain_pin_test.sh; run it from the required lint job"; fail=1 ;;
  *) echo "FAIL: tests/toolchain_pin_test.sh must run once, from ci.yml's lint job (required check), gated to a leg lint's matrix has; found (job|if|gate-ok): $(echo "$placements" | tr '\n' ' ')"; fail=1 ;;
esac

echo "checked ${pins} toolchain pins and ${froms} Dockerfile FROM rust: pins against channel ${channel}, ${calls} cargo calls across ${files} workflow files, placement ${placements//$'\n'/; }"
[ "$fail" -eq 0 ] && echo PASS
exit "$fail"
