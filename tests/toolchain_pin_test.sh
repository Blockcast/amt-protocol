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
#   4. Every dependency-resolving cargo call in .github/workflows/*.y*ml passes
#      `--locked`, which is what ci.yml's top-level env comment promises. `cargo
#      fmt` and `cargo fuzz` resolve no dependencies at that position and take no
#      `--locked`, so they are not checked. Four things this used to get wrong
#      (BLO-42496), none visible from a green run because a missed call reads
#      exactly like no missed call:
#        - the pattern was anchored at line start, so `RUSTFLAGS=x cargo build`,
#          `cd fuzz && cargo test`, and anything after `&&` inside a `run: |`
#          block escaped it. It now matches `cargo` after any of ` ;&|(` too.
#        - it also required whitespace or end-of-line *after* the verb, the same
#          mistake at the other end: `(cargo build)` ends on `)` and did not
#          count. The tail is now any non-word character, which still rejects
#          `cargo building`.
#        - `cargo +nightly test` escaped the verb list, because the toolchain
#          override sits where the verb was expected. driad-parser.yml's fuzz
#          job is this repo's toolchain-override job, so that is where it lands.
#        - the scan read ci.yml alone while the pin scan above globbed
#          `*.yml`, which is how driad-parser.yml carried three unlocked
#          `cargo test` calls. Both now glob `*.y*ml`.
#        - `--locked` was tested against the whole LINE, and grep yields one hit
#          per line however many calls it holds, so `cargo build --locked &&
#          cargo test` passed on the first call's flag and reported the same
#          count a clean tree does. Each line is now split on ` ; & | ` and
#          each segment scanned on its own. A `;&|` inside a quoted argument
#          splits too, which can red a locked call -- loud, and the message
#          names the line.
#        - a backslash-continued call was scanned a line at a time, so the
#          `--locked` on the next line did not count. Continuations are joined
#          first and reported under the line the call starts on.
#      The separator class is down to whitespace and `(`, because the segment
#      split above already consumed ` ; & | ` -- no segment can still contain
#      one, so keeping them was three elements no leg could exercise. Measured:
#      with the split in, dropping `&`, `;` or `|` individually left every leg
#      green. `=` was dropped earlier for the same reason (no idiom puts it
#      immediately before `cargo` -- in `RUSTFLAGS=x cargo build` the separator
#      is the space). `(` stays and has its own leg: `(cargo build)` is one
#      segment, so the paren is still what precedes the verb.
#      The separator legs are now exercising the split rather than the class,
#      which is the honest description of what each one covers.
#      `#` comments and YAML `name:` keys are blanked first: a step named
#      `- name: cargo test (lib)` is not an invocation and carries no `--locked`.
#      A `#` opens a comment only at line start or after whitespace, which is
#      YAML's own rule. Blanking from *any* `#` deleted `echo '#frag' && cargo
#      build` from the scanned view, and the per-file guard below could not see
#      that because it greps the already-blanked text.
#      The per-file guard is what makes a broken pattern loud -- a file whose
#      blanked body still says `cargo <lowercase-word>` must yield at least one
#      call, so a rename or a bad regex fails instead of reading as "nothing to
#      check". It deliberately does not reuse the verb list, or a broken verb
#      list would silence its own alarm. A file with no cargo at all
#      (publish-amt-verify.yml) is legitimately zero.
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
# Resolved before the cd, or `--self-test` only works when the invocation path
# is still valid from the repo root: `cd tests && bash toolchain_pin_test.sh
# --self-test` otherwise cannot copy itself and reds all 17 legs, which is the
# output that makes a reader doubt the guard rather than the invocation.
me=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")
cd "$(dirname "$me")/.." || exit 2

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
    base=$(basename "$me"); legs=0 fails=0

    # leg <name> <want-rc> <want-text> [--no-cargo] [second-workflow-filename]
    # -- extra workflow yaml is read from stdin and written as the second
    # workflow (driad.yml unless overridden); `-` means write no second
    # workflow at all. `--no-cargo` drops the cargo step from the fixture
    # ci.yml, which is the only way to reach the global "matched nothing
    # anywhere" arm: the per-file guard below it only fires on a file that
    # still says `cargo`.
    leg() {
        local name=$1 want=$2 text=$3 nocargo=${4:-} second=${5:-driad.yml} d=$tmp/$1 out rc
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
        [ "$nocargo" = --no-pin ] && sed -i '/dtolnay/d' "$d/.github/workflows/ci.yml"
        local extra; extra=$(cat)
        if [ "$extra" = - ]; then rm -f "$d/.github/workflows/ci.yml"
        elif [ -n "$extra" ]; then printf '%s\n' "$extra" >"$d/.github/workflows/$second"; fi
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
    # One leg per separator in the pattern's class, each a single line so the
    # asserted line number names the separator under test. These were one leg
    # with four calls asserting one message, which is the shape this whole
    # check exists to argue against: measured at that head, dropping `&`, `(`,
    # `;` or `=` from the class individually left the leg green, because the
    # `|` line it asserted still matched. Only dropping all five at once red.
    leg sep-amp 1 'driad.yml:1 cargo call lacks --locked' <<'WF'
      - run: cd fuzz&&cargo test
WF
    leg sep-paren 1 'driad.yml:1 cargo call lacks --locked' <<'WF'
      - run: (cargo build)
WF
    leg sep-semi 1 'driad.yml:1 cargo call lacks --locked' <<'WF'
      - run: true;cargo check
WF
    leg sep-pipe 1 'driad.yml:1 cargo call lacks --locked' <<'WF'
      - run: true|cargo doc
WF
    # Two cargo calls on one line. `grep` yields one hit per LINE, so the
    # unlocked call hid behind the locked one and the count printed `2` -- the
    # same number a clean tree prints, because the second call never became a
    # hit. Pre-fix: PASS.
    leg multi-call-one-line 1 'driad.yml:1 cargo call lacks --locked' <<'WF'
      - run: cargo build --locked && cargo test
WF
    # A backslash-continued call -- the standard idiom for a long invocation.
    # Its `--locked` is on the next line, so scanning lines independently reds a
    # correct call. Loud rather than silent, but it is a hard failure on valid
    # YAML. Pre-fix: FAIL at :2.
    leg backslash-continued 0 PASS <<'WF'
      - run: |
          cargo test \
            --locked \
            --all-features
WF
    # `cargo +<toolchain> <verb>`: the override sits where the verb was
    # expected. The locked call above it keeps the per-file guard satisfied, so
    # this leg reds on the verb pattern alone and not on the guard. Pre-fix:
    # PASS, reported as 2 calls.
    leg toolchain-override 1 'driad.yml:2 cargo call lacks --locked' <<'WF'
      - run: cargo test --locked
      - run: cargo +nightly test --no-default-features
WF
    # A `#` that does not open a YAML comment. Blanking from any `#` deleted
    # the call with it, and the per-file guard could not see that because it
    # greps the blanked text -- the `cargo` token is gone too. Pre-fix: PASS.
    leg hash-midline 1 'driad.yml:1 cargo call lacks --locked' <<'WF'
      - run: echo '#frag' && cargo build
WF
    # No false positive on a commented-out call, nor on a step TITLE -- a
    # `- name: cargo test (lib)` line carries no `--locked` and is not a call.
    leg comment 0 PASS <<'WF'
      # cargo build
      - name: cargo test (lib)
        run: cargo test --locked
WF
    # Fails closed: a file that says cargo but yields no call means the pattern
    # broke, not that there is nothing to check. Deliberately not keyed on the
    # verb list -- `frobnicate` is not a verb, and a broken verb list must not
    # be able to silence the alarm that would report it.
    leg pattern-broke 1 'driad.yml says cargo but the cargo-call pattern matched nothing' <<'WF'
      - run: cargo frobnicate
WF
    # ...but a lowercase word is required after it, so `cargo --version` in a
    # call-free workflow is not a false alarm. Reverting that reds this leg.
    # Narrower than it looks: `echo cargo is pinned` still trips the guard,
    # because `is` is a lowercase word. Dropping that too needs the verb list,
    # which `pattern-broke` above exists to keep out of this guard.
    leg guard-not-prose 0 PASS <<'WF'
      - run: cargo --version
WF
    # Workflows exist but none of them calls cargo at all. The per-file guard
    # cannot see this -- it needs a file that still says `cargo` -- so the
    # global count is the only thing standing between a vanished check 4 and a
    # green run.
    leg no-cargo-anywhere 1 'matched no cargo calls in .github/workflows/*.y*ml' --no-cargo </dev/null
    # Both globs are `*.y*ml`, so a workflow saved as `.yaml` is scanned rather
    # than silently skipped. Two legs because one cannot cover both: this one
    # reds via the cargo scan, and an rc=1 leg asserting containment stays
    # green when the *pin* glob narrows, because the cargo failure it asserts
    # is still printed. The pin half needs its own leg that expects PASS.
    leg glob-yaml 1 'driad.yaml:1 cargo call lacks --locked' '' driad.yaml <<'WF'
      - run: cargo test --lib
WF
    # ci.yml's pin is dropped, so the .yaml file carries the only one: narrow
    # the pin glob and `pins` falls to 0.
    leg glob-yaml-pin 0 PASS --no-pin driad.yaml <<'WF'
      - uses: dtolnay/rust-toolchain@1.99.0
      - run: cargo test --locked
WF
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
done < <(grep -nE '^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*dtolnay/rust-toolchain@' .github/workflows/*.y*ml)
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
for wf in .github/workflows/*.y*ml; do
  [ -e "$wf" ] || continue
  files=$((files + 1))
  # Line-numbered shell view: `#` comments and `name:` keys blanked, so a step
  # title never reads as an invocation. A `#` opens a YAML comment only at line
  # start or after whitespace -- blanking from any `#` at all would delete the
  # rest of `echo '#frag' && cargo build`. Backslash-continued lines are joined
  # first (reported under the line the call starts on), then each line is split
  # into shell segments and emitted as its own record: `grep` yields one hit per
  # LINE however many calls it holds, so `cargo build --locked && cargo test`
  # used to be one hit that matched `--locked` and passed. The ": " after the
  # number is load-bearing -- it supplies the leading separator a segment-initial
  # `cargo` would otherwise lack.
  shell=$(awk '
    function emit(n, l,   i, k, seg) { k = split(l, seg, /[;&|]+/)
                                       for (i = 1; i <= k; i++) printf "%s: %s\n", n, seg[i] }
    { l = $0; sub(/(^|[[:space:]])#.*/, "", l)
      if (l ~ /^[[:space:]]*(-[[:space:]]+)?name:/) l = ""
      if (join != "") { l = join " " l } else { ln = NR }
      join = ""
      if (l ~ /\\[[:space:]]*$/) { sub(/\\[[:space:]]*$/, "", l); join = l; next }
      emit(ln, l) }
    END { if (join != "") emit(ln, join) }' "$wf")
  found=0
  while IFS= read -r hit; do
    found=$((found + 1))
    calls=$((calls + 1))
    case "$hit" in
      *--locked*) ;;
      *) echo "FAIL: ${wf}:${hit%%:*} cargo call lacks --locked"; fail=1 ;;
    esac
  done < <(printf '%s\n' "$shell" | grep -E '(^|[[:space:](])cargo[[:space:]]+(\+[^[:space:]]+[[:space:]]+)?(build|check|clippy|test|run|doc|fetch|install)([^[:alnum:]_-]|$)')
  if [ "$found" -eq 0 ] && printf '%s\n' "$shell" | grep -q '[[:space:]]cargo[[:space:]][a-z]'; then
    echo "FAIL: $wf says cargo but the cargo-call pattern matched nothing in it"
    fail=1
  fi
done
# No `[ "$files" -gt 0 ]` here. An empty glob is already caught twice over --
# the pin scan above it and the placement parser below both fail on it (leg
# `no-workflows` asserts that) -- and a third check for it had no failing
# mutation: reverting it alone left every leg green. Adding one would be the
# subset-reads-as-coverage mistake this block exists to answer.
[ "$calls" -gt 0 ] || { echo "FAIL: matched no cargo calls in .github/workflows/*.y*ml"; fail=1; }

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
