#!/usr/bin/env bash
# Guards every .github/workflows/*.yml against the parse failure that killed the
# public-vantage probe for ~2h on 2026-10-01 (BLO-38732):
#
#   HTTP 422: failed to parse workflow: (Line: 288, Col: 14):
#             Exceeded max expression length 21000
#
# WHY A STATIC GUARD. The failure is invisible by construction. A workflow that
# cannot parse still produces a run -- `completed/failure`, ZERO jobs,
# created_at == updated_at -- and GitHub renders its name as the raw file path
# because it never read `name:`. On a forwarding detector that signals by FILING
# an issue, that reads as "ran, nothing wrong": silence and health are the same
# observation. Nothing else here distinguishes them.
#
# THE LIMIT IS 21,000 CHARACTERS OF *YAML SCALAR*, and it applies only to a
# `run:` block that contains `${{ }}` -- such a block is compiled to a
# `format('...', expr)` expression, and that expression is what is measured.
# A block with no interpolation is a plain literal, is never parsed as an
# expression, and is not bounded by this at all.
#
#   scalar   ${{ }}   dispatch
#   ------   ------   --------
#   19,709   1        204   43a6ba2d -- scheduled + dispatched fine
#   30,584   1        422   714213867 / 8a5426bf7 -- 0-job runs
#   30,569   0        204   8238f07d -- SAME BYTES, expression removed
#
# MEASURE THE SCALAR, NOT THE FILE TEXT. BLO-38732 recorded 23,168 / 36,213 and
# concluded the 21,000 limit was "falsified by its own control", because 23,168
# already exceeds it and parsed. Those are the INDENTED block as it appears in
# the file; the 10-space step indent over ~346 lines inflates it by ~3.4k, which
# is exactly enough to carry a 19,709 scalar across the line. On the quantity
# GitHub actually parses there is no anomaly: 19,709 < 21,000 < 30,584.
#
# AND MEASURE THE COMPILED EXPRESSION, NOT THE SCALAR. What GitHub bounds is
# `format('<literals>', <exprs>)`, in which every `'` `{` `}` in the literal text
# is doubled. That inflation is a function of quote/brace DENSITY, not a
# constant: measured here it is +0.48% on the probe block but +1.50% on ci.yml's
# `cargo test` block, and a shell block full of `awk '{print $1}'` / `jq -r
# '{a:.b}'` runs ~20%. At 20% a 20,000-char scalar compiles to ~24,100 -- GitHub
# refuses and a scalar-length guard reports PASS, which is exactly the silent
# failure this guard exists to prevent. So the model below is applied and the
# budget sits near the real ceiling instead of padding against an unknown.
set -uo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

# --self-test (BLO-38880). Every guard below lives on a path no real workflow in
# this repo takes, so CI's one invocation stays green with all of them deleted:
# the next edit to this file had no failing mutation to catch it, which is the
# condition the guards themselves exist to prevent, one level up. Each leg builds
# a fixture repo under a temp dir, copies THIS script into its `tests/` so
# REPO_ROOT resolves there by the same BASH_SOURCE path a real run uses, and
# asserts rc plus a substring of the expected verdict.
#
# Two traps this harness is shaped against, both paid for on #65:
#
#   * A LEG MUST BE PROVED TO HAVE RUN. Asserting that something did NOT happen
#     passes just as well when the subject never ran. Every FAIL leg here asserts
#     text only the guard reading that fixture can emit, and the rc=0 legs assert
#     `scanned 1`, which no empty run produces. Two legs cannot self-witness that
#     way and carry explicit controls: `glob-none`, whose message comes from
#     finding nothing, is controlled by `happy` -- same harness, file present,
#     scanned 1; and `job-suppresses-scan`, the one genuine negative expectation,
#     by `job-suppresses-scan-control` -- identical file minus the malformed job,
#     which then DOES report the over-budget step the other leg claims is
#     suppressed. Without that pair, a fixture that scanned nothing at all would
#     satisfy the suppression leg for the wrong reason.
#   * AN EMPTY-FILE FIXTURE MUST ACTUALLY BE EMPTY. #65's leg-runner wrote the
#     file only `if [ -n "$2" ]`, so the empty leg silently wrote nothing and
#     re-ran the control, reporting rc=0 as a pass. `cat >` here is
#     unconditional -- empty stdin yields a 0-byte file, it cannot skip -- and
#     the leg asserts that byte count rather than trusting the construction.
if [ "${1:-}" = --self-test ]; then
    # DEPENDENCY GATE (BLO-39023). 19 of the 22 legs below run this script as a
    # child against a fixture repo, so on an interpreter without PyYAML every one
    # of them dies in the bootstrap guard at the bottom of this file and the leg
    # dumps that guard's 33-line verdict: 666 lines, 19 reported divergences, one
    # missing import. Probe once, here, and say it once.
    #
    # Three options were weighed; this is the third.
    #   * Hoist the whole bootstrap guard above this dispatch. Rejected: that
    #     guard runs `python3 -m pip install pyyaml`, so --self-test would MUTATE
    #     the host interpreter. That is exactly what silently healed this rig
    #     mid-investigation on BLO-38880 and left a stale "PyYAML is not
    #     importable here" note reading as current. A test mode must not repair
    #     the condition it reports on.
    #   * Probe and warn without exiting. Rejected: keeps all 22 legs, but still
    #     emits the 666 lines this exists to suppress -- it fails the one
    #     requirement while costing nothing else.
    #   * Probe read-only and exit, below.
    #
    # THE COST, STATED: this gives up the only three legs that do NOT need PyYAML
    # and are therefore the only three that still ran on such a host --
    # `bootstrap`, which fakes the failure with a PATH stub rather than the real
    # interpreter; `usage`, which returns at the argv branch above the guard; and
    # `dependency-gate`, which covers this block and runs under that same stub.
    # Accepted: a 3-of-22 run is not a verdict worth acting on, and all three run
    # in CI, where PyYAML is present (BLO-38861).
    #
    # The headline names the PROBE, not PyYAML: an absent python3 lands in this
    # same branch, with `command not found` under `import said:` and a venv
    # remedy that cannot run either. One probe and one headline true of both --
    # a second branch for the absent-interpreter case would be another guard
    # with no failing mutation, which is the defect this block is answering.
    if ! dep_said=$(python3 -c 'import yaml' 2>&1); then
        cat >&2 <<'SELFTEST_DEP'
FAIL: --self-test -- `python3 -c 'import yaml'` failed here: no PyYAML, or no
      python3 at all. `import said:` below carries the real cause. 19 of the 22
      legs run this script as a child, so they would all fail in the bootstrap
      guard and report a single missing import as 19 diverged legs.
      NO LEG WAS RUN. This is a dependency failure, not a self-test verdict.
      Fix: run the self-test from a venv (installing python3 first if that is
      what is missing) --
        v=$(mktemp -d) && python3 -m venv "$v" && "$v"/bin/pip -q install pyyaml
        PATH="$v/bin:$PATH" bash tests/workflow_expression_budget_test.sh --self-test
SELFTEST_DEP
        { echo "      import said:"; sed 's/^/        /' <<<"$dep_said"; } >&2
        # rc=3, not 1: 1 is `$fails of $legs leg(s) diverged` below, and sharing
        # it makes the one distinction this block exists to draw invisible to
        # anything reading the status code. Not 2 (that is bad argv), and not
        # the conventional 77 -- a harness reading 77 as skip-and-pass would
        # turn a dependency failure green, which is this file's whole subject.
        exit 3
    fi
    tmp=$(mktemp -d) || exit 1
    trap 'rm -rf "$tmp"' EXIT
    me=${BASH_SOURCE[0]}; base=$(basename "$me")
    # Pin the budget for children: an exported override in the ambient env would
    # otherwise move the over-budget legs' verdict out from under them.
    export WORKFLOW_EXPRESSION_BUDGET=20500
    legs=0 fails=0

    # leg <name> <want-rc> <want-text> [reject-text] [--no-workflows] [path-dir]
    #     [ext]
    # The workflow yaml is read from stdin unless --no-workflows is passed, and
    # is written as `wf.<ext>` -- `yml` unless a leg asks otherwise, which is
    # what gives the discovery glob's `*.yaml` arm a failing mutation.
    leg() {
        local name=$1 want=$2 text=$3 reject=${4:-} nowf=${5:-} pre=${6:-} \
              ext=${7:-yml} d=$tmp/$1 out rc
        mkdir -p "$d/tests"; cp "$me" "$d/tests/$base"
        if [ "$nowf" != --no-workflows ]; then
            mkdir -p "$d/.github/workflows"; cat >"$d/.github/workflows/wf.$ext"
        fi
        legs=$((legs + 1))
        out=$(PATH="${pre:+$pre:}$PATH" bash "$d/tests/$base" 2>&1); rc=$?
        if [ "$rc" != "$want" ] || ! grep -qF -- "$text" <<<"$out" \
           || { [ -n "$reject" ] && grep -qF -- "$reject" <<<"$out"; }; then
            fails=$((fails + 1))
            printf 'SELF-TEST FAIL [%s]: want rc=%s containing %q%s\n' \
                "$name" "$want" "$text" \
                "${reject:+ and NOT containing $(printf %q "$reject")}"
            printf '  got rc=%s:\n' "$rc"; sed 's/^/    /' <<<"$out"
        fi
    }

    # A `run:` block that compiles past the budget, and the one-job workflow
    # that carries it. Built here so all three legs that need an over-budget
    # `big` job -- `over-budget`, `job-suppresses-scan` and its control -- share
    # one definition rather than three heredocs maintained in parallel.
    over=$(head -c 25000 /dev/zero | tr '\0' x)
    scan_body="jobs:
  big:
    steps:
      - run: |
          $over \${{ github.sha }}"

    leg glob-none 1 'no workflows matched' '' --no-workflows
    leg happy 0 'scanned 1 workflow(s)' <<<'jobs: {b: {steps: [{run: echo hi}]}}'

    leg empty-file    1 'does not load as a YAML mapping' </dev/null
    leg bare-scalar   1 'does not load as a YAML mapping' <<<'just a string'
    leg no-jobs-key   1 'carries no `jobs:` mapping' <<<'name: stub'
    leg jobs-empty    1 'carries no `jobs:` mapping' <<<'jobs: {}'
    leg jobs-list     1 'carries no `jobs:` mapping' <<<'jobs: [a, b]'
    leg jobs-null     1 'carries no `jobs:` mapping' <<<'jobs:'
    leg job-null      1 'job `build` is not a mapping' <<<'jobs: {build: }'
    leg job-str       1 'job `build` is not a mapping' <<<'jobs: {build: oops}'
    leg job-list      1 'job `build` is not a mapping' <<<'jobs: {build: [a]}'

    # The three guards 5fcdc46 added to the same pre-pass, which landed with no
    # leg of their own -- the gap this whole mode exists to close, reappearing
    # one commit later. A non-list `steps:` failed the OPPOSITE way to the rest
    # of this block: truthy, so `or []` kept it, `enumerate` walked its keys and
    # every one was skipped -- zero steps scanned, rc=0. And a null job key
    # (`~:`) collided with the old `next(..., None)` sentinel, skipping the
    # pre-pass and reaching `.get()` as a traceback.
    #
    # The two non-list legs straddle truthiness ON PURPOSE, and swapping either
    # side back costs a mutation: `steps-map`'s `{}` is falsy, `steps-scalar`'s
    # `x` is truthy. That is what witnesses the `is not None` comment below --
    # with both truthy (`{run: echo hi}` here, as this leg first shipped),
    # rewriting the guard to `if steps and not isinstance(...)` left this mode
    # green at 21/21 while silently passing `steps: {}`, `''` and `0`.
    leg steps-map    1 'has a `steps:` that is not a list' <<<'jobs: {b: {steps: {}}}'
    leg steps-scalar 1 'has a `steps:` that is not a list' <<<'jobs: {b: {steps: x}}'
    leg job-key-null 1 'job `None` is not a mapping' <<<'jobs: {~: oops}'

    # Deliberate rc=0 cases: the regress stops short of `steps`, so a reusable-
    # workflow caller and an explicitly empty `steps:` must stay passing. If
    # either of these goes red, the guard has started rejecting valid workflows.
    # `steps-empty` carries the `.yaml` extension as well: discovery globs both
    # `*.yml` and `*.yaml`, and with every fixture a `.yml` the `*.yaml` arm had
    # no failing mutation -- deleting it left this self-test green, and the file
    # it would then skip is skipped in exactly the silence this guard exists to
    # break. `scanned 1 workflow(s)` is the witness that the file was found.
    leg reusable-caller 0 'scanned 1 workflow(s)' \
        <<<'jobs: {call: {uses: ./.github/workflows/ci.yml}}'
    leg steps-empty 0 'scanned 1 workflow(s)' '' '' '' yaml \
        <<<'jobs: {b: {steps: []}}'

    leg over-budget 1 'job `big` step' <<<"$scan_body"

    # The negative expectation and its control. Same file; the malformed job is
    # the only difference. Suppression must swallow an over-budget step that the
    # control proves is otherwise reported -- without the control, a fixture that
    # never scanned anything would pass this leg for the wrong reason.
    #
    # `$scan_body` is shared rather than re-typed so that "same file minus the
    # malformed job" is structural instead of a thing two heredocs happen to
    # agree on. Maintained separately, an edit to one `big:` job would leave the
    # control silently no longer controlling anything -- green, which is the
    # failure this whole mode exists to make impossible.
    leg job-suppresses-scan 1 'job `bad` is not a mapping' 'job `big` step' \
        <<<"$scan_body
  bad: oops"
    leg job-suppresses-scan-control 1 'job `big` step' <<<"$scan_body"

    # The bootstrap guard (BLO-38826) is the one leg whose fixture is an
    # interpreter rather than a workflow: shadow python3 with a stub that cannot
    # import yaml and whose `-m pip install` refuses, which is what a PEP
    # 668-managed interpreter does. The workflow present here is deliberately
    # VALID -- a bootstrap failure has to win before any file is read.
    #
    # ASSERT A MARKER ONLY THE STUB CAN EMIT, not pip's own text. On a PEP
    # 668-managed host that lacks PyYAML the REAL `python3 -m pip install pyyaml`
    # prints `error: externally-managed-environment` byte-identically, so a leg
    # asserting that string passes with the stub contributing nothing -- the
    # fixture is not proved to have run, which is this harness's first trap in
    # the one place it was still unguarded. The guard echoes pip's stderr back
    # verbatim under `pip said:`, so a sentinel in it is carried through.
    # $stub goes FIRST on PATH wherever it is used, so it shadows every command
    # the child resolves, not just python3. It ALSO shadows the `timeout` in the
    # `PATH=... timeout 60 bash ...` line below -- but by a different route,
    # worth keeping straight because the two have different blast radii. That
    # line is a command-prefix assignment, so the PARENT resolves `timeout` at
    # exec time; the child never looks it up. The hazard survives the
    # correction: measured under bash 5.2.37, the parent performs that lookup
    # through the ASSIGNED PATH rather than its own, so a `$stub/timeout` would
    # capture the bound itself, not merely be shadowed inside the child.
    # Harmless while python3 is the only file here; if you add a second stub,
    # check nothing downstream resolves that name through this directory.
    stub=$tmp/stub; mkdir -p "$stub"
    cat >"$stub/python3" <<'STUB'
#!/bin/sh
case "$*" in *pip*)
  echo "error: externally-managed-environment [self-test stub]" >&2; exit 1;;
esac
echo "ModuleNotFoundError: No module named 'yaml' [self-test stub]" >&2; exit 1
STUB
    chmod +x "$stub/python3"
    leg bootstrap 1 'externally-managed-environment [self-test stub]' '' '' \
        "$stub" <<<'jobs: {b: {steps: [{run: echo hi}]}}'

    # The dependency gate at the top of this branch, which `leg` cannot reach for
    # the same reason as `usage` below: it needs `--self-test` in the child's
    # argv. In CI PyYAML is present, so the gate's condition is always false and
    # deleting the whole block leaves this self-test green. That gate and the
    # `timeout 60` bound below are the complete list of guards that CANNOT be
    # covered from inside this suite -- both bound a path CI never takes, so no
    # leg can reach either. Keep THAT inventory current: a third uncoverable
    # guard added without being named here is the stale-control shape the rest
    # of the file is built against. (Measured at this head: deleting
    # `timeout 60` leaves `22 legs passed`, rc=0.)
    #
    # Scope matters, because "no failing mutation" alone is a WIDER predicate
    # and this is not the only place it holds: the three `isinstance` checks at
    # the foot of the scanner are green under mutation too (see the block above
    # `unusable = []`). They are a different category -- uncovered but
    # COVERABLE. Measured here: a leg feeding `jobs: {b: {steps: [1]}}` is rc=0
    # today and rc=1 with `isinstance(step, dict)` neutered (AttributeError:
    # 'int' object has no attribute 'get'), so a leg would close it. The two
    # named above admit no such leg at any effort. Do not merge the two lists.
    #
    # Run a child self-test under the import-refusing stub. Assert
    # `NO LEG WAS RUN`, which only the gate emits, and the stub's
    # sentinel, which proves the stub is the interpreter it probed: a real
    # PyYAML-less host prints the bare ModuleNotFoundError identically.
    # The child is marked NESTED and skips this leg: with the gate deleted it
    # would otherwise run its own copy of this leg, and so on without end. With
    # the mark it runs the other legs under the stub, they diverge, and this
    # leg fails on the missing `NO LEG WAS RUN` instead of hanging.
    #
    # rc=3 is the gate's own code, distinct from the `leg(s) diverged` 1 below,
    # so this leg also carries the failing mutation for that distinction:
    # reverting the gate to `exit 1` reds here.
    #
    # The mark is read from the ambient environment, so an inherited
    # EXPRESSION_BUDGET_SELFTEST_NESTED=1 silently drops this leg (`21 legs
    # passed`, rc=0). Left as-is deliberately (BLO-39230 item 2): it is not a
    # false green -- the leg count visibly changes -- and the only fix that
    # actually closes it is moving the mark out of the environment into argv,
    # where an outer shell cannot reach it. That means touching the argv
    # parsing shared by all 22 legs and by the byte-identical-default
    # constraint standing since BLO-38820, which is a poor trade against a
    # cosmetic read. Revisit only if the mark ever gates something whose
    # absence is NOT visible in the count.
    if [ -z "${EXPRESSION_BUDGET_SELFTEST_NESTED:-}" ]; then
        legs=$((legs + 1))
        # Bound the child. The NESTED mark above is the recursion guard and it
        # is correct, but its FAILURE mode is an unbounded fork chain, not a
        # red: delete the gate AND force the mark true and every level spawns
        # another, each holding a `mktemp -d` (measured on this rig: 99 live
        # processes at 91s, no output). That is worth a bound rather than
        # tolerating, because CI makes the degenerate case LESS visible than a
        # plain red -- under `timeout-minutes` a hung job surfaces as
        # `cancelled`, and `failure()` does not see `cancelled` (BLO-38880).
        # rc=124 lands in the `!= 3` arm below and reds as [dependency-gate].
        #
        # 60s is deliberate order-of-magnitude headroom against an unknown-slow
        # rig, NOT a fit to a measurement. Be precise about WHAT it bounds: the
        # child below runs with $stub first on PATH, so its own `import yaml`
        # probe fails, it trips the dependency gate above and `exit 3`s -- it
        # never reaches the `mktemp -d` that starts a leg. Measured at this head
        # on the CephFS-backed tree this runs from, 5 runs: 30/34/34/32/36ms,
        # rc=3. So on the green path the bound is ~1800x the work and can never
        # bind. (An earlier version of this comment cited the OUTER 22-leg run,
        # ~3.4s, and argued headroom from "forks an interpreter over a network
        # filesystem". Both describe a workload this leg does not run -- the
        # number was right, its stated basis was not. Caught in review on #72.)
        #
        # The bound exists only for the degenerate case, where it is the gate
        # being disabled that lets the child run legs at all. There is no
        # measured upper bound on that path -- it is the unbounded chain -- so
        # 60s is chosen to be far above any plausible green run rather than
        # fitted to one. Do not shrink it toward the 30ms above: that figure is
        # the floor of what this leg costs, not a budget to trim against.
        #
        # KNOWN RESIDUAL, measured, not an oversight: this bounds the VERDICT,
        # not the process tree. Under the double mutation the top-level call
        # returns rc=124 at 60s and reds here, but the orphaned subtree keeps
        # going -- each nested `timeout` setpgid()s into its OWN process group,
        # so the parent's SIGTERM cannot reach it, and every new level gets a
        # fresh 60s. Measured: 116 processes and 90 temp dirs still climbing
        # 20s AFTER the leg reported. Depth stays ~10; it leaks in time, not
        # depth. Closing that needs a bound that does not live in the mark the
        # mutation removes (a depth counter), i.e. another guard with its own
        # coverage question -- deliberately out of scope here. If you run the
        # BLO-39230 checklist by hand, reap afterwards:
        #     pkill -9 -f 'workflow_expression_budget_test[.]sh'
        #
        # PORTABILITY: `timeout` is this file's only GNU-coreutils dependency
        # (python3/mktemp/grep/sed/awk are all POSIX here, so there is no
        # precedent to inherit). Stock macOS ships it as `gtimeout` only, where
        # this leg reds as [dependency-gate] rc=127. Left as a note, not a
        # `command -v` preflight: bash's `command not found` goes to fd 2 and
        # `2>&1` captures it into $out, so the failure already names its own
        # cause, and CI is Linux. A preflight would be a THIRD guard that no
        # leg can cover -- precisely what the register above warns against.
        out=$(EXPRESSION_BUDGET_SELFTEST_NESTED=1 PATH="$stub:$PATH" \
              timeout 60 bash "$tmp/happy/tests/$base" --self-test 2>&1); rc=$?
        if [ "$rc" != 3 ] || ! grep -qF -- 'NO LEG WAS RUN' <<<"$out" \
           || ! grep -qF -- "No module named 'yaml' [self-test stub]" <<<"$out"; then
            fails=$((fails + 1))
            printf 'SELF-TEST FAIL [dependency-gate]: want rc=3 containing "NO LEG WAS RUN" and the stub sentinel\n'
            printf '  got rc=%s%s:\n' "$rc" \
                "$([ "$rc" = 124 ] && printf ' (124 = the 60s bound above tripped; the child did not finish)')"
            sed 's/^/    /' <<<"$out"
        fi
    fi

    wf=$tmp/empty-file/.github/workflows/wf.yml
    if [ ! -f "$wf" ] || [ -s "$wf" ]; then
        fails=$((fails + 1))
        echo "SELF-TEST FAIL [empty-file]: fixture is not a 0-byte file -- the" \
             "leg re-ran the control and its rc=1 means nothing."
    fi

    # Same shape, for the other fixture whose construction carries a claim the
    # assertion cannot see. `steps-empty`'s `yaml` rides in the 7th positional
    # slot behind three placeholders; mis-slot it and `ext` falls back to `yml`,
    # the leg still passes on `scanned 1`, and the `*.yaml` glob arm silently
    # loses its only failing mutation.
    if [ ! -f "$tmp/steps-empty/.github/workflows/wf.yaml" ]; then
        fails=$((fails + 1))
        echo "SELF-TEST FAIL [steps-empty]: fixture is not wf.yaml -- the \`ext\`" \
             "slot was mis-passed and the \`*.yaml\` glob arm is now uncovered."
    fi

    # The usage branch below, which `leg` cannot reach because it passes the
    # child no argv. Uncovered it is the same shape as everything else here:
    # replacing it with `elif false` leaves this self-test green while an
    # unknown argument falls through and runs the full scan as if it had been
    # invoked bare. Reuses the `happy` fixture -- a valid repo, so rc=2 can only
    # come from the argument.
    legs=$((legs + 1))
    out=$(bash "$tmp/happy/tests/$base" --bogus 2>&1); rc=$?
    if [ "$rc" != 2 ] || ! grep -qF -- 'usage:' <<<"$out"; then
        fails=$((fails + 1))
        printf 'SELF-TEST FAIL [usage]: want rc=2 containing "usage:"\n'
        printf '  got rc=%s:\n' "$rc"; sed 's/^/    /' <<<"$out"
    fi

    if [ "$fails" != 0 ]; then
        echo "self-test: $fails of $legs leg(s) diverged"; exit 1
    fi
    echo "self-test: $legs legs passed"
    exit 0
elif [ $# -gt 0 ]; then
    echo "usage: $(basename "$0") [--self-test]" >&2
    exit 2
fi

# The real ceiling is 21,000, measured against the compiled expression. The only
# remaining slack is this model's fidelity to GitHub's compiler, so ~2.4% is
# enough -- a step crossing the line fails here, where the message names the
# step, rather than at dispatch, where it takes the whole workflow down silently.
BUDGET=${WORKFLOW_EXPRESSION_BUDGET:-20500}

# PyYAML is this guard's only dependency, and a bootstrap that cannot supply it
# has to fail in its own voice. Unguarded, `pip install` is refused on a PEP
# 668-managed interpreter (`error: externally-managed-environment`), there is no
# `set -e` above, so the script carries on and the heredoc dies on `import yaml`:
# rc=1 whose terminal output is a bare `ModuleNotFoundError` traceback. rc=1 is
# the safe direction, but it is the same silence-reads-as-health shape as the
# rest of this guard one level out -- nothing was scanned, and the only thing
# telling that apart from a real budget FAIL is reading the text. Re-probe after
# the install and name the bootstrap; `python3 -m pip` so the installer and the
# probe are provably the same interpreter (BLO-38826).
#
# Our voice and pip's are not in tension: PEP 668 is only the common cause, not
# the only one (absent pip, no network, a half-written wheel whose real error is
# an `ImportError`, not a `ModuleNotFoundError`). Discarding both diagnostics
# and then naming PEP 668 as fact is confidently wrong in every other case with
# nothing left to correct it, so capture them and print them under the framing.
if ! python3 -c 'import yaml' 2>/dev/null; then
    pip_said=$(python3 -m pip install pyyaml 2>&1)
    if ! import_said=$(python3 -c 'import yaml' 2>&1); then
        cat >&2 <<'BOOTSTRAP'
FAIL: bootstrap -- PyYAML is not importable and `python3 -m pip install pyyaml`
      did not supply it (most often PEP 668: `externally-managed-environment`).
      NO WORKFLOW WAS SCANNED. This is a bootstrap failure, not a budget verdict.
      Fix: install it from the system packager (`apt-get install python3-yaml`),
      or run this guard from a venv --
        v=$(mktemp -d) && python3 -m venv "$v" && "$v"/bin/pip -q install pyyaml
        PATH="$v/bin:$PATH" bash tests/workflow_expression_budget_test.sh
BOOTSTRAP
        { echo "      pip said:";    sed 's/^/        /' <<<"$pip_said"
          echo "      import said:"; sed 's/^/        /' <<<"$import_said"; } >&2
        exit 1
    fi
fi

python3 - "$REPO_ROOT" "$BUDGET" <<'PY'
import glob, os, re, sys, yaml

root, budget = sys.argv[1], int(sys.argv[2])
EXPR = re.compile(r'\$\{\{(.*?)\}\}', re.S)
bad = largest = 0
worst = None


def compiled_len(text):
    """Chars GitHub measures: the `format('<lits>', <exprs>)` the scalar becomes.

    Literal text is escaped `'`->`''`, `{`->`{{`, `}`->`}}`, so the inflation
    tracks quote/brace density and is not a constant. Returns 0 when there is no
    interpolation -- such a scalar is a plain literal and is never compiled to an
    expression, so this limit does not apply to it at all.

    `len(e)` counts the expression WITH its source padding, deliberately. Whether
    GitHub re-serialises `${{ github.sha }}` to `github.sha` or keeps the source
    text is not settleable from outside its compiler, and the two readings differ
    by 2 chars per expression. `len(e)` is correct under the second and
    over-counts under the first; a guard may only ever over-count.
    """
    exprs = EXPR.findall(text)
    if not exprs:
        return 0
    lits = ''.join(EXPR.split(text)[::2])
    return (len("format('")
            + len(lits) + lits.count("'") + lits.count('{') + lits.count('}')
            + sum(len('{%d}' % i) for i in range(len(exprs)))
            + len("'")
            + sum(len(', ') + len(e) for e in exprs)
            + len(')'))


# compiled_len is the load-bearing half of this guard: understate it and the
# budget silently reverts to measuring the raw scalar, which is the exact
# false-PASS the header exists to prevent. Pin the escaping on all three paths
# against hand-built format() strings. Inputs are unpadded so these hold under
# either reading of the whitespace question above.
assert compiled_len("plain text, no interpolation") == 0
assert compiled_len("a${{b}}c") == len("format('a{0}c', b)")
assert compiled_len("x${{y}}z${{w}}") == len("format('x{0}z{1}', y, w)")
assert compiled_len("it's {a}${{s}}") == len("format('it''s {{a}}{0}', s)")


def scalars(step):
    """Every step field compiled as an expression: `run`, and each `with:` input.

    `with:` is the same expression plane and the same ceiling -- an interpolated
    `actions/github-script` `script:` is the usual way a repo grows a large one.
    """
    if isinstance(step.get('run'), str):
        yield 'run', step['run']
    for key, val in (step.get('with') or {}).items():
        if isinstance(val, str):
            yield f'with.{key}', val


paths = sorted(glob.glob(os.path.join(root, '.github/workflows/*.yml'))
               + glob.glob(os.path.join(root, '.github/workflows/*.yaml')))

# Scanning nothing must not read as passing. `root` comes from this script's own
# location, so a copy invoked from anywhere else globs an empty directory, prints
# `(none)` and would exit 0 -- byte-identical output for a correct workflow, for
# the broken one this guard exists to catch, and for no input at all. That is the
# same silence-reads-as-health shape as the 0-job run in the header, one level up:
# a verifier mutation-testing this guard gets a PASS and concludes it is inert.
if not paths:
    sys.exit(f'FAIL: no workflows matched {root}/.github/workflows/*.y[a]ml. '
             f'This guard resolves its root from its own file location -- run it '
             f'in place as tests/workflow_expression_budget_test.sh, not from a '
             f'copy somewhere else.')

# Same shape one level in. `yaml.safe_load` raising is loud; loading to None (an
# empty file) or to a bare scalar is not -- the file is skipped, no step in it is
# ever measured, and a directory of entirely unusable workflows prints
# `(none)` and exits 0, byte-identical to a clean scan. Collected and failed on
# rather than merely counted: a guard that scanned nothing usable has not
# attested anything, and GitHub will not run such a file either.
#
# That `safe_load` stays unguarded on purpose, and it is the one exemption from
# the crash-not-verdict standard below: a syntax error aborts with a
# `yaml.parser.ParserError` naming the file, line AND column, so the traceback IS
# the verdict -- where the shapes below traceback without saying anything useful.
# Cost accepted, not overlooked: it aborts mid-loop, so one syntax error
# suppresses the `scanned N` summary and every sibling FAIL in the same run.
#
# `jobs:` is the last notch of that family (BLO-38855). A `name:`/`description:`
# stub, a stray `action.yml`, a half-written file -- all load as mappings, carry
# no job, contribute zero steps, and are counted in `scanned N`: PASS over
# something never attested, same signature, one notch narrower. `or not jobs`
# is deliberate and is NOT redundant with the isinstance: an explicit `jobs: {}`
# IS a mapping and still scans zero steps, so it is the same defect. The
# isinstance half is also what keeps `jobs:` as a LIST from reaching `.items()`
# -- unguarded that is an AttributeError traceback, which is rc=1 but a crash,
# not a verdict, and that is the shape BLO-38826 just removed from the bootstrap.
#
# A job VALUE gets the same treatment, one level in: `build:` with no body is
# None, and `build: oops` / `build: [a]` are a str and a list -- each reaches
# `.get('steps')` and tracebacks, the same crash-not-verdict shape. So does a
# `steps:` that is not a list, but it fails the OTHER way: `steps:` written as a
# mapping (a forgotten `-`) or a scalar is truthy, so `or []` keeps it,
# `enumerate` walks its keys, and `isinstance(step, dict)` skips every one --
# zero steps scanned, rc=0, the silent PASS this whole regress exists to remove.
# Both are checked in one pre-pass rather than inside the scan loop so that a
# file with one malformed job contributes NO steps at all; that keeps it a
# file-level verdict like the two above it, and keeps the shared
# `so no step in it was scanned` wording true.
#
# The loop is explicit rather than a `next(...)` generator with a None sentinel:
# a job key can legitimately BE None (`~:` / `null:`), and a sentinel cannot tell
# that apart from "no bad job found" -- which silently skipped the pre-pass and
# let the value fall through to `.get()`, reintroducing the exact traceback this
# block removes. `0:` and `'':` were always fine; only the None key collided.
#
# `steps is not None` is load-bearing and is NOT the same as a truthiness test: a
# job with no `steps:` at all must keep passing, or this guard rejects every
# reusable-workflow caller in the repo (see the stopping point below). `steps: []`
# likewise stays passing -- an explicit empty list is a list.
#
# The regress stops here, with the stopping point written down rather than
# implied: a workflow whose jobs all have empty or absent `steps:` scans nothing
# and still exits 0. That case is left open on purpose, and the reason is a
# concrete valid shape rather than a judgement about what GitHub tolerates -- a
# caller of a reusable workflow,
#
#     jobs:
#       call:
#         uses: ./.github/workflows/ci.yml
#
# has no `steps:` anywhere, is entirely valid, and scans zero steps. One notch
# further in and this guard rejects every such caller in the repo.
#
# Also left open, and narrower still: the three type checks below that skip a
# malformed STEP inside an otherwise-scanned job without saying so --
# `isinstance(step, dict)`, `isinstance(step.get('run'), str)` and
# `isinstance(val, str)`. Unlike the cases above them these are not file-level
# verdicts -- `steps:` is a list and the rest of the job IS attested, so only
# that one element goes unmeasured. That claim is only true because a non-list
# `steps:` is now caught above; while it was not, "the rest of the job" could be
# nothing at all.
#
# Naming the SET rather than one member: all three are green under mutation in
# `--self-test`, so a reader who checks only the one member named here would
# conclude the other two are covered. They are NOT part of the uncoverable-guard
# register in the `--self-test` branch (the dependency gate and its `timeout 60`)
# -- that register is deliberately narrower, and this trio is excluded from it on
# purpose rather than omitted. The difference is coverability, not coverage: a
# leg feeding `jobs: {b: {steps: [1]}}` would red `isinstance(step, dict)`, so
# these are closable whenever someone wants them closed. The register's two
# admit no such leg.
# `job.get('steps') or []` and
# `step.get('with') or {}` look like the same family and are NOT in it --
# dropping either fallback reds (`reusable-caller` by name, and `happy`). Those
# reds are crashes the mutation introduces rather than the pre-mutation
# behaviour, but that is the point of the idiom: the fallback exists to tolerate
# the absent key, so removing it is the defect.
unusable = []

for path in paths:
    rel = os.path.relpath(path, root)
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict):
        unusable.append((rel, 'does not load as a YAML mapping (empty file, or '
                              'a bare scalar)'))
        continue
    jobs = doc.get('jobs')
    if not isinstance(jobs, dict) or not jobs:
        unusable.append((rel, 'loads as a mapping but carries no `jobs:` mapping '
                              '(missing, empty, or not a mapping)'))
        continue
    bad_job = None
    for jname, job in jobs.items():
        if not isinstance(job, dict):
            bad_job = (jname, 'is not a mapping (a typed job key with no body, '
                              'or a scalar/list value)')
            break
        steps = job.get('steps')
        if steps is not None and not isinstance(steps, list):
            bad_job = (jname, 'has a `steps:` that is not a list (a forgotten '
                              '`-`, or a scalar)')
            break
    if bad_job is not None:
        jn, why = bad_job
        unusable.append((rel, f'job `{jn}` {why}'))
        continue
    for jname, job in jobs.items():
        for i, step in enumerate(job.get('steps') or []):
            if not isinstance(step, dict):
                continue
            sname = step.get('name') or step.get('id') or f'step[{i}]'
            for field, text in scalars(step):
                size = compiled_len(text)
                if not size:
                    continue
                n = len(EXPR.findall(text))
                if size > largest:
                    largest, worst = size, f'{rel} {jname} / {sname} ({field})'
                if size > budget:
                    bad += 1
                    print(f'FAIL {rel}: job `{jname}` step `{sname}`: `{field}` '
                          f'is {len(text)} scalar chars and contains {n} '
                          f'${{{{ }}}} expression(s), so GitHub compiles it to a '
                          f'{size}-char format() expression; budget is {budget}, '
                          f'GitHub refuses at 21000.')
                    print('     Fix: move the interpolated value into `env:` and '
                          'read it as a shell variable -- that takes the block out '
                          'of the expression plane entirely and leaves it unbounded. '
                          'Splitting the step also works. Do NOT just trim: over the '
                          'limit the WHOLE WORKFLOW stops parsing, which presents as '
                          'a 0-job `completed/failure` run, not as an error anyone '
                          'reads.')

print(f'scanned {len(paths)} workflow(s); largest interpolated block: {largest} '
      f'compiled chars ({worst or "none"}), budget {budget}, hard limit 21000')

for rel, why in unusable:
    print(f'FAIL {rel}: {why}, so no step in it was scanned. A guard that '
          f'skipped a workflow has not attested it; GitHub will not run it '
          f'either.')

sys.exit(1 if bad or unusable else 0)
PY
