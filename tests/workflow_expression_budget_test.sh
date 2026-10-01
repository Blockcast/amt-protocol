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
    tmp=$(mktemp -d) || exit 1
    trap 'rm -rf "$tmp"' EXIT
    me=${BASH_SOURCE[0]}; base=$(basename "$me")
    # Pin the budget for children: an exported override in the ambient env would
    # otherwise move the over-budget legs' verdict out from under them.
    export WORKFLOW_EXPRESSION_BUDGET=20500
    legs=0 fails=0

    # leg <name> <want-rc> <want-text> [reject-text] [--no-workflows] [path-dir]
    # The workflow yaml is read from stdin unless --no-workflows is passed.
    leg() {
        local name=$1 want=$2 text=$3 reject=${4:-} nowf=${5:-} pre=${6:-} \
              d=$tmp/$1 out rc
        mkdir -p "$d/tests"; cp "$me" "$d/tests/$base"
        if [ "$nowf" != --no-workflows ]; then
            mkdir -p "$d/.github/workflows"; cat >"$d/.github/workflows/wf.yml"
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

    # A `run:` block that compiles past the budget. Built here so both the
    # over-budget leg and the suppression control share one definition.
    over=$(head -c 25000 /dev/zero | tr '\0' x)

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

    # Deliberate rc=0 cases: the regress stops short of `steps`, so a reusable-
    # workflow caller and an explicitly empty `steps:` must stay passing. If
    # either of these goes red, the guard has started rejecting valid workflows.
    leg reusable-caller 0 'scanned 1 workflow(s)' \
        <<<'jobs: {call: {uses: ./.github/workflows/ci.yml}}'
    leg steps-empty 0 'scanned 1 workflow(s)' <<<'jobs: {b: {steps: []}}'

    leg over-budget 1 'job `big` step' <<YAML
jobs:
  big:
    steps:
      - run: |
          $over \${{ github.sha }}
YAML

    # The negative expectation and its control. Same file; the malformed job is
    # the only difference. Suppression must swallow an over-budget step that the
    # control proves is otherwise reported -- without the control, a fixture that
    # never scanned anything would pass this leg for the wrong reason.
    leg job-suppresses-scan 1 'job `bad` is not a mapping' 'job `big` step' <<YAML
jobs:
  big:
    steps:
      - run: |
          $over \${{ github.sha }}
  bad: oops
YAML
    leg job-suppresses-scan-control 1 'job `big` step' <<YAML
jobs:
  big:
    steps:
      - run: |
          $over \${{ github.sha }}
YAML

    # The bootstrap guard (BLO-38826) is the one leg whose fixture is an
    # interpreter rather than a workflow: shadow python3 with a stub that cannot
    # import yaml and whose `-m pip install` refuses, which is what a PEP
    # 668-managed interpreter does. The workflow present here is deliberately
    # VALID -- a bootstrap failure has to win before any file is read, and
    # asserting pip's own text proves the stub ran rather than the real python3.
    stub=$tmp/stub; mkdir -p "$stub"
    cat >"$stub/python3" <<'STUB'
#!/bin/sh
case "$*" in *pip*) echo "error: externally-managed-environment" >&2; exit 1;; esac
echo "ModuleNotFoundError: No module named 'yaml'" >&2; exit 1
STUB
    chmod +x "$stub/python3"
    leg bootstrap 1 'error: externally-managed-environment' '' '' "$stub" \
        <<<'jobs: {b: {steps: [{run: echo hi}]}}'

    wf=$tmp/empty-file/.github/workflows/wf.yml
    if [ ! -f "$wf" ] || [ -s "$wf" ]; then
        fails=$((fails + 1))
        echo "SELF-TEST FAIL [empty-file]: fixture is not a 0-byte file -- the" \
             "leg re-ran the control and its rc=1 means nothing."
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
# Also left open, and narrower still: `isinstance(step, dict)` below skips a
# malformed step inside an otherwise-scanned job without saying so. Unlike the
# cases above it that is not a file-level verdict -- `steps:` is a list and the
# rest of the job IS attested, so only that one element goes unmeasured. That
# claim is only true because a non-list `steps:` is now caught above; while it
# was not, "the rest of the job" could be nothing at all.
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
