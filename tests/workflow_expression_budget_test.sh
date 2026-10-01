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
if ! python3 -c 'import yaml' 2>/dev/null; then
    python3 -m pip install --quiet pyyaml >/dev/null 2>&1
    python3 -c 'import yaml' 2>/dev/null || { cat >&2 <<'BOOTSTRAP'
FAIL: bootstrap -- PyYAML is missing and `python3 -m pip install pyyaml` did not
      supply it (usually PEP 668: `error: externally-managed-environment`).
      NO WORKFLOW WAS SCANNED. This is a bootstrap failure, not a budget verdict.
      Fix: install it from the system packager (`apt-get install python3-yaml`),
      or run this guard from a venv --
        python3 -m venv /tmp/wb && /tmp/wb/bin/pip -q install pyyaml
        PATH=/tmp/wb/bin:$PATH bash tests/workflow_expression_budget_test.sh
BOOTSTRAP
        exit 1; }
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
unusable = []

for path in paths:
    rel = os.path.relpath(path, root)
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict):
        unusable.append(rel)
        continue
    for jname, job in (doc.get('jobs') or {}).items():
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

for rel in unusable:
    print(f'FAIL {rel}: does not load as a YAML mapping (empty file, or a bare '
          f'scalar), so no step in it was scanned. A guard that skipped a '
          f'workflow has not attested it; GitHub will not run it either.')

sys.exit(1 if bad or unusable else 0)
PY
