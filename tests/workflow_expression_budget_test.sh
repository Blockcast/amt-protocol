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
# GitHub actually parses there is no anomaly: 19,709 < 21,000 < 30,584. Modelling
# the format() escaping on top (`'`->`''`, `{`->`{{`) moves both by ~0.5% --
# 19,807 and 30,731 -- and changes no verdict, so the scalar length is the
# working instrument.
set -uo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

# The real ceiling is 21,000. ~5% under it: enough that a step crossing the line
# fails here, where the message names the step, rather than at dispatch, where it
# takes the whole workflow down silently.
BUDGET=${WORKFLOW_EXPRESSION_BUDGET:-20000}

python3 -c 'import yaml' 2>/dev/null || pip install --quiet pyyaml

python3 - "$REPO_ROOT" "$BUDGET" <<'PY'
import glob, os, re, sys, yaml

root, budget = sys.argv[1], int(sys.argv[2])
EXPR = re.compile(r'\$\{\{.*?\}\}', re.S)
bad = largest = 0
worst = None

for path in sorted(glob.glob(os.path.join(root, '.github/workflows/*.yml'))
                   + glob.glob(os.path.join(root, '.github/workflows/*.yaml'))):
    rel = os.path.relpath(path, root)
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict):
        continue
    for jname, job in (doc.get('jobs') or {}).items():
        for i, step in enumerate(job.get('steps') or []):
            if not (isinstance(step, dict) and isinstance(step.get('run'), str)):
                continue
            run = step['run']
            sname = step.get('name') or step.get('id') or f'step[{i}]'
            n = len(EXPR.findall(run))
            if not n:
                continue
            if len(run) > largest:
                largest, worst = len(run), f'{rel} {jname} / {sname}'
            if len(run) > budget:
                bad += 1
                print(f'FAIL {rel}: job `{jname}` step `{sname}`: run block is '
                      f'{len(run)} scalar chars and contains {n} ${{{{ }}}} '
                      f'expression(s); budget is {budget}, GitHub refuses at '
                      f'21000.')
                print('     Fix: move the interpolated value into `env:` and '
                      'read it as a shell variable -- that takes the block out '
                      'of the expression plane entirely and leaves it unbounded. '
                      'Splitting the step also works. Do NOT just trim: over the '
                      'limit the WHOLE WORKFLOW stops parsing, which presents as '
                      'a 0-job `completed/failure` run, not as an error anyone '
                      'reads.')

print(f'largest interpolated run block: {largest} scalar chars '
      f'({worst or "none"}), budget {budget}, hard limit 21000')
sys.exit(1 if bad else 0)
PY
