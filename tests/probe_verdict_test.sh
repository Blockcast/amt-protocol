#!/usr/bin/env bash
# Guards the probe step's VERDICT logic in
# .github/workflows/amt-public-vantage-probe.yml.
#
# It extracts the real run-block from the workflow YAML and executes it with
# `docker` stubbed, so this tests the shipped shell rather than a copy of it
# that can drift.
#
# Three contracts, each of which was violated at some point and is easy to
# re-break:
#
#   BLO-26574, CTO ruling item 5
#     amt-verify exits 1 on `outcome: timeout`, which is the NORMAL end of a
#     bounded sample. The verdict is therefore packet_count, not the exit code:
#     timeout + packet_count > 0 is a SUCCESS.
#
#   Ally review at head ada0251, Important (1)
#     The step used to exit with tunnel 1's status, so a healthy first tunnel
#     made an N-tunnel run green even when every later tunnel received nothing.
#     The verdict must be the aggregate.
#
#   Ally review at head ada0251, Important (2)
#     TUNNELS=1 must remain artifact-compatible with the single `docker run`
#     this step replaced: consumers fetch `report.json` / `verbose.log` by name.
#
#   Ally review at head 0ad7198, Important (1)
#     `fanout_capable` was telemetry the verdict never read, so an N-tunnel run
#     could go GREEN for a measurement the step had declared itself incapable of
#     making. TUNNELS > k is VOID (91), decided before packet_count -- and the
#     aggregate above must still be reachable and correct when k allows it.
#
#   Ally review at head 0ad7198, Important (2)
#     `tunnels` is an unbounded dispatch input used as the launch count. Reject
#     non-integers and anything outside 1..256 at the boundary (92).
set -uo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORKFLOW="$REPO_ROOT/.github/workflows/amt-public-vantage-probe.yml"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

# The ramp's host-capacity guard must validate every scalar before arithmetic.
# A single numeric-looking line is not enough: the old `printf ... | grep`
# check accepted a malformed sibling line because grep searched for *any* match.
# Keep this small contract test next to the workflow test so that a future edit
# cannot silently reintroduce arithmetic on `unavailable`/partial receipts.
is_uint() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; }
for value in 0 42 1048576; do
  is_uint "$value" || { echo "FAIL: expected unsigned integer: $value"; exit 1; }
done
# $'...' so the newline is real: a single-quoted '42\nnope' is the literal
# 8-char string backslash-n and never reached the multi-line case. $'42\n42'
# (every line numeric) is the input the old any-match grep was surest about.
for value in '' unavailable $'42\nnope' $'42\n42' '1x' '-1'; do
  if is_uint "$value"; then
    echo "FAIL: malformed host-capacity value accepted: $value"
    exit 1
  fi
done
grep -q 'is_uint()' "$WORKFLOW" || {
  echo "FAIL: workflow has no fail-closed scalar validator"; exit 1;
}
if grep -q "printf '%s\\\\n'.*grep -Eq '^[0-9]" "$WORKFLOW"; then
  echo "FAIL: workflow still validates a list with any-match grep"; exit 1
fi

python3 - "$WORKFLOW" "$WORK/probe.sh" <<'PY'
import sys, yaml
wf, out = sys.argv[1], sys.argv[2]
steps = yaml.safe_load(open(wf))['jobs']['probe']['steps']
block = next(s['run'] for s in steps if 'run' in s and 'docker pull' in s['run'])
open(out, 'w').write(block)
PY

# Extraction is a PRECONDITION, not a case. It fails for reasons that have
# nothing to do with the verdict logic -- a missing or moved workflow file, a
# renamed `probe` job, a step that no longer carries `docker pull`, absent
# pyyaml -- and without `set -e` the suite then runs every case against a
# missing probe.sh, scoring `bash: no such file` (127) as the result: 17
# assertions (13 cases) go red with a want/got line that reads like a
# verdict-logic regression. Abort instead of diagnosing it thirteen times.
#
# Delete THIS guard alone and the 13 probe cases go 17 FAIL / 0 PASS -- the
# sole `want=nonzero` case, "N=1 unparseable receipt -> red", is held red by
# the `!= 127` clause below. Delete BOTH and it is 16 FAIL / 1 PASS: that case
# goes GREEN because 127 is nonzero, and it cannot tell "probe.sh rejected a
# corrupt receipt" from "probe.sh never ran". That vacuous pass is the real
# defect -- Ally's review of #25 (head 1e849975, Suggestion 4) stated it as a
# silent vacuous pass of the WHOLE suite, which does not reproduce.
#
# Counts are assertions, not cases: 13 `run_case` calls, but the two N=1 cases
# that pass `pcs != oops` each add two legacy-artifact assertions that emit
# only on failure -- hence 17 broken from 13 cases. Figures above are the
# probe cases only. Healthy whole-suite is 19 PASS / 0 FAIL. The 6
# `run_ramp_case` calls #22 added never read probe.sh, but they do read
# verdict.sh, extracted the same way, so a broken precondition fails them too.
# With the verdict.sh guard below present the suite aborts before them: the
# whole-suite broken rows are the probe figures above (0 PASS / 17 FAIL and
# 1 PASS / 16 FAIL), exit 2, and `grep -c FAIL` returns 17 and 16 (the
# `FAILURES` summary line is never reached).
[ -s "$WORK/probe.sh" ] || { echo "ABORT: could not extract probe.sh from $WORKFLOW (workflow file missing, the 'probe' job renamed, the 'docker pull' step moved, or pyyaml absent)" >&2; exit 2; }

mkdir -p "$WORK/bin"
cat >"$WORK/bin/docker" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  pull)    exit 0 ;;
  inspect) echo "stub@sha256:deadbeef"; exit 0 ;;
esac
# The N tunnels run CONCURRENTLY, so a read-modify-write counter file races and
# two stubs hand back the same packet_count -- which silently turns the
# "a later tunnel got nothing" case green, i.e. hides the very regression this
# file exists to catch. mkdir is atomic; claim a slot with it.
n=0
while ! mkdir "$STUB_DIR/.claim.$((n+1))" 2>/dev/null; do n=$((n+1)); done
n=$((n+1))
pc=$(echo "$PC_LIST"   | cut -d, -f"$n")
ec=$(echo "$EXIT_LIST" | cut -d, -f"$n")
# BLO-33636 AC 2 delta control. LOSS_LIST is optional and unset for every probe
# case, which read only source/group/packet_count -- so those receipts keep the
# shape they had. Two sentinels the delta cases need and a float cannot express:
#   none = emit NO mmtp block at all (an older client build), which is what
#          exercises the `loss_ratio | type == "number"` guard. An absent field
#          arrives as null and a null must NOT be allowed to read as 0.
#   imp  = emit mmtp with implausible=1, the sequence-validity guard.
# A non-numeric token otherwise lands in the JSON verbatim and corrupts the
# receipt, which is the same `oops` mechanism PC_LIST already uses.
loss=$(echo "${LOSS_LIST:-}" | cut -d, -f"$n")
# An EMPTY receipt: the container died before writing (OOM-kill, evicted).
# The shell redirect still creates the file, so jq -s sees a valid input
# carrying ZERO values -- it does not error, the leg's array is simply one
# element short. That is what the `length == $n` count guard is for.
if [ "$pc" = empty ]; then echo "handshake trace" >&2; exit "$ec"; fi
case "$loss" in
  ''|none) mmtp= ;;
  imp)     mmtp=',"mmtp":{"implausible":1,"loss_ratio":0}' ;;
  noloss)  mmtp=',"mmtp":{"implausible":0}' ;;
  # A receipt for a DIFFERENT source, or a DIFFERENT group, with an otherwise
  # clean mmtp block, so one conjunct of the per-leg `.source == $s and
  # .group == $g` clause is the only guard that sees it. Two sentinels, not one
  # that varies both: a receipt wrong in both fields fails each conjunct, so
  # either conjunct alone would still void it and the other would go unheld.
  badsrc)  SOURCE=198.51.100.9; mmtp=',"mmtp":{"implausible":0,"loss_ratio":0.0015}' ;;
  badgrp)  GROUP=232.9.9.9; mmtp=',"mmtp":{"implausible":0,"loss_ratio":0.0015}' ;;
  *)       mmtp=",\"mmtp\":{\"implausible\":0,\"loss_ratio\":$loss}" ;;
esac
echo "{\"source\":\"$SOURCE\",\"group\":\"$GROUP\",\"packet_count\":$pc,\"outcome\":\"timeout\"$mmtp}"
echo "handshake trace" >&2
exit "$ec"
EOF
chmod +x "$WORK/bin/docker"
# The delta step curls api.ipify.org once per leg for its per-leg vantage
# receipt. Stub it: a unit test must not depend on egress, and the real call
# would also be the slowest thing in this file by two orders of magnitude.
cat >"$WORK/bin/curl" <<'EOF'
#!/usr/bin/env bash
echo "203.0.113.7"
EOF
chmod +x "$WORK/bin/curl"
export PATH="$WORK/bin:$PATH" STUB_DIR="$WORK"

FAILED=0
run_case() {
  local name=$1 tunnels=$2 pcs=$3 exits=$4 want=$5 k=${6:-1} got
  local dir; dir=$(mktemp -d -p "$WORK"); rm -rf "$WORK"/.claim.*
  # Ally review of #39 (head c04f8534), Important (1). GITHUB_ENV is a real
  # file here, as it is on a runner. Left unset, the aggregate's
  # `>> "$GITHUB_ENV"` was an ambiguous redirect that killed the script with
  # exit 1 -- so a red case could not tell "reached the verdict" from "died at
  # the redirect", and the knee case passed only because a regressed knee
  # (writing ZERO_DATA) died too. ZERO_DATA is what files an OUTAGE row, so
  # it is asserted per case below, not inferred from the exit code.
  : >"$dir/gh_env"
  ( cd "$dir"
    export TUNNELS=$tunnels PC_LIST=$pcs EXIT_LIST=$exits DISTINCT_SOURCE_IPS=$k \
           RELAY=1.2.3.4 SOURCE=69.25.95.192 GROUP=232.1.1.60 TIMEOUT=5 PACKETS=3 \
           GITHUB_ENV="$dir/gh_env"
    # k=unset is the production shape: the variable is ABSENT and the `:-1`
    # default in the workflow decides k.
    [ "$k" = unset ] && unset DISTINCT_SOURCE_IPS
    bash "$WORK/probe.sh" ) >/dev/null 2>&1; got=$?

  # `want=nonzero` where the contract is only "must not pass": a corrupt receipt
  # dies at the (S,G) guard carrying jq's own exit code, and pinning that number
  # would freeze an implementation detail rather than the behaviour. 127 is
  # excluded because it is the one nonzero code that means the subject never
  # produced a verdict of its own -- bash returns it both when probe.sh is
  # absent and when probe.sh runs but calls a missing binary (jq gone from the
  # image). A "must not pass" assertion is otherwise satisfied by a broken test
  # environment, which is the opposite of a positive control. Belt-and-braces
  # with the extraction guard above: that one catches the known cause, this one
  # catches any cause.
  #
  # Exit 1 is the aggregate verdict and the ONLY path that may set ZERO_DATA=1;
  # 0, VOID 91, knee 93, reject 92 and a corrupt receipt must leave it unset.
  local got_env want_env=; got_env=$(cat "$dir/gh_env")
  [ "$want" = 1 ] && want_env=ZERO_DATA=1
  if { { [ "$want" = nonzero ] && [ "$got" != 0 ] && [ "$got" != 127 ]; } || [ "$got" = "$want" ]; } \
     && [ "$got_env" = "$want_env" ]; then
    echo "PASS  $name (exit $got, GITHUB_ENV='$got_env')"
  else
    echo "FAIL  $name: want exit $want GITHUB_ENV='$want_env', got exit $got GITHUB_ENV='$got_env'"; FAILED=1
  fi

  if [ "$tunnels" = 1 ] && [ "$pcs" != oops ]; then
    for legacy in report.json verbose.log; do
      [ -f "$dir/$legacy" ] || { echo "FAIL  $name: legacy artifact $legacy missing"; FAILED=1; }
    done
  fi
  rm -rf "$dir"
}

#                                                       name                          N  packet_counts  exits  want  k
run_case "N=1 timeout-exit1 but packet_count>0 -> green" 1 "412"     "1"   0
run_case "N=1 zero data -> red"                          1 "0"       "1"   1
run_case "N=1 unparseable receipt -> red"                1 "oops"    "1"   nonzero

# Ally review of #25 (head 0ad7198), Important (1). k=1 is the real rig: every
# container shares the runner netns, and the relay keys tunnel state on source
# ADDRESS, so N>1 cannot establish fan-out. "second zero-data" used to exit 1
# with a message blaming delivery; it is now VOID (91), decided before
# packet_count is consulted.
#
# ⚠ "both receiving, k=1" USED TO ASSERT 91 AND NOW ASSERTS 0. That test
# encoded the premise this PR retires: with the old `TUNNELS -gt K` guard the
# verdict never looked at what the run measured, so 2/2 receiving from one
# address was voided as "the relay must be pre-fix". Prod .128 was rolled onto
# the endpoint-key module on 2026-09-28 and run 36474867098 then took 3/3 from
# ONE public address -- so ok > K is now the DEMONSTRATION that the relay
# fans out, and voiding it would fail the only runs that can prove the fix.
run_case "N=2 both receiving, k=1 -> green (fan-out demonstrated)" 2 "500,500" "1,1" 0 1
run_case "N=2 second zero-data, k=1 -> void not red"     2 "500,0"   "1,1" 91  1

# Ally review of #25 (head 73c16a1), Important (1). Every case above exports
# DISTINCT_SOURCE_IPS, so the `:-1` default -- the only value a real dispatch
# ever uses, and the line the VOID gate hangs on -- was never exercised. Run
# once with the variable absent; this case fails if that default drifts.
run_case "N=2 second zero-data, k unset -> void (prod default)" 2 "500,0" "1,1" 91 unset

# The aggregate verdict must still be correct for a rig that DOES present
# distinct source addresses, or the k-gate above would silently retire the
# coverage Ally's earlier review added. k=2 is the only way to reach it.
run_case "N=2 second zero-data, k=2 -> red"              2 "500,0"   "1,1" 1   2
run_case "N=2 first zero-data, k=2 -> red"               2 "0,500"   "1,1" 1   2
run_case "N=2 both receiving, k=2 -> green"              2 "500,500" "1,1" 0   2

# Ally review of #39 (head fed8b706), Important (1). The VOID condition must
# key on K, not on a literal 1: byte-identical while K is 1, but with distinct
# source addresses a run that never demonstrated fan-out would go GREEN. Here
# N=3 over k=2 addresses with only 2 receiving is exactly that -- ok <= K, so
# nothing was demonstrated beyond what k already gives you. Mutation-checked:
# with the literal-1 form this case scores 1 -- a routed OUTAGE row for a run
# that established no fan-out at all. Only the K form voids it.
run_case "N=3, ok=2, k=2 -> void (no fan-out beyond k)"  3 "500,500,0" "1,1,1" 91 2

# Ally review of #39 (head fed8b706), Important (2). The partial knee is a
# relay at its per-source cap: it IS forwarding, to ok tunnels. It used to fall
# through to the aggregate verdict, which sets ZERO_DATA=1 and files an OUTAGE
# row. Distinct code, and ZERO_DATA stays unset so neither routing arm fires.
run_case "N=3, ok=2, k=1 -> knee not outage"             3 "500,500,0" "1,1,1" 93 1

# Ally review of #25 (head 0ad7198), Important (2). `tunnels` is a dispatch
# input used as the launch count; reject at the boundary, not mid-loop.
run_case "tunnels=0 rejected"                            0     "0" "1" 92
run_case "tunnels=abc rejected"                          abc   "0" "1" 92
run_case "tunnels=257 over documented cap rejected"      257   "0" "1" 92
run_case "tunnels='' rejected"                           ""    "0" "1" 92


# Ally review of #22 (head d3896d3), Important (1). The tunnels-ramp Verdict
# step derived `cap` from the raw STEPS text while `top` came from `jq -r`, and
# compared them as strings: `1, 8, 1024` (accepted by `Validate ramp steps`,
# which word-splits) left a leading blank in `cap`, so a fully clean ramp fell
# through to "degraded ... BINDER NOT ESTABLISHED (0 cause(s))". Drive the real
# Verdict run-block against synthetic ramp-index.json fixtures. It needs only
# `jq` and `tee`, so no docker stub.
python3 - "$WORKFLOW" "$WORK/verdict.sh" <<'PY'
import sys, yaml
wf, out = sys.argv[1], sys.argv[2]
steps = yaml.safe_load(open(wf))['jobs']['tunnels-ramp']['steps']
open(out, 'w').write(next(s['run'] for s in steps if s.get('name') == 'Verdict'))
PY
# Same precondition contract as the probe.sh guard above, and `bash -n` is NOT
# it: `open(out,'w')` runs before `next()` raises, so a renamed `Verdict` step
# leaves an EMPTY verdict.sh, which parses cleanly and takes that check GREEN.
# (A renamed job raises KeyError on the lookup line before `open()` and leaves
# no file; `-s` catches both. The probe block cannot leave an empty file: its
# `next()` runs on its own line, before `open()`.)
# The 6 ramp cases below then go red with `want '...', got:` lines that read
# like a verdict-logic regression. Measured on the merged head: rename the
# `Verdict` step and the suite reports 13 PASS / 6 FAIL with zero "does not
# parse", i.e. the one assertion meant to catch this is the one that passes.
[ -s "$WORK/verdict.sh" ] || { echo "ABORT: could not extract the tunnels-ramp Verdict step from $WORKFLOW (workflow file missing, the 'tunnels-ramp' job or 'Verdict' step renamed, or pyyaml absent)" >&2; exit 2; }
bash -n "$WORK/verdict.sh" || { echo "FAIL  tunnels-ramp Verdict step does not parse"; FAILED=1; }

run_ramp_case() {
  local name=$1 steps=$2 index=$3 want=$4
  local dir; dir=$(mktemp -d -p "$WORK")
  printf '%s' "$index" >"$dir/ramp-index.json"
  ( cd "$dir" && STEPS=$steps bash "$WORK/verdict.sh" ) >/dev/null 2>&1
  if grep -qF "$want" "$dir/verdict.txt" 2>/dev/null; then
    echo "PASS  $name"
  else
    echo "FAIL  $name: want '$want', got: $(head -c 200 "$dir/verdict.txt" 2>/dev/null)"; FAILED=1
  fi
  rm -rf "$dir"
}

CLEAN='[{"requested":1,"report":{"alive":1,"distinct_outer_sources":1}},{"requested":8,"report":{"alive":8,"distinct_outer_sources":8}},{"requested":1024,"report":{"alive":1024,"distinct_outer_sources":1024}}]'
run_ramp_case "clean ramp, bare steps -> config-bound" "1,8,1024" "$CLEAN" \
  "verdict=ceiling >= 1024, config-bound"
# Negative control for the string-compare regression: the validator accepts
# this spelling, so the verdict must read it identically.
run_ramp_case "clean ramp, comma-space steps -> config-bound (regression: cap kept leading blank)" "1, 8, 1024" "$CLEAN" \
  "verdict=ceiling >= 1024, config-bound"
run_ramp_case "aliased step supersedes clean cap" "1,8,1024" \
  '[{"requested":1,"report":{"alive":1,"distinct_outer_sources":1}},{"requested":8,"report":{"alive":8,"distinct_outer_sources":8}},{"requested":1024,"report":{"alive":1024,"distinct_outer_sources":1}}]' \
  "verdict=WITNESS NOT ESTABLISHED"
run_ramp_case "legacy report without distinct_outer_sources -> aliased" "1,8,1024" \
  '[{"requested":1,"report":{"alive":1,"distinct_outer_sources":1}},{"requested":8,"report":{"alive":8}},{"requested":1024,"report":{"alive":1024,"distinct_outer_sources":1024}}]' \
  "verdict=WITNESS NOT ESTABLISHED (1/3"
run_ramp_case "degraded relay-attributed -> knee" "1,8,1024" \
  '[{"requested":1,"report":{"alive":1,"distinct_outer_sources":1}},{"requested":8,"report":{"alive":8,"distinct_outer_sources":8}},{"requested":1024,"report":{"alive":900,"distinct_outer_sources":1024,"establish_errors":{"relay refused: tunnel table full":124}}}]' \
  "verdict=knee at N>8"
run_ramp_case "degraded unknown cause -> binder not established" "1,8,1024" \
  '[{"requested":1,"report":{"alive":1,"distinct_outer_sources":1}},{"requested":8,"report":{"alive":8,"distinct_outer_sources":8}},{"requested":1024,"report":{"alive":900,"distinct_outer_sources":1024,"establish_errors":{"connection reset":124}}}]' \
  "verdict=degraded above N=8, BINDER NOT ESTABLISHED (1 cause(s)"

# Ally review at head 50f03ee, Important (1). The infra arm routes a
# flake-prone class -- ipify, checkout, the ghcr login, upload-artifact -- into
# a row that nothing closed, so the first blip filed `[amt-probe][infra] ...`
# permanently and the exact-title dedup then demoted every LATER genuine
# detector death to a comment on that stale row. `Clear probe failure rows`
# closes both rows on a green scheduled run.
#
# THE SILENT WAY THIS ROTS IS TITLE DRIFT. The clear step looks its rows up by
# exact string, so editing a title in one step and not the other leaves a step
# that runs, exits 0, prints clear=absent, and clears nothing forever -- the
# same never-closes state, reached with the fix apparently in place. So this
# does NOT assert the titles equal some literal copied into the test (which
# would drift with them). It runs BOTH real run-blocks and feeds the clear step
# a list built from the titles the ROUTE step actually emitted.
python3 - "$WORKFLOW" "$WORK/route.sh" "$WORK/clear.sh" <<'PY'
import sys, yaml
wf, route, clear = sys.argv[1:4]
steps = {s.get('name'): s for s in yaml.safe_load(open(wf))['jobs']['probe']['steps']}
for name, out in (('Route probe failure', route), ('Clear probe failure rows', clear)):
    assert name in steps, f'step missing from workflow: {name}'
    open(out, 'w').write(steps[name]['run'])
PY
bash -n "$WORK/route.sh"  || { echo "FAIL  Route probe failure does not parse"; FAILED=1; }
bash -n "$WORK/clear.sh"  || { echo "FAIL  Clear probe failure rows does not parse"; FAILED=1; }

cat >"$WORK/bin/gh" <<'EOF'
#!/usr/bin/env bash
verb=$2; shift 2
case "$verb" in
  list) cat "$GH_LIST" ;;
  create)
    while [ $# -gt 0 ]; do
      [ "$1" = --title ] && printf '%s\n' "$2" >>"$GH_OUT.titles"
      shift
    done
    echo "https://example.invalid/issues/0" ;;
  comment) printf 'comment %s\n' "$1" >>"$GH_OUT.acts" ;;
  close)   printf 'close %s\n'   "$1" >>"$GH_OUT.acts" ;;
esac
exit 0
EOF
chmod +x "$WORK/bin/gh"

probe_env() {
  # GITHUB_REPOSITORY is load-bearing, not decoration: both run-blocks are
  # `set -u`, so omitting it aborts them before the first gh call and this
  # file's real assertions all pass vacuously on zero observations.
  export RELAY=1.2.3.4 SOURCE=69.25.95.192 GROUP=232.1.1.60 \
         RUN_URL=https://example.invalid/run GH_TOKEN=stub \
         GITHUB_REPOSITORY=Blockcast/amt-protocol
}

# 1. Harvest the two titles the route step really builds, one per arm.
echo '[]' >"$WORK/empty.json"
: >"$WORK/routed.titles"
for arm in zero infra; do
  ( probe_env
    export GH_LIST="$WORK/empty.json" GH_OUT="$WORK/routed"
    [ "$arm" = zero ] && export ZERO_DATA=1
    bash "$WORK/route.sh" ) >/dev/null 2>&1
done
mapfile -t ROUTED_TITLES <"$WORK/routed.titles"
if [ "${#ROUTED_TITLES[@]}" -ne 2 ]; then
  echo "FAIL  route step emitted ${#ROUTED_TITLES[@]} titles, want 2 (one per arm)"; FAILED=1
fi

# 2. The dedup path. Case 1 drove the route step with an empty list, so only
# `gh issue create` was covered; `gh issue comment` on an already-open row is
# what "the row count tracks FAULTS and not minutes" actually rests on. Feed
# the titles it just emitted straight back in: each arm must comment on its OWN
# row, and a create here would mean the exact-title lookup missed a row it had
# itself filed one call earlier.
python3 - "$WORK/routed.titles" "$WORK/open.json" <<'PY'
import json, sys
titles = [t.rstrip('\n') for t in open(sys.argv[1]) if t.strip()]
json.dump([{'number': 101 + i, 'title': t} for i, t in enumerate(titles)], open(sys.argv[2], 'w'))
PY
for arm in zero infra; do
  : >"$WORK/dedup-$arm.acts"; : >"$WORK/dedup-$arm.titles"
  ( probe_env
    export GH_LIST="$WORK/open.json" GH_OUT="$WORK/dedup-$arm"
    [ "$arm" = zero ] && export ZERO_DATA=1
    bash "$WORK/route.sh" ) >/dev/null 2>&1
  # routed.titles is written zero-arm first, so #101 is zero and #102 is infra.
  want=101; [ "$arm" = infra ] && want=102
  if [ "$(cat "$WORK/dedup-$arm.acts")" = "comment $want" ] && [ ! -s "$WORK/dedup-$arm.titles" ]; then
    echo "PASS  route step dedups the $arm arm onto its own open row (#$want)"
  else
    echo "FAIL  route step $arm arm: want 'comment $want' and no create, got"
    echo "      acts=$(cat "$WORK/dedup-$arm.acts") created=$(cat "$WORK/dedup-$arm.titles")"; FAILED=1
  fi
done

# 3. Offer the clear step exactly those rows. Matching titles => both closed.
: >"$WORK/clear.acts"
( probe_env
  export GH_LIST="$WORK/open.json" GH_OUT="$WORK/clear"
  bash "$WORK/clear.sh" ) >/dev/null 2>&1
closed=$(grep -c '^close ' "$WORK/clear.acts" || true)
closed=${closed:-0}
if [ "$closed" = "${#ROUTED_TITLES[@]}" ] && [ "$closed" != 0 ]; then
  echo "PASS  green scheduled run closes both routed rows (titles agree across steps)"
else
  echo "FAIL  clear step closed $closed of ${#ROUTED_TITLES[@]} rows the route step files."
  echo "      Titles have drifted between 'Route probe failure' and 'Clear probe failure rows';"
  echo "      the rows would never close. Route emitted:"
  printf '        %s\n' "${ROUTED_TITLES[@]}"
  FAILED=1
fi

# 4. Negative control: nothing open must close nothing. Without this, a clear
# step that closed whatever it found first would pass case 3 for free.
: >"$WORK/none.acts"
( probe_env
  export GH_LIST="$WORK/empty.json" GH_OUT="$WORK/none"
  bash "$WORK/clear.sh" ) >/dev/null 2>&1
if [ -s "$WORK/none.acts" ]; then
  echo "FAIL  clear step acted with no matching row open: $(cat "$WORK/none.acts")"; FAILED=1
else
  echo "PASS  clear step is a no-op when neither row is open"
fi

# 5. The clear step must be gated on BOTH a green run and a scheduled one: a
# dispatch may target a different (S,G) or the .99 positive control, and
# clearing a production row off a control run is the silent direction of wrong.
CLEAR_IF=$(python3 -c "
import sys, yaml
steps = {s.get('name'): s for s in yaml.safe_load(open(sys.argv[1]))['jobs']['probe']['steps']}
print(steps['Clear probe failure rows'].get('if', ''))
" "$WORKFLOW")
case "$CLEAR_IF" in
  *success\(\)*schedule*) echo "PASS  clear step gated on success() and event_name == schedule" ;;
  *) echo "FAIL  clear step gate must require success() and a scheduled event, got: $CLEAR_IF"; FAILED=1 ;;
esac

# 6. Ally review at head 1678771, Important (1). The bound in case 7 frees the
# runner but does NOT make a wedge file anything -- that depends on which job
# status a timeout produces, which the GitHub docs do not state. MEASURED in
# run 36207352472 (`timeout-minutes: 1` vs `sleep 300`): the job ends
# CANCELLED, `if: failure()` is SKIPPED, and `always()` / `cancelled()` steps
# still run with `job.status == 'cancelled'`. So a `failure()`-gated router is
# blind to exactly the wedge it exists to catch, and the fix has to be in the
# gate. Assert the mechanism, not the string: a status FUNCTION must be present
# or the runner prepends an implicit `success() &&`, the non-verdict arm must
# key on `job.status` rather than `failure()`, and `failure()` must be gone
# from the expression entirely -- reintroducing it anywhere re-arms the hole.
ROUTE_IF=$(python3 -c "
import sys, yaml
steps = {s.get('name'): s for s in yaml.safe_load(open(sys.argv[1]))['jobs']['probe']['steps']}
print(steps['Route probe failure'].get('if', ''))
" "$WORKFLOW")
route_gate_ok=1
case "$ROUTE_IF" in *'always()'*) ;; *) route_gate_ok=0 ;; esac
case "$ROUTE_IF" in *"job.status != 'success'"*) ;; *) route_gate_ok=0 ;; esac
case "$ROUTE_IF" in *'failure()'*) route_gate_ok=0 ;; esac
if [ "$route_gate_ok" = 1 ]; then
  echo "PASS  route step survives a job-timeout cancellation (always() + job.status, no failure())"
else
  echo "FAIL  route step gate must be always()-anchored and key the non-verdict arm on"
  echo "      job.status != 'success'; failure() is FALSE on a timeout cancellation"
  echo "      (measured, run 36207352472) so a wedge would file nothing. Got: $ROUTE_IF"
  FAILED=1
fi

# 7. Ally review at head 50f03ee, Suggestion (1). The default job timeout is
# 360 min against a 15-minute cron, so one wedge spans ~24 firings and runs
# overlap. Anything under the interval also removes the overlap.
PROBE_TIMEOUT=$(python3 -c "
import sys, yaml
print(yaml.safe_load(open(sys.argv[1]))['jobs']['probe'].get('timeout-minutes', 0))
" "$WORKFLOW")
if [ "$PROBE_TIMEOUT" -gt 0 ] && [ "$PROBE_TIMEOUT" -le 15 ]; then
  echo "PASS  probe job bounded at ${PROBE_TIMEOUT}m, inside the 15m cron interval"
else
  echo "FAIL  probe job timeout-minutes=$PROBE_TIMEOUT: must be 1..15 so a wedge cannot"
  echo "      outlive its cron interval"; FAILED=1
fi

# 8. Ally review at head d1c80d2, Important (1). Case 6 asserts TOKENS in the
# route gate -- `always()` present, `job.status != 'success'` present,
# `failure()` absent. That is documentation, not a guard: it passed green while
# `job.status != 'cancelled'` on the zero-data arm made (cancelled,
# ZERO_DATA=1, schedule) satisfy NEITHER arm, so a verdict that was actually
# reached routed nothing. A token test cannot express exhaustiveness, which is
# the property that matters, so evaluate the gate instead of grepping it.
#
# The invariant: on a SCHEDULED run every non-success end must route exactly
# one row -- either diagnosis is actionable, silence is not. This case would
# also have gone red on the original `!cancelled()` gate, i.e. on both
# instances of this bug rather than only the second.
python3 - "$WORKFLOW" <<'PY' || FAILED=1
import re, sys, yaml

steps = {s.get('name'): s for s in yaml.safe_load(open(sys.argv[1]))['jobs']['probe']['steps']}
expr = steps['Route probe failure']['if'].strip()
expr = re.sub(r'^\$\{\{|\}\}$', '', expr).strip()

def gate(status, zero, event, route_failure):
    """Evaluate the GitHub Actions `if:` expression for one context tuple."""
    e = expr
    # Status functions are exactly their job.status equivalents. Substituting
    # all three (rather than only always()) keeps this evaluator valid for the
    # whole grammar this gate can legally use, so a future `!cancelled()` or
    # `success()` fails the EXHAUSTIVENESS check below on its merits instead of
    # dying in a SyntaxError that reads as a broken test.
    e = e.replace('always()', 'True')
    e = re.sub(r'\bsuccess\(\)', repr(status == 'success'), e)
    e = re.sub(r'\bfailure\(\)', repr(status == 'failure'), e)
    e = re.sub(r'\bcancelled\(\)', repr(status == 'cancelled'), e)
    e = re.sub(r'\bjob\.status\b', repr(status), e)
    e = re.sub(r'\benv\.ZERO_DATA\b', repr(zero), e)
    e = re.sub(r'\bgithub\.event_name\b', repr(event), e)
    e = re.sub(r'\binputs\.route_failure\b', repr(route_failure), e)
    e = e.replace('&&', ' and ').replace('||', ' or ')
    e = re.sub(r'!(?![=])', ' not ', e)
    # Any context or status function we did not substitute would silently
    # NameError; surface it as a failure rather than a crash.
    return bool(eval(e, {'__builtins__': {}}, {}))

bad = []
try:
    # A. THE ONE THAT MATTERS. Arms exhaustive over every non-success end of a
    #    scheduled run. ZERO_DATA=1 is the relay verdict, '' is a detector
    #    death; `cancelled` is what `timeout-minutes` produces (run
    #    36207352472) and `failure` is every other bad exit.
    for status in ('failure', 'cancelled'):
        for zero in ('1', ''):
            if not gate(status, zero, 'schedule', False):
                bad.append(f"scheduled job.status={status} ZERO_DATA={zero!r}: routes NOTHING")
    # B. A green scheduled run must stay silent, or the detector cries wolf.
    if gate('success', '', 'schedule', False):
        bad.append("green scheduled run routes an alert")
    # C. An unopted dispatch must stay silent -- this is the spam guard
    #    `route_failure` exists for, and every measurement run trips it.
    for status in ('failure', 'cancelled'):
        if gate(status, '1', 'workflow_dispatch', False):
            bad.append(f"dispatch route_failure=false job.status={status}: routes an alert")
    # D. An opted dispatch with a real zero-data verdict must route, including
    #    after a cancellation: the verdict precedes it and is not retracted.
    for status in ('failure', 'cancelled'):
        if not gate(status, '1', 'workflow_dispatch', True):
            bad.append(f"dispatch route_failure=true job.status={status} ZERO_DATA=1: routes NOTHING")
except Exception as exc:
    bad.append(f"gate is not evaluable ({exc.__class__.__name__}: {exc}); unsubstituted context?")

if bad:
    print("FAIL  route gate arms are not exhaustive over job.status != 'success'")
    for b in bad:
        print(f"      - {b}")
    print(f"      gate: {expr}")
    sys.exit(1)
print("PASS  route gate routes exactly one row for every non-success scheduled end")
PY

# ---------------------------------------------------------------------------
# BLO-33636 AC 2 (AMENDED 2026-09-29): the fan-out loss DELTA control.
#
# Extracted the same way as probe.sh, from the `loss-delta` job, so this tests
# the shipped shell rather than a copy that can drift. The probe extractor
# above is scoped to jobs['probe'], so the new job cannot disturb it.
# ---------------------------------------------------------------------------
python3 - "$WORKFLOW" "$WORK/delta.sh" <<'PY'
import sys, yaml
wf, out = sys.argv[1], sys.argv[2]
steps = yaml.safe_load(open(wf))['jobs']['loss-delta']['steps']
block = next(s['run'] for s in steps if 'run' in s and 'docker pull' in s['run'])
open(out, 'w').write(block)
PY
[ -s "$WORK/delta.sh" ] || { echo "ABORT: could not extract delta.sh from $WORKFLOW (the 'loss-delta' job renamed, or its 'docker pull' step moved)" >&2; exit 2; }

# run_delta_case <name> <N> <pcs> <losses> <timeout> <want>
#
# PC_LIST/LOSS_LIST are FLAT across all three legs, in leg order: index 1 is
# leg 1 (N=1), 2..N+1 are the middle leg, N+2 is leg 3. Within the middle leg
# the N concurrent stubs claim indices in a racy order, but every assertion
# here is order-independent by construction -- a mean does not care, and one
# bad receipt invalidates the leg whichever slot it lands in.
run_delta_case() {
  local name=$1 n=$2 pcs=$3 losses=$4 tmo=$5 want=$6 got
  local dir; dir=$(mktemp -d -p "$WORK"); rm -rf "$WORK"/.claim.*
  ( cd "$dir"
    export TUNNELS=$n PC_LIST=$pcs LOSS_LIST=$losses EXIT_LIST=1,1,1,1,1,1,1,1 \
           RELAY=1.2.3.4 SOURCE=69.25.95.192 GROUP=232.1.1.60 \
           TIMEOUT=$tmo PACKETS=3
    bash "$WORK/delta.sh" >out.log 2>&1
  ); got=$?
  if [ "$got" = "$want" ]; then
    echo "PASS  $name (exit $got)"
  else
    echo "FAIL  $name: want exit $want, got $got"; FAILED=1
    sed -n '1,40p' "$dir/out.log" | sed 's/^/      /'
  fi
}

# Reference legs are 1,3,1 with THRESH=0.002.
#
#   base   = mean(leg1, leg3);  signal = leg2 - base;  noise = |leg1 - leg3|
#
# 0 = PASS, 1 = FAIL (fan-out costs loss), 91 = VOID, 92 = rejected input.

# signal = 0.0015 - 0.001 = 0.0005 < 0.002; noise = 0. The instrument's
# positive control: it must be able to return a PASS, or every red below is
# vacuous.
run_delta_case "clean fan-out -> PASS" \
  3 1,1,1,1,1 0.001,0.0015,0.0015,0.0015,0.001 30 0

# signal = 0.005 - 0.001 = 0.004 >= 0.002 over a floor of 0, so the path was
# stable enough to ask and the cost is attributable to serving 3 tunnels.
run_delta_case "fan-out costs loss over a quiet floor -> FAIL" \
  3 1,1,1,1,1 0.001,0.005,0.005,0.005,0.001 30 1

# The VOID arm must beat a clean-looking PASS. noise = |0.001 - 0.010| = 0.009
# >= 0.002, so the run cannot ask the question. Note the signal here is
# NEGATIVE (0.0015 - 0.0055 = -0.004), i.e. it clears the PASS test
# comfortably -- so an implementation without the VOID arm reports a clean PASS
# off a baseline that moved 9x the threshold underneath it. That is the retired
# absolute clause's defect with the sign flipped.
run_delta_case "wide noise floor beats a clean-looking signal -> VOID" \
  3 1,1,1,1,1 0.001,0.0015,0.0015,0.0015,0.010 30 91

# THE PRECEDENCE CASE: both arms fire at once. base = 0.0035, so signal =
# 0.0065 >= 0.002 AND noise = |0.001 - 0.006| = 0.005 >= 0.002. VOID and FAIL
# are BOTH true and the order of the tests decides which is reported -- the
# ruling says VOID, because a large signal measured across a baseline that
# moved by 2.5x the threshold is not evidence that fan-out is expensive, it is
# evidence that this run could not tell. Reporting FAIL there would indict a
# relay on the runner's egress, which is the whole defect being retired.
#
# The case above does NOT test this: with a negative signal only one arm can
# fire, so swapping the two tests leaves its verdict unchanged. Only a case
# where both are true can see the order at all.
run_delta_case "wide floor AND large signal -> VOID, not FAIL" \
  3 1,1,1,1,1 0.001,0.010,0.010,0.010,0.006 30 91

# A zero-data tunnel in the middle leg. The mean must NOT be taken over the two
# survivors: that would be a 2-tunnel measurement wearing a 3-tunnel label, and
# N is the variable under test. Establishing fan-out is oneshot's verdict, so
# this routes VOID rather than being re-diagnosed here.
run_delta_case "zero-data tunnel in the middle leg -> VOID" \
  3 1,1,0,1,1 0.001,0.0015,0.0015,0.0015,0.001 30 91

# An older client build with no mmtp block at all.
run_delta_case "receipt with no mmtp block -> VOID" \
  3 1,1,1,1,1 0.001,0.0015,none,0.0015,0.001 30 91

# mmtp PRESENT and implausible=0, but loss_ratio ABSENT -- a build that reports
# sequence validity without a loss figure.
#
# ⚠ This case exists because mutation testing caught the one above being
# INERT for the `loss_ratio | type == "number"` guard. With no mmtp block the
# `implausible // 1` guard fires first and returns null anyway, so removing the
# type guard left that case green and the type guard was untested -- a guard
# with a confident comment and nothing holding it. Here implausible is a clean
# 0, so the type guard is the ONLY thing that sees the absent field.
#
# Without it, `map(.mmtp.loss_ratio)` yields [0.0015, null, 0.0015]; jq's `add`
# treats null as the identity rather than erroring, so it sums to 0.003 and
# divides by 3 for a mean of 0.001. The missing receipt is silently scored as a
# PERFECT zero-loss tunnel, the leg looks clean, and the run reports PASS. A
# non-numeric loss_ratio (a string) would make `add` error and land on null by
# accident -- absence is the shape that fails open, which is why this case uses
# it. Same family as every other "an absent field is not a zero" trap here.
run_delta_case "mmtp present but loss_ratio absent -> VOID" \
  3 1,1,1,1,1 0.001,0.0015,noloss,0.0015,0.001 30 91

# A receipt that echoes a different source or group is not a measurement of
# this run's channel. Without the (S,G) clause in the per-leg mean it is
# averaged in like any other tunnel, and a clean-looking stray receipt lowers
# the leg mean. Every other guard passes these receipts, so each case holds one
# conjunct: replacing `.source == $s` with `true` turns the first green, and
# replacing `.group == $g` with `true` turns the second green.
run_delta_case "receipt echoes a different source -> VOID" \
  3 1,1,1,1,1 0.001,0.0015,badsrc,0.0015,0.001 30 91
run_delta_case "receipt echoes a different group -> VOID" \
  3 1,1,1,1,1 0.001,0.0015,badgrp,0.0015,0.001 30 91

# implausible != 0 means the sequence numbers cannot be trusted, so neither can
# a loss ratio derived from them.
run_delta_case "implausible sequence numbers -> VOID" \
  3 1,1,1,1,1 0.001,0.0015,imp,0.0015,0.001 30 91

# A corrupt receipt: `oops` lands in the JSON verbatim, so the file will not
# parse and the leg has no usable mean.
run_delta_case "unparseable receipt -> VOID" \
  3 1,1,oops,1,1 0.001,0.0015,0.0015,0.0015,0.001 30 91

# An EMPTY receipt -- the container died before writing. Distinct from the
# corrupt one above and caught by a different guard: jq -s does NOT error on an
# empty input, it just yields one value fewer, so the leg would otherwise be
# scored as a clean 2-tunnel run wearing a 3-tunnel label. `length == $n` is
# the only thing that sees it.
run_delta_case "empty receipt (container died mid-write) -> VOID" \
  3 1,1,empty,1,1 0.001,0.0015,0.0015,0.0015,0.001 30 91

# N=1 makes the middle leg a control leg: signal is 0 by construction and the
# run would report PASS having measured nothing. Rejected at the boundary.
run_delta_case "N=1 is a vacuous green -> rejected" \
  1 1,1,1 0.001,0.001,0.001 30 92
run_delta_case "non-integer N -> rejected" \
  abc 1,1,1 0.001,0.001,0.001 30 92

# Three legs run sequentially, so the job's wall clock is ~3x timeout. Reject
# at the boundary rather than letting the job cap CANCEL the run mid-leg: a
# cancelled job emits no verdict, which reads as a missing measurement rather
# than a rejected input.
run_delta_case "3 x timeout over the job budget -> rejected" \
  3 1,1,1,1,1 0.001,0.001,0.001,0.001,0.001 400 92

# The legs must be ordered 1, N, 1 -- bracketing, not 1,1,N. Ordered 1,1,N the
# noise floor is measured entirely BEFORE the signal and cannot witness drift
# across the interval the signal was taken in, which is the whole reason the
# ruling specified this order. A source-level assertion because the exit code
# cannot distinguish the two orders on a stationary stub path.
grep -q 'for n in 1 "\$TUNNELS" 1; do' "$WORK/delta.sh" \
  && echo "PASS  delta legs bracket the N leg (1, N, 1)" \
  || { echo "FAIL  delta legs are not ordered 1, N, 1 -- the noise floor no longer spans the signal"; FAILED=1; }

# The threshold decides the result, so a dispatch caller must not be able to
# supply it. Same contract as DISTINCT_SOURCE_IPS in the probe job.
grep -q '^ *THRESH=0.002' "$WORK/delta.sh" \
  && echo "PASS  delta threshold is a constant, not an input" \
  || { echo "FAIL  delta threshold is no longer a hardcoded constant"; FAILED=1; }

# A wide floor has two causes with different follow-ups -- the egress rotated,
# or the path drifted while the address held -- and only the per-leg addresses
# tell them apart. Live run 36568716671 hit the second (one IP across all three
# legs, floor 0.0088), so a VOID that does not report the vantage sends the
# reader to re-dispatch against a vantage that cannot answer. Source-level
# because the exit code is 91 either way.
grep -q 'vantage=\$vantage' "$WORK/delta.sh" \
  && echo "PASS  VOID message reports the vantage addresses" \
  || { echo "FAIL  VOID no longer reports vantage: a rotated egress and a drifting path are indistinguishable"; FAILED=1; }

[ "$FAILED" = 0 ] && { echo "ALL PASS"; exit 0; } || { echo "FAILURES"; exit 1; }
