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
echo "{\"source\":\"$SOURCE\",\"group\":\"$GROUP\",\"packet_count\":$pc,\"outcome\":\"timeout\"}"
echo "handshake trace" >&2
exit "$ec"
EOF
chmod +x "$WORK/bin/docker"
export PATH="$WORK/bin:$PATH" STUB_DIR="$WORK"

FAILED=0
run_case() {
  local name=$1 tunnels=$2 pcs=$3 exits=$4 want=$5 k=${6:-1} got
  local dir; dir=$(mktemp -d -p "$WORK"); rm -rf "$WORK"/.claim.*
  ( cd "$dir"
    export TUNNELS=$tunnels PC_LIST=$pcs EXIT_LIST=$exits DISTINCT_SOURCE_IPS=$k \
           RELAY=1.2.3.4 SOURCE=69.25.95.192 GROUP=232.1.1.60 TIMEOUT=5 PACKETS=3
    # k=unset is the production shape: the variable is ABSENT and the `:-1`
    # default in the workflow decides k.
    [ "$k" = unset ] && unset DISTINCT_SOURCE_IPS
    bash "$WORK/probe.sh" ) >/dev/null 2>&1; got=$?

  # `want=nonzero` where the contract is only "must not pass": a corrupt receipt
  # dies at the (S,G) guard carrying jq's own exit code, and pinning that number
  # would freeze an implementation detail rather than the behaviour.
  if { [ "$want" = nonzero ] && [ "$got" != 0 ]; } || [ "$got" = "$want" ]; then
    echo "PASS  $name (exit $got)"
  else
    echo "FAIL  $name: want exit $want, got $got"; FAILED=1
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
# ADDRESS, so N>1 cannot establish fan-out. Both of these USED to be decided by
# packet_count -- "both receiving" was asserted GREEN here, which is the false
# positive Ally flagged, and "second zero-data" exited 1 with a message blaming
# delivery. Both are now VOID (91), decided before packet_count is consulted.
run_case "N=2 both receiving, k=1 -> void"               2 "500,500" "1,1" 91  1
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

# 2. Offer the clear step exactly those rows. Matching titles => both closed.
python3 - "$WORK/routed.titles" "$WORK/open.json" <<'PY'
import json, sys
titles = [t.rstrip('\n') for t in open(sys.argv[1]) if t.strip()]
json.dump([{'number': 101 + i, 'title': t} for i, t in enumerate(titles)], open(sys.argv[2], 'w'))
PY
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

# 3. Negative control: nothing open must close nothing. Without this, a clear
# step that closed whatever it found first would pass case 2 for free.
: >"$WORK/none.acts"
( probe_env
  export GH_LIST="$WORK/empty.json" GH_OUT="$WORK/none"
  bash "$WORK/clear.sh" ) >/dev/null 2>&1
if [ -s "$WORK/none.acts" ]; then
  echo "FAIL  clear step acted with no matching row open: $(cat "$WORK/none.acts")"; FAILED=1
else
  echo "PASS  clear step is a no-op when neither row is open"
fi

# 4. The clear step must be gated on BOTH a green run and a scheduled one: a
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

# Ally review at head 50f03ee, Suggestion (1). An EXCEEDED job timeout CANCELS
# the job, so `Route probe failure` never runs and a wedged probe files nothing
# at all -- the one failure direction this whole workflow exists to remove.
# The default is 360 min against a 15-minute cron.
PROBE_TIMEOUT=$(python3 -c "
import sys, yaml
print(yaml.safe_load(open(sys.argv[1]))['jobs']['probe'].get('timeout-minutes', 0))
" "$WORKFLOW")
if [ "$PROBE_TIMEOUT" -gt 0 ] && [ "$PROBE_TIMEOUT" -le 15 ]; then
  echo "PASS  probe job bounded at ${PROBE_TIMEOUT}m, inside the 15m cron interval"
else
  echo "FAIL  probe job timeout-minutes=$PROBE_TIMEOUT: must be 1..15 so a wedge cannot"
  echo "      outlive its cron interval and be cancelled before it can route"; FAILED=1
fi

[ "$FAILED" = 0 ] && { echo "ALL PASS"; exit 0; } || { echo "FAILURES"; exit 1; }
