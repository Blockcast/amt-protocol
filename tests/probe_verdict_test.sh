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
# Delete THIS guard alone and the result is 17 FAIL / 0 PASS -- the sole
# `want=nonzero` case, "N=1 unparseable receipt -> red", is held red by the
# `!= 127` clause below. Delete BOTH and it is 16 FAIL / 1 PASS: that case
# goes GREEN because 127 is nonzero, and it cannot tell "probe.sh rejected a
# corrupt receipt" from "probe.sh never ran". That vacuous pass is the real
# defect -- Ally's review of #25 (head 1e849975, Suggestion 4) stated it as a
# silent vacuous pass of the WHOLE suite, which does not reproduce.
#
# Counts are assertions, not cases: 13 `run_case` calls, but the two N=1 cases
# that pass `pcs != oops` each add two legacy-artifact assertions that emit
# only on failure -- hence 13 healthy, 17 broken. `grep -c FAIL` overcounts by
# one, matching the `FAILURES` summary line too: 18 with this guard alone
# removed, 17 with both removed.
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
  # would freeze an implementation detail rather than the behaviour. 127 is
  # excluded because it is the one nonzero code that means the subject never
  # produced a verdict of its own -- bash returns it both when probe.sh is
  # absent and when probe.sh runs but calls a missing binary (jq gone from the
  # image). A "must not pass" assertion is otherwise satisfied by a broken test
  # environment, which is the opposite of a positive control. Belt-and-braces
  # with the extraction guard above: that one catches the known cause, this one
  # catches any cause.
  if { [ "$want" = nonzero ] && [ "$got" != 0 ] && [ "$got" != 127 ]; } || [ "$got" = "$want" ]; then
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

[ "$FAILED" = 0 ] && { echo "ALL PASS"; exit 0; } || { echo "FAILURES"; exit 1; }
