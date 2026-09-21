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

python3 - "$WORKFLOW" "$WORK/probe.sh" <<'PY'
import sys, yaml
wf, out = sys.argv[1], sys.argv[2]
steps = yaml.safe_load(open(wf))['jobs']['probe']['steps']
block = next(s['run'] for s in steps if 'run' in s and 'docker pull' in s['run'])
open(out, 'w').write(block)
PY

# Extraction is a PRECONDITION, not a case. It fails for reasons that have
# nothing to do with the verdict logic -- absent pyyaml, a renamed job, a step
# that no longer carries `docker pull` -- and without `set -e` the suite then
# runs every case against a missing probe.sh, scoring `bash: no such file`
# (127) as the result. 17 of 18 cases go red with a want/got line that reads
# like a verdict-logic regression, and the one `want=nonzero` case at :104
# goes GREEN, because 127 is nonzero: that case cannot tell "probe.sh rejected
# a corrupt receipt" from "probe.sh never ran". Abort instead of diagnosing it
# eighteen times. (Ally review of #25, head 1e849975, Suggestion 4 -- whose
# stated failure mode, a silent vacuous pass of the whole suite, does not
# reproduce: measured 17 FAIL / 1 PASS. The single vacuous pass is real.)
[ -s "$WORK/probe.sh" ] || { echo "ABORT: could not extract probe.sh from $WORKFLOW (pyyaml missing, or the 'docker pull' step moved)" >&2; exit 2; }

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

[ "$FAILED" = 0 ] && { echo "ALL PASS"; exit 0; } || { echo "FAILURES"; exit 1; }
