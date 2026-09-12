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
#   Ally review of #25, Important (1)
#     The step used to exit with tunnel 1's status, so a healthy first tunnel
#     made an N-tunnel run green even when every later tunnel received nothing.
#     The verdict must be the aggregate.
#
#   Ally review of #25, Important (2)
#     TUNNELS=1 must remain artifact-compatible with the single `docker run`
#     this step replaced: consumers fetch `report.json` / `verbose.log` by name.
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
  local name=$1 tunnels=$2 pcs=$3 exits=$4 want=$5 got
  local dir; dir=$(mktemp -d -p "$WORK"); rm -rf "$WORK"/.claim.*
  ( cd "$dir"
    export TUNNELS=$tunnels PC_LIST=$pcs EXIT_LIST=$exits \
           RELAY=1.2.3.4 SOURCE=69.25.95.192 GROUP=232.1.1.60 TIMEOUT=5 PACKETS=3
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

run_case "N=1 timeout-exit1 but packet_count>0 -> green" 1 "412"     "1"   0
run_case "N=1 zero data -> red"                          1 "0"       "1"   1
run_case "N=2 first ok, second zero-data -> red"         2 "500,0"   "1,1" 1
run_case "N=2 both receiving -> green"                   2 "500,500" "1,1" 0
run_case "N=1 unparseable receipt -> red"                1 "oops"    "1"   nonzero

[ "$FAILED" = 0 ] && { echo "ALL PASS"; exit 0; } || { echo "FAILURES"; exit 1; }
