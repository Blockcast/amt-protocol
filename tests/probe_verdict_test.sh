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
#   reorder = a REORDERING receipt: clean implausible, clean numeric
#          loss_ratio, correct source/group, full packet_count -- and
#          in_sequence at half of it. Every other guard passes, so the
#          in_sequence ratio guard is the only one that can fire. It is the
#          live receipt on run 36613263318 (BLO-33636, artifact
#          amt-verify-receipt) verbatim: loss_ratio 0.32420171254357943, 9
#          tracks, in_sequence 34115, received 46328 -- pair it with
#          packet_count 67248, MORE than its peers received.
#   clean<T> = a perfectly clean T-track stream: in_sequence = packet_count - T,
#          because a track's first arrival is never in-sequence (amt-verify
#          SeqTracker::observe), and received = packet_count. The shape a
#          short sample really has.
#   lost<G> = one track, G single-packet gaps: received = packet_count (a
#          gap-ending arrival IS received), in_sequence = packet_count - 1 - G,
#          loss_ratio = G / (G + received) as amt-verify computes it.
#   inseq<I> = 9 tracks, in_sequence I, received 9 + I, loss 0: a REORDERING
#          receipt whose other arrivals were behind the mark (in packet_count,
#          not in received). Sets in_sequence exactly, for the bar's boundary.
#   bigtracks = tracks > received, which no genuine receipt can carry.
#   notracks = otherwise clean mmtp with NO tracks field.
#   noinseq = mmtp with a clean loss_ratio and NO in_sequence at all. An absent
#          field must fail CLOSED; `null >= x` is false in jq, so the ratio
#          test would already refuse it -- the `type == "number"` conjunct is
#          what makes that refusal deliberate rather than incidental.
# A non-numeric token otherwise lands in the JSON verbatim and corrupts the
# receipt, which is the same `oops` mechanism PC_LIST already uses.
loss=$(echo "${LOSS_LIST:-}" | cut -d, -f"$n")
# An EMPTY receipt: the container died before writing (OOM-kill, evicted).
# The shell redirect still creates the file, so jq -s sees a valid input
# carrying ZERO values -- it does not error, the leg's array is simply one
# element short. That is what the `length == $n` count guard is for.
if [ "$pc" = empty ]; then echo "handshake trace" >&2; exit "$ec"; fi
# Healthy receipts carry in_sequence ~= packet_count (0.996..1.000 of
# packet_count, measured across 15 live receipts). Emit that by default so the
# ratio guard is a no-op for every pre-existing case, and let the sentinels
# below break it on purpose.
#
# received is DECOUPLED from packet_count on every sentinel: $rcv, above the
# sample floor (received >= 500 at THRESH 0.002), whatever packet_count says.
# A sentinel exists to be refused by ONE guard; a realistic received (<= its
# packet_count of 1) would have the floor refuse it too and hold nothing -- the
# zero-data case's `packet_count > 0` guard first of all. Only clean/lost/inseq,
# whose job is the floor and the bar, carry a received consistent with the rest.
rcv=1000
case "$loss" in
  ''|none) mmtp= ;;
  imp)     mmtp=',"mmtp":{"implausible":1,"loss_ratio":0,"tracks":1,"received":'"$rcv"',"in_sequence":'"$pc"'}' ;;
  noloss)  mmtp=',"mmtp":{"implausible":0,"tracks":1,"received":'"$rcv"',"in_sequence":'"$pc"'}' ;;
  reorder) mmtp=',"mmtp":{"implausible":0,"loss_ratio":0.32420171254357943,"tracks":9,"received":46328,"in_sequence":34115}' ;;
  noinseq) mmtp=',"mmtp":{"implausible":0,"loss_ratio":0.0015,"tracks":1,"received":'"$rcv"'}' ;;
  # in_sequence PRESENT but not a number. jq orders string > number, so
  # `"n/a" >= 60300` is TRUE and the ratio conjunct waves this through -- the
  # `type == "number"` conjunct is the only one that can refuse it. Absence
  # (noinseq) cannot hold that conjunct, because `null >= number` is false and
  # the ratio test catches it first. Two sentinels because two conjuncts.
  strinseq) mmtp=',"mmtp":{"implausible":0,"loss_ratio":0.0015,"tracks":1,"received":'"$rcv"',"in_sequence":"n/a"}' ;;
  # A receipt for a DIFFERENT source, or a DIFFERENT group, with an otherwise
  # clean mmtp block, so one conjunct of the per-leg `.source == $s and
  # .group == $g` clause is the only guard that sees it. Two sentinels, not one
  # that varies both: a receipt wrong in both fields fails each conjunct, so
  # either conjunct alone would still void it and the other would go unheld.
  badsrc)  SOURCE=198.51.100.9; mmtp=',"mmtp":{"implausible":0,"loss_ratio":0.0015,"tracks":1,"received":'"$rcv"',"in_sequence":'"$pc"'}' ;;
  badgrp)  GROUP=232.9.9.9; mmtp=',"mmtp":{"implausible":0,"loss_ratio":0.0015,"tracks":1,"received":'"$rcv"',"in_sequence":'"$pc"'}' ;;
  clean*)  t=${loss#clean}; mmtp=',"mmtp":{"implausible":0,"loss_ratio":0,"tracks":'"$t"',"received":'"$pc"',"in_sequence":'"$((pc - t))"'}' ;;
  lost*)   g=${loss#lost}; mmtp=',"mmtp":{"implausible":0,"loss_ratio":'"$(jq -n "$g / ($g + $pc)")"',"tracks":1,"received":'"$pc"',"in_sequence":'"$((pc - 1 - g))"'}' ;;
  inseq*)  i=${loss#inseq}; mmtp=',"mmtp":{"implausible":0,"loss_ratio":0,"tracks":9,"received":'"$((9 + i))"',"in_sequence":'"$i"'}' ;;
  bigtracks) mmtp=',"mmtp":{"implausible":0,"loss_ratio":0.0015,"tracks":'"$((rcv + 1))"',"received":'"$rcv"',"in_sequence":'"$pc"'}' ;;
  notracks) mmtp=',"mmtp":{"implausible":0,"loss_ratio":0.0015,"received":'"$rcv"',"in_sequence":'"$pc"'}' ;;
  *)       mmtp=",\"mmtp\":{\"implausible\":0,\"loss_ratio\":$loss,\"tracks\":1,\"received\":$rcv,\"in_sequence\":$pc}" ;;
esac
echo "{\"source\":\"$SOURCE\",\"group\":\"$GROUP\",\"packet_count\":$pc,\"outcome\":\"timeout\"$mmtp}"
echo "handshake trace" >&2
exit "$ec"
EOF
chmod +x "$WORK/bin/docker"
# The delta legs curl api.ipify.org once each for their per-leg vantage
# receipt. Stub it: a unit test must not depend on egress, and the real call
# would also be the slowest thing in this file by two orders of magnitude.
#
# IP_LIST is indexed by $LEG, because the cross-vantage design makes the
# address a VARIABLE the verdict judges rather than a constant it records:
# three distinct addresses is the licence to compare the legs at all. Unset (as
# it is for every probe case) it falls back to the single constant those cases
# were written against, so their behaviour is unchanged.
cat >"$WORK/bin/curl" <<'EOF'
#!/usr/bin/env bash
if [ -n "${IP_LIST:-}" ]; then echo "$IP_LIST" | cut -d, -f"${LEG:-1}"; else echo "203.0.113.7"; fi
EOF
chmod +x "$WORK/bin/curl"
# Each leg stamps a start and an end with `date -u +%s`, and the verdict
# intersects the three windows. Stubbed the legs would start and finish inside
# one second, so every window would be a POINT and the three-way overlap would
# be zero -- which is the "legs never ran at the same time" VOID. Every
# receipt-level case would go red for a reason that has nothing to do with the
# receipts. TIME_LIST supplies the six stamps (start1,end1,...,end3) instead.
#
# mkdir is the same atomic claim the docker stub uses: it succeeds on a leg's
# FIRST call (the start stamp) and fails on its second (the end stamp), so the
# stub needs no counter file it could race on. Falls through to the real date
# for every other caller and for an unset TIME_LIST.
cat >"$WORK/bin/date" <<'EOF'
#!/usr/bin/env bash
if [ -n "${TIME_LIST:-}" ] && [ "${1:-}" = "-u" ] && [ "${2:-}" = "+%s" ]; then
  f=$((2 * ${LEG:-1} - 1))
  mkdir "$STUB_DIR/.date.${LEG:-1}" 2>/dev/null || f=$((f + 1))
  echo "$TIME_LIST" | cut -d, -f"$f"
  exit 0
fi
exec /bin/date "$@"
EOF
chmod +x "$WORK/bin/date"
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
# BLO-33636 AC 2 (AMENDED 2026-09-30): the fan-out loss DELTA control, now
# CONCURRENT CROSS-VANTAGE. The sequential same-vantage bracket is withdrawn as
# structurally invalid -- it required the control leg to share a source address
# with the treatment leg AND be unaffected by it, and the relay keys tunnel
# state on the source address, so the control was coupled to the treatment
# through the mechanism under test.
#
# The shipped shell is now THREE blocks in three jobs (preflight / leg /
# verdict), because a matrix is the only way to get a leg its own runner and
# therefore its own egress address. All three are extracted, and the driver
# below stitches them in the order a real run executes them -- so every case
# still exercises the shipped shell rather than a copy that can drift, and
# every pre-existing case keeps its signature and its expected exit code.
# ---------------------------------------------------------------------------
python3 - "$WORKFLOW" "$WORK" <<'PY'
import sys, yaml
wf, work = sys.argv[1], sys.argv[2]
jobs = yaml.safe_load(open(wf))['jobs']
def block(job, needle):
    return next(s['run'] for s in jobs[job]['steps']
                if 'run' in s and needle in s['run'])
open(work + '/preflight.sh', 'w').write(block('loss-delta-preflight', 'MAX_TUNNELS'))
open(work + '/leg.sh',       'w').write(block('loss-delta',           'docker pull'))
open(work + '/dverdict.sh',  'w').write(block('loss-delta-verdict',   'fanout_loss_signal'))
PY
for f in preflight leg dverdict; do
  [ -s "$WORK/$f.sh" ] || { echo "ABORT: could not extract $f.sh from $WORKFLOW (a 'loss-delta*' job renamed, or its step moved)" >&2; exit 2; }
  # PARSE the block before running any case against it. These blocks embed long
  # jq programs inside shell SINGLE quotes, so one apostrophe in an English
  # word closes the quote and bash reparses the rest of the jq as commands.
  # That fails with `syntax error near unexpected token else` pointing at a
  # line nowhere near the apostrophe, and -- because a syntax error is exit 2
  # -- it turns EVERY case red at once with a want/got line that reads like a
  # verdict regression. Measured while writing this design: 36 cases, one
  # apostrophe. Diagnose it once, here, by name.
  bash -n "$WORK/$f.sh" 2>/dev/null \
    || { echo "ABORT: $f.sh is not valid bash -- look for an apostrophe inside a single-quoted jq program:" >&2
         bash -n "$WORK/$f.sh"; exit 2; }
done

# run_delta_case <name> <N> <pcs> <losses> <timeout> <want> [<reason>]
#
# PACKETS (the dispatch packet_count) is only handed to the stubbed docker, so
# every receipt-level case runs at 100000, clear of the up-front sample floor.
# The packet_count boundary cases set it per call: CASE_PACKETS=<v> run_delta_case ...
# CASE_IPS and CASE_TIMES do the same for the two guards this design added.
#
# <reason>, when given, must appear in the output: several VOIDs share exit 91,
# and a case about one cause must not go green on the other.
#
# PC_LIST/LOSS_LIST are FLAT across all three legs, in leg order: index 1 is
# leg 1 (N=1), 2..N+1 are the treatment leg, N+2 is leg 3. Within the treatment
# leg the N concurrent stubs claim indices in a racy order, but every assertion
# here is order-independent by construction -- a mean does not care, and one
# bad receipt invalidates the leg whichever slot it lands in.
#
# The legs run SEQUENTIALLY here while being CONCURRENT in production, and that
# is not a fidelity gap: the leg block's own behaviour does not depend on its
# siblings, and the only thing concurrency buys -- three distinct vantages
# whose windows overlap -- is a property of the ARTIFACTS, which CASE_IPS and
# CASE_TIMES set directly. Simulating real parallelism would test the harness.
run_delta_case() {
  local name=$1 n=$2 pcs=$3 losses=$4 tmo=$5 want=$6 reason=${7:-} got
  local dir; dir=$(mktemp -d -p "$WORK"); rm -rf "$WORK"/.claim.* "$WORK"/.date.*
  ( cd "$dir"
    export TUNNELS=$n PC_LIST=$pcs LOSS_LIST=$losses EXIT_LIST=1,1,1,1,1,1,1,1 \
           RELAY=1.2.3.4 SOURCE=69.25.95.192 GROUP=232.1.1.60 \
           TIMEOUT=$tmo PACKETS=${CASE_PACKETS-100000} \
           IP_LIST=${CASE_IPS-203.0.113.1,203.0.113.2,203.0.113.3} \
           TIME_LIST=${CASE_TIMES-100,160,100,160,100,160}
    # Preflight is a GATE, not a step: on rejection the legs never run, and its
    # exit code is the run's. Without the `|| exit` a rejected dispatch would
    # fall through to three legs and a verdict, and the 92 cases would score
    # whatever the verdict happened to say.
    bash "$WORK/preflight.sh" >out.log 2>&1 || exit $?
    for leg in 1 2 3; do
      # The matrix's `include`, by hand: legs 1 and 3 are the N=1 floor pair,
      # leg 2 is the treatment.
      if [ "$leg" = 2 ]; then export LEG=$leg N=$TUNNELS; else export LEG=$leg N=1; fi
      # `|| true`: the leg block is contracted never to fail on a measurement
      # outcome, and a leg that DID fail must still reach the verdict as a
      # missing artifact rather than aborting the case -- that is the shape the
      # verdict's "did not produce three legs" guard exists to report.
      bash "$WORK/leg.sh" >>out.log 2>&1 || true
    done
    bash "$WORK/dverdict.sh" >>out.log 2>&1
  ); got=$?
  if [ "$got" != "$want" ]; then
    echo "FAIL  $name: want exit $want, got $got"; FAILED=1
    sed -n '1,40p' "$dir/out.log" | sed 's/^/      /'
  elif [ -n "$reason" ] && ! grep -qF "$reason" "$dir/out.log"; then
    echo "FAIL  $name: exit $got, but no '$reason' in the output"; FAILED=1
    grep -F '::error::' "$dir/out.log" | sed 's/^/      /'
  else
    echo "PASS  $name (exit $got)"
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

# BLO-33636. A REORDERING receipt: every existing guard passes it. implausible
# is 0, the source and group are right, packet_count is FULL -- higher than its
# peers on the live run, in fact -- and loss_ratio is a clean float. It is just
# a wrong one: 0.3242, because the sequence space was read twice rather than a
# third of the stream being lost. in_sequence is the only field that dissents,
# at half of packet_count against 0.996..1.000 of packet_count on every healthy
# receipt. It is run 36613263318's receipt.
#
# ⚠ BOTH floor legs carry it, and that is the whole point of the case. With the
# corruption in ONE leg the noise term blows past the threshold and the run
# VOIDs anyway -- exit 91 with or without the guard, so the case is green on a
# reverted guard and holds nothing. Mutation testing caught exactly that here,
# on a case whose own comment had already noticed the exit codes collide and
# shipped it regardless. Corrupt BOTH floors with the SAME value and the noise
# term goes to ZERO: the run then reports a confident PASS off a 32% baseline.
# That is the shape a shared upstream reordering episode actually produces,
# and it is the one that is dangerous rather than merely noisy.
run_delta_case "reordering receipts fake a quiet floor -> VOID, not PASS" \
  3 67248,67000,67000,67000,67248 reorder,0.0015,0.0015,0.0015,reorder 30 91

# The same guard's other half, and it needs its own sentinel because the two
# conjuncts mask each other under mutation: a missing in_sequence is refused by
# the ratio test (`null >= number` is false) whichever conjunct you revert. A
# STRING is not -- jq orders string > number, so the ratio test says true and
# only `type == "number"` can refuse it.
run_delta_case "non-numeric in_sequence -> VOID" \
  3 67000,67000,67000,67000,67000 0.001,0.0015,strinseq,0.0015,0.001 30 91

# And the plain absent-field case. It holds NEITHER conjunct alone -- revert
# either one and the other still refuses it -- so it guards only against both
# going at once. The conjuncts' own witnesses are `reorder` (ratio) and
# `strinseq` (type).
run_delta_case "receipt with no in_sequence field -> VOID" \
  3 67000,67000,67000,67000,67000 0.001,0.0015,noinseq,0.0015,0.001 30 91

# Ally review of #49 (head fd9591ea), Important. Clean SHORT samples, the shape
# a default dispatch (PACKETS=3) produced before the up-front refusal below, and
# a deadline that expires short of packet_count still does: in_sequence is
# packet_count - tracks exactly, because no track's first arrival is
# in-sequence. The in_sequence bar now clears them (the old 0.9 x packet_count
# refused both, 3 < 3.6 and 3 < 5.4) -- but they are still VOID, for the right
# reason. One lost packet in 4 reads as 1/5 = 0.2, a hundred times THRESH, and
# a lossy short leg failed the bar besides (a gap-ending arrival is not
# in-sequence): short samples returned PASS or VOID and never FAIL. The sample
# floor refuses them by name, before they can PASS. Same figures as
# amt-verify's own fixtures contiguous_sequence_is_zero_loss and
# tracks_are_counted_independently.
run_delta_case "clean short sample, 4 packets / 1 track -> VOID, too short" \
  3 4,4,4,4,4 clean1,clean1,clean1,clean1,clean1 30 91 "sample too short"
run_delta_case "clean short sample, 6 packets / 3 tracks -> VOID, too short" \
  3 6,6,6,6,6 clean3,clean3,clean3,clean3,clean3 30 91 "sample too short"

# The floor's own boundary, derived from THRESH = 0.002: one lost packet reads
# as 1/(received + 1), so received 499 reads 0.002 (not below) and 500 reads
# 0.001996. Kills an off-by-one in either direction.
run_delta_case "received 499, one short of the floor -> VOID, too short" \
  3 499,499,499,499,499 clean1,clean1,clean1,clean1,clean1 30 91 "sample too short"
run_delta_case "received 500, at the floor -> PASS" \
  3 500,500,500,500,500 clean1,clean1,clean1,clean1,clean1 30 0

# Ally review of #49 (head 1817b412), Important: the floor's two quantifiers
# were not mutation-held. The per-receipt floor is `all`: one coarse receipt
# among long ones must still VOID the leg, or it contributes a mean it cannot
# resolve (`any` turned this VOID into PASS). The per-leg check is `any`: one
# short leg among three must VOID by name (`all` fell through to arithmetic on
# the string "short" and VOIDed as "verdict arithmetic failed").
run_delta_case "one short receipt among long ones -> VOID, too short" \
  3 1000,1000,1000,4,1000 clean1,clean1,clean1,clean1,clean1 30 91 "sample too short"
run_delta_case "one short leg among three -> VOID, too short" \
  3 4,1000,1000,1000,1000 clean1,clean1,clean1,clean1,clean1 30 91 "sample too short"

# Above the floor, the bar must still subtract tracks. 100 tracks at 600
# packets: in_sequence is 500, which clears 0.9 x (600 - 100) = 450 and would
# be refused by 0.9 x 600 = 540. tracks has to exceed a tenth of packet_count
# for the subtraction to decide anything, which the floor makes 56+ tracks.
run_delta_case "clean 600 packets / 100 tracks -> PASS (bar subtracts tracks)" \
  3 600,600,600,600,600 clean100,clean100,clean100,clean100,clean100 30 0

# And FAIL is reachable once the sample can resolve it -- the verdict a short
# sample could never return. Clean N=1 floors at 1000 packets; each N-leg
# receipt lost 3 of 1003, loss 0.00299. signal 0.00299 >= 0.002 over noise 0.
run_delta_case "above the floor, fan-out loses packets -> FAIL" \
  3 1000,1000,1000,1000,1000 clean1,lost3,lost3,lost3,clean1 30 1

# The bar's boundary at the live receipt's 9 tracks: 0.9 x (1009 - 9) = 900.
# 899 VOIDs, 900 passes. Kills the loosening mutants (0.9 -> 0.51 reads 510;
# 2 x tracks reads 891.9) with the first, and dropping tracks (908.1) with the
# second. received is 9 + in_sequence, so both clear the floor.
run_delta_case "in_sequence 899 against a bar of 900 -> VOID" \
  3 1009,1009,1009,1009,1009 inseq899,inseq899,inseq899,inseq899,inseq899 30 91 "no usable mean"
run_delta_case "in_sequence 900 against a bar of 900 -> PASS" \
  3 1009,1009,1009,1009,1009 inseq900,inseq900,inseq900,inseq900,inseq900 30 0

# tracks > received. No genuine receipt carries it, since every track's first
# arrival is received, and it drives the bar negative: 0.9 x (1 - 1001) waves
# any in_sequence through. `tracks <= received` is the only guard that sees it.
run_delta_case "tracks exceeds received -> VOID" \
  3 1,1,1,1,1 0.001,0.0015,bigtracks,0.0015,0.001 30 91 "no usable mean"

# The bar subtracts tracks, so tracks must be a number. Absent, `// 0` restores
# the strict packet_count bar -- which this receipt (in_sequence = packet_count)
# clears -- so the `tracks | type == "number"` conjunct is the only thing that
# refuses it.
run_delta_case "receipt with no tracks field -> VOID" \
  3 67000,67000,67000,67000,67000 0.001,0.0015,notracks,0.0015,0.001 30 91

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

# The within-vantage spread needs the same count guard as the mean. The leg's
# verdict is already VOID here (its mean is null), so the exit code cannot see
# it -- but the spread is harvested ACROSS runs into a population, and without
# `length == $n` the two survivors (0.0015, 0.0095) publish 0.008 under this
# leg's N=3 with nothing on the line saying the reading is short.
run_delta_case "empty receipt -> within-vantage spread null, not a spread over the survivors" \
  3 1,1,empty,1,1 0.001,0.0015,0.0015,0.0095,0.001 30 91 "leg2_within_vantage_spread=null"
# And it is still computed when every receipt counts. Without this the case
# above is satisfied by a spread that is always null.
run_delta_case "every receipt counts -> within-vantage spread reported" \
  3 1,1,1,1,1 0.001,0.001,0.002,0.001,0.001 30 0 "leg2_within_vantage_spread=0.001"

# Ally review of #49 (head 0a907563), Important. packet_count is shared with
# oneshot and defaults to 3, but received <= packet_count and the sample floor
# needs received >= floor(1 / THRESH) = 500 -- so a packet_count below 500 can
# only VOID, after three full legs. Refused up front instead. The receipts are
# the shape such a dispatch would really produce, so without the refusal each
# case VOIDs (91) as "sample too short" rather than passing by accident; 500 is
# the boundary, and PASSes. The `abc` case's receipts clear the floor and would
# PASS, so the integer guard is the only thing that stops it reaching amt-verify.
CASE_PACKETS=3 run_delta_case "packet_count=3 (the shared default) -> rejected" \
  3 3,3,3,3,3 clean1,clean1,clean1,clean1,clean1 30 92 "below the sample floor of 500"
CASE_PACKETS=499 run_delta_case "packet_count=499, one short of the floor -> rejected" \
  3 499,499,499,499,499 clean1,clean1,clean1,clean1,clean1 30 92 "below the sample floor of 500"
CASE_PACKETS=500 run_delta_case "packet_count=500, at the floor -> not refused (PASS)" \
  3 500,500,500,500,500 clean1,clean1,clean1,clean1,clean1 30 0
CASE_PACKETS=abc run_delta_case "non-integer packet_count -> rejected" \
  3 1000,1000,1000,1000,1000 clean1,clean1,clean1,clean1,clean1 30 92 "packet_count must be an integer"

# N=1 makes the middle leg a control leg: signal is 0 by construction and the
# run would report PASS having measured nothing. Rejected at the boundary.
run_delta_case "N=1 is a vacuous green -> rejected" \
  1 1,1,1 0.001,0.001,0.001 30 92
run_delta_case "non-integer N -> rejected" \
  abc 1,1,1 0.001,0.001,0.001 30 92

# The legs are CONCURRENT now, so the job budget is 1x timeout, not 3x. Reject
# at the boundary rather than letting the job cap CANCEL a leg mid-join: a
# cancelled leg emits no artifact, which the verdict can only report as a
# missing measurement rather than a rejected input. 780 is the boundary and
# must be ACCEPTED -- without that second case the check is satisfied by a
# guard that rejects everything.
run_delta_case "timeout over the job budget -> rejected" \
  3 1,1,1,1,1 0.001,0.001,0.001,0.001,0.001 800 92 "exceeds the 780s budget"
run_delta_case "timeout at the job budget -> accepted" \
  3 1000,1000,1000,1000,1000 clean1,clean1,clean1,clean1,clean1 780 0

# ---------------------------------------------------------------------------
# The two guards the 2026-09-30 concurrent cross-vantage design ADDS. Both are
# structural: they decide whether the run was a valid experiment at all, so
# they are checked BEFORE the means and each needs its own witness.
# ---------------------------------------------------------------------------

# DISTINCT VANTAGES. Two legs on one address are not a control pair, they ARE
# the collision this AC measures -- so a run that drew a duplicate egress has
# rebuilt the withdrawn same-vantage bracket by accident. The receipts here are
# perfectly clean and would otherwise PASS, so the distinctness guard is the
# only thing that can refuse them.
CASE_IPS=203.0.113.1,203.0.113.1,203.0.113.3 \
run_delta_case "two legs share an egress address -> VOID, not PASS" \
  3 1000,1000,1000,1000,1000 clean1,clean1,clean1,clean1,clean1 30 91 "three distinct, known egress addresses"
# And the FLOOR PAIR specifically: legs 1 and 3 are the noise term, so a
# collision between the two of them makes the floor a measurement of the defect
# rather than of the path. Distinct from the case above, which collides a floor
# leg with the treatment leg.
CASE_IPS=203.0.113.1,203.0.113.2,203.0.113.1 \
run_delta_case "the two floor legs share an egress address -> VOID" \
  3 1000,1000,1000,1000,1000 clean1,clean1,clean1,clean1,clean1 30 91 "three distinct, known egress addresses"
# An UNKNOWN vantage must fail CLOSED. `unavailable` is what the leg writes
# when the ipify curl fails, and three of them are `unique | length == 1` so
# the distinctness test catches that shape -- but ONE among two real addresses
# is `unique | length == 3` and passes it. The explicit `any(. == "unavailable")`
# conjunct is the only guard that sees this one: an address that could not be
# read cannot be shown distinct from the other two.
CASE_IPS=203.0.113.1,unavailable,203.0.113.3 \
run_delta_case "one vantage unreadable -> VOID, fails closed" \
  3 1000,1000,1000,1000,1000 clean1,clean1,clean1,clean1,clean1 30 91 "three distinct, known egress addresses"

# OVERLAPPING WINDOWS. A floor that did not run WHILE the signal ran is the
# withdrawn sequential design wearing this one's label -- which is exactly what
# a matrix leg delayed by a queued runner produces, silently, with three
# distinct addresses and clean receipts. Legs here run 100-160, 200-260,
# 300-360: no shared instant.
CASE_TIMES=100,160,200,260,300,360 \
run_delta_case "legs ran in sequence, not concurrently -> VOID" \
  3 1000,1000,1000,1000,1000 clean1,clean1,clean1,clean1,clean1 30 91 "never ran at the same time"
# TOUCHING windows are not overlapping windows. max(starts)=160, min(ends)=160,
# so the intersection is a single instant of zero length -- the boundary the
# `<= 0` test exists for, and the one a `< 0` test would wave through.
CASE_TIMES=100,160,160,220,100,220 \
run_delta_case "windows touch but do not overlap -> VOID" \
  3 1000,1000,1000,1000,1000 clean1,clean1,clean1,clean1,clean1 30 91 "never ran at the same time"
# One second of genuine overlap is enough to ask the question. Without this the
# two cases above are satisfied by a guard that voids every run.
CASE_TIMES=100,161,160,220,100,220 \
run_delta_case "one second of three-way overlap -> PASS" \
  3 1000,1000,1000,1000,1000 clean1,clean1,clean1,clean1,clean1 30 0

# The verdict must assemble the legs BY INDEX, not by the order the artifact
# files happen to glob in.
#
# ⚠ This case is written AROUND run_delta_case on purpose, and the first
# version of it was INERT. Driven through the stitched driver the legs are
# written as leg-1/leg-2/leg-3, so the `leg-*.json` glob yields index order
# anyway and `sort_by(.leg)` can be deleted with the suite still green --
# mutation testing caught exactly that. A case that cannot fail when the guard
# is removed is documentation.
#
# The contract is real even though the current filenames satisfy it by luck:
# rename the artifacts to something descriptive -- floor-a / floor-b /
# treatment, an obvious future tidy-up -- and lexical order becomes 1, 3, 2,
# putting a FLOOR leg at $m[1] and computing the signal against the treatment.
# So the files here are named so that lexical order (a, b, c) is legs 3, 1, 2.
# Leg 2 is the only lossy one: by index the signal is 0.00299 and the run
# FAILs; read in glob order the legs are misindexed and it VOIDs instead.
delta_glob_order_case() {
  local dir; dir=$(mktemp -d -p "$WORK"); local got
  ( cd "$dir"
    printf '%s\n' '{"leg":3,"n":1,"mean":0.0,"ip":"203.0.113.3","start":100,"end":160}' >leg-a.json
    printf '%s\n' '{"leg":1,"n":1,"mean":0.0,"ip":"203.0.113.1","start":100,"end":160}' >leg-b.json
    printf '%s\n' '{"leg":2,"n":3,"mean":0.00299,"ip":"203.0.113.2","start":100,"end":160}' >leg-c.json
    TIMEOUT=30 TUNNELS=3 bash "$WORK/dverdict.sh" >out.log 2>&1
  ); got=$?
  if [ "$got" = 1 ]; then
    echo "PASS  verdict orders legs by index, not by glob order (exit $got)"
  else
    echo "FAIL  verdict reads legs in glob order: want exit 1 (FAIL), got $got"; FAILED=1
    sed -n '1,20p' "$dir/out.log" | sed 's/^/      /'
  fi
}
delta_glob_order_case

# The verdict checks the N each artifact CARRIES, not only the matrix source.
# Here the treatment leg ran N=1 -- a matrix edit that dropped fan-out. Every
# other guard passes (three indices, three distinct vantages, full overlap,
# clean means), so without the shape arm this is a PASS having measured
# nothing: signal 0 by construction, the vacuous green preflight refuses N=1
# to prevent. The matrix assertion below cannot see it; it reads the source.
delta_leg_shape_case() {
  local dir; dir=$(mktemp -d -p "$WORK"); local got
  ( cd "$dir"
    for leg in 1 2 3; do
      printf '{"leg":%s,"n":1,"mean":0.0,"ip":"203.0.113.%s","start":100,"end":160}\n' "$leg" "$leg" >"leg-$leg.json"
    done
    TIMEOUT=30 TUNNELS=3 bash "$WORK/dverdict.sh" >out.log 2>&1
  ); got=$?
  if [ "$got" = 91 ] && grep -qF "not floor/treatment/floor" "$dir/out.log"; then
    echo "PASS  treatment leg carrying n=1 -> VOID, not a vacuous PASS (exit $got)"
  else
    echo "FAIL  treatment leg carrying n=1: want exit 91 naming the leg shape, got $got"; FAILED=1
    sed -n '1,20p' "$dir/out.log" | sed 's/^/      /'
  fi
}
delta_leg_shape_case

# A leg that never produced an artifact at all -- a cancelled or evicted runner.
# Distinct from every receipt-level VOID above: there is no leg file to judge,
# so the count-and-index guard is the only thing that sees it, and it must say
# "missing measurement" rather than naming a receipt field that was never read.
delta_missing_leg_case() {
  local dir; dir=$(mktemp -d -p "$WORK"); rm -rf "$WORK"/.claim.* "$WORK"/.date.*
  local got
  ( cd "$dir"
    export TUNNELS=3 PC_LIST=1000,1000,1000,1000,1000 \
           LOSS_LIST=clean1,clean1,clean1,clean1,clean1 EXIT_LIST=1,1,1,1,1,1,1,1 \
           RELAY=1.2.3.4 SOURCE=69.25.95.192 GROUP=232.1.1.60 \
           TIMEOUT=30 PACKETS=100000 \
           IP_LIST=203.0.113.1,203.0.113.2,203.0.113.3 \
           TIME_LIST=100,160,100,160,100,160
    bash "$WORK/preflight.sh" >out.log 2>&1 || exit $?
    for leg in 1 2; do
      if [ "$leg" = 2 ]; then export LEG=$leg N=$TUNNELS; else export LEG=$leg N=1; fi
      bash "$WORK/leg.sh" >>out.log 2>&1 || true
    done
    bash "$WORK/dverdict.sh" >>out.log 2>&1
  ); got=$?
  if [ "$got" = 91 ] && grep -qF "three legs indexed 1,2,3" "$dir/out.log"; then
    echo "PASS  leg 3 never reported (cancelled runner) -> VOID, missing measurement (exit $got)"
  else
    echo "FAIL  leg 3 never reported: want exit 91 naming the missing leg, got $got"; FAILED=1
    sed -n '1,40p' "$dir/out.log" | sed 's/^/      /'
  fi
}
delta_missing_leg_case

# Legs 1 and 3 are the N=1 floor pair and leg 2 is the treatment. A matrix that
# puts N=1 anywhere but 1 and 3 computes the signal against the wrong term. A
# source-level assertion on the workflow because the stitched driver above sets
# LEG/N itself and so cannot witness the matrix at all.
python3 - "$WORKFLOW" <<'PY' && echo "PASS  delta matrix is floor/treatment/floor at legs 1/2/3" \
  || { echo "FAIL  delta matrix legs are no longer N=1 / N / N=1 at 1 / 2 / 3"; FAILED=1; }
import sys, yaml
m = yaml.safe_load(open(sys.argv[1]))['jobs']['loss-delta']['strategy']['matrix']['include']
want = [{'leg': 1, 'n': 1}, {'leg': 3, 'n': 1}]
got = [e for e in m if e['n'] == 1]
sys.exit(0 if len(m) == 3 and got == want and '${{' in str(
    next(e['n'] for e in m if e['leg'] == 2)) else 1)
PY

# The verdict gate reads the preflight job's result, and that job id has
# HYPHENS. A bare property name in the Actions expression grammar is
# [a-zA-Z_][a-zA-Z0-9_]*, so `needs.loss-delta-preflight.result` is parsed as
# subtraction, not as a lookup -- it evaluates to something that is not the
# preflight result, with no workflow error to say so, and the gate that keeps a
# rejected dispatch from being re-reported as a VOID quietly stops working.
# Bracket syntax is the only form that survives a hyphen.
python3 - "$WORKFLOW" <<'PY' && echo "PASS  verdict gate reads preflight via bracket syntax (hyphen-safe)" \
  || { echo "FAIL  verdict gate uses dotted syntax on a hyphenated job id: the expression parses as subtraction"; FAILED=1; }
import sys, yaml, re
g = yaml.safe_load(open(sys.argv[1]))['jobs']['loss-delta-verdict']['if']
sys.exit(0 if "needs['loss-delta-preflight']" in g or 'needs["loss-delta-preflight"]' in g
         else 1)
PY

# fail-fast would CANCEL the surviving legs the moment one failed, and a
# cancelled leg uploads no artifact -- so a single dead leg would destroy the
# vantage and window evidence the verdict needs to say WHY the run is void.
python3 -c "
import sys, yaml
s = yaml.safe_load(open(sys.argv[1]))['jobs']['loss-delta']['strategy']
sys.exit(0 if s.get('fail-fast') is False else 1)" "$WORKFLOW" \
  && echo "PASS  a dead leg does not cancel its siblings" \
  || { echo "FAIL  loss-delta matrix no longer sets fail-fast: false"; FAILED=1; }

# The threshold decides the result, so a dispatch caller must not be able to
# supply it. Same contract as DISTINCT_SOURCE_IPS in the probe job. Asserted on
# BOTH blocks that carry it: preflight derives the sample floor from it and the
# verdict applies it, so either one becoming an input reopens the hole.
for blk in preflight dverdict; do
  grep -q '^ *THRESH=0.002' "$WORK/$blk.sh" \
    && echo "PASS  delta threshold is a constant in $blk, not an input" \
    || { echo "FAIL  delta threshold is no longer a hardcoded constant in $blk"; FAILED=1; }
done

# A wide floor sends the reader somewhere, and where depends on the vantages --
# so a VOID that does not report them is a dead end. Live run 36568716671 hit
# the same-vantage case under the withdrawn design (one IP across all three
# legs, floor 0.0088). Source-level because the exit code is 91 either way.
grep -q 'vantages=\$vantage' "$WORK/dverdict.sh" \
  && echo "PASS  VOID message reports the vantage addresses" \
  || { echo "FAIL  VOID no longer reports the vantages: a drifting path and a collided egress are indistinguishable"; FAILED=1; }

# The ruling's condition 4: no PASS is credited until the floor is characterized
# over >= 5 runs. That is a claim about a POPULATION, so each run has to emit
# its own reading in a form a later reader can harvest without having read the
# workflow. A PASS that does not say it is provisional invites exactly the
# single-reading credit the condition forbids.
grep -q 'floor_legs=' "$WORK/dverdict.sh" \
  && echo "PASS  every run emits its floor reading for the >=5-run distribution" \
  || { echo "FAIL  the run no longer emits floor_legs: the floor distribution cannot be harvested"; FAILED=1; }
grep -q 'NOT YET A CREDITED PASS' "$WORK/dverdict.sh" \
  && echo "PASS  a PASS states it is one reading, not a credited pass" \
  || { echo "FAIL  PASS no longer states the >=5-run floor-characterization condition"; FAILED=1; }

# The within-vantage control. The N>1 leg runs its tunnels from ONE address at
# one instant, so their disagreement is what the cross-vantage floor ASSUMES is
# the whole story -- and on run 36664230865 the two differed by ~265x in the
# same minute (7.6e-6 within vantage against a 2.02e-3 cross-vantage floor).
# Without this term a wide floor cannot be told apart from a noisy night, which
# is the question the >=5-run characterization exists to answer.
grep -q 'within_vantage_spread=' "$WORK/dverdict.sh" \
  && echo "PASS  every run emits the within-vantage control beside the floor" \
  || { echo "FAIL  within_vantage_spread no longer emitted: a wide floor cannot be told from a noisy night"; FAILED=1; }
# It must be a REPORTED term, never a verdict arm. Gating it needs a constant,
# and the ruling that commissioned this design reserves new constants to data.
# A `spread` appearing in the verdict jq would be that constant smuggled in.
#
# STRUCTURAL, not a regex over comparison syntax. The first version matched only
# a jq VARIABLE named $sp..., so a field comparison -- `($l[1].spread >= x)` --
# or an alias -- `.spread as $w | ... $w >= x` -- slipped through it (Ally,
# head 46e839d4). Every verdict arm lives in the one jq program assigned to
# `verdict=`, and that program has no reason to read `spread` at all, so assert
# exactly that. The comparison regex stays for the rest of the block, where a
# shell-side override of $v would have to compare the term to something.
python3 - "$WORK/dverdict.sh" <<'PY' \
  && echo "PASS  within-vantage spread is reported, not gated" \
  || { echo "FAIL  within-vantage spread became a verdict arm: that is a new constant chosen by the instrument author"; FAILED=1; }
import re, sys
src = open(sys.argv[1]).read()
# The program is single-quoted and apostrophe-free (bash -n above), so the
# first quote after `jq -rn ...` closes it.
m = re.search(r"verdict=\$\(jq -rn [^']*'([^']*)'\) \|\| verdict=", src)
prog = m.group(1) if m else ''
# Non-vacuous: an extraction that missed the arms would pass `not in` trivially.
arms = all(f'"{v}\\t' in prog for v in ('PASS', 'FAIL', 'VOID'))
compared = re.search(r'(\$sp[a-z_]* *|\.spread[^|\n]*)(>=|<=|>|<)', src)
sys.exit(0 if arms and 'spread' not in prog and not compared else 1)
PY

# The VOID message carries the control beside the floor, and the 2e-4 bar
# beside THRESH. A wide floor is at least 10x the single read condition 4 calls
# a signal to re-examine the DESIGN, and whether it is the night or the design
# is the question within_vantage_spread exists to answer -- so a VOID that
# omits it leaves that question unanswerable from the log. Source-level
# for the same reason as the vantages assertion: the exit code is 91 either way.
grep -F '::error::VOID' "$WORK/dverdict.sh" | grep -F 'within_vantage_spread=$within' | grep -qF '2e-4' \
  && echo "PASS  VOID message reports the within-vantage control and the 2e-4 bar" \
  || { echo "FAIL  VOID no longer reports within_vantage_spread and the 2e-4 bar beside the floor"; FAILED=1; }

[ "$FAILED" = 0 ] && { echo "ALL PASS"; exit 0; } || { echo "FAILURES"; exit 1; }
