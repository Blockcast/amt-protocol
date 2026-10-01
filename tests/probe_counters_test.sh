#!/usr/bin/env bash
# Guards the receive-side COUNTER legs of the probe step in
# .github/workflows/amt-public-vantage-probe.yml -- the `udp_delta` /
# `softnet_delta` emits and the `RcvbufErrors` positive control (BLO-33636).
#
# Like tests/probe_verdict_test.sh, this extracts the real run-block from the
# workflow YAML and executes it with `docker` stubbed, so it tests the shipped
# shell rather than a copy that can drift. The /proc reads are redirected via
# the PROC_SNMP / PROC_SOFTNET seams; every other stub is a PATH-shadowed
# binary, which cannot work for a file read.
#
# WHY THIS FILE EXISTS. The leg's whole purpose is to answer "did THIS HOST drop
# the packets `mmtp.gaps` is counting?", and the expensive failure is a zero that
# is not a measurement:
#
#   1. A DEAD DIAL. The prediction is "udp_delta non-zero on N=3, zero on N=1".
#      A counter that never moves reads zero on BOTH, which presents as REFUTING
#      the receive-side hypothesis and re-indicts the relay. The pre-existing
#      width check cannot catch it -- it establishes capture validity, not field
#      responsiveness -- and neither can the known-clean negative control, since
#      a dead counter and a quiet one both read 0. Hence the positive control,
#      and hence `live dial` below, which asserts it actually fires on the same
#      runner class that runs the probe.
#
#   2. A FABRICATED ZERO. `A[i]-B[i]` over unset awk fields is 0-0, so an
#      unreadable or reshaped /proc file yields a complete, well-formed, entirely
#      fake `dropped=0`. Every invalid case below therefore asserts the ABSENCE
#      of the delta line, not merely the presence of the _invalid line: a grep
#      for `dropped=` must find nothing, which is the honest answer.
#
#   3. A MIS-PINNED COLUMN. /proc/net/softnet_stat has NO header line, so the
#      label-keying that protects `udp_delta` has no analogue -- position is the
#      only addressing available. "column 2" is ambiguous between 0- and
#      1-indexing and the wrong pick reports a large time_squeeze as drops.
#      `$2/$3 pinned` below holds the indices against exactly that.
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

# Extraction is a PRECONDITION, not a case: without this every assertion below
# scores `bash: no such file` (127) and reads like a counter regression.
[ -s "$WORK/probe.sh" ] || {
  echo "ABORT: could not extract probe.sh from $WORKFLOW (workflow missing, 'probe' job renamed, the 'docker pull' step moved, or pyyaml absent)" >&2
  exit 2
}

FAILED=0

# ---------------------------------------------------------------------------
# Structural: the control must run to COMPLETION BEFORE the baseline is taken.
#
# The control's own drops land in the SAME netns-wide counter the probe reads.
# Run before `udp_before`, they sit in the baseline and cancel out of
# `after - before`; run after it -- or concurrently -- they are indistinguishable
# from drops caused by the tunnels under test, and the control becomes a
# contaminant that manufactures the very non-zero it exists to validate.
#
# Source order is the only thing that fixes this, so assert source order. A
# behavioural assertion cannot: in fixture mode the control reads the same static
# file twice and contributes nothing either way, which is precisely why the
# hazard would go unheld.
# ---------------------------------------------------------------------------
ctl_line=$(grep -n 'udp_control_out=' "$WORK/probe.sh" | head -1 | cut -d: -f1)
before_line=$(grep -n '^udp_before=' "$WORK/probe.sh" | head -1 | cut -d: -f1)
if [ -n "$ctl_line" ] && [ -n "$before_line" ] && [ "$ctl_line" -lt "$before_line" ]; then
  echo "PASS  ordering: positive control precedes the udp_before baseline"
else
  echo "FAIL  ordering: control at '${ctl_line:-absent}', udp_before at '${before_line:-absent}' -- the control must fully exit BEFORE the baseline or its own drops contaminate the delta"
  FAILED=1
fi
# Backgrounding it would satisfy the line-order check above and still overlap the
# probe, which is the same contamination by another route. Scan the whole control
# region, not just its first line: the realistic way to background a `$(...)` is
# a trailing `&` on the CLOSING paren, which a regex anchored to the opening line
# cannot see -- and a guard that cannot fail is documentation, not a guard.
if [ -n "$ctl_line" ] && [ -n "$before_line" ] \
   && sed -n "${ctl_line},${before_line}p" "$WORK/probe.sh" | grep -qE '(^|[^&])&[[:space:]]*$'; then
  echo "FAIL  ordering: the positive control region is backgrounded; it must run synchronously to completion"
  FAILED=1
else
  echo "PASS  ordering: positive control is not backgrounded"
fi

mkdir -p "$WORK/bin"
# The stub stands in for the tunnel containers AND, crucially, advances the
# counter fixtures: it is the only thing that runs between the `before` and
# `after` samples, so it is where a real run's drops would accrue. Without this
# a static fixture gives before == after and every delta is trivially 0 -- the
# suite would then pass just as happily against a parser that always printed 0.
cat >"$WORK/bin/docker" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  pull)    exit 0 ;;
  inspect) echo "stub@sha256:deadbeef"; exit 0 ;;
esac
[ -n "${SNMP_AFTER:-}" ]    && printf '%s\n' "$SNMP_AFTER"    >"$PROC_SNMP"
[ -n "${SOFTNET_AFTER:-}" ] && printf '%s\n' "$SOFTNET_AFTER" >"$PROC_SOFTNET"
echo "{\"source\":\"$SOURCE\",\"group\":\"$GROUP\",\"packet_count\":500,\"outcome\":\"timeout\",\"mmtp\":{\"implausible\":0,\"loss_ratio\":0,\"tracks\":1,\"received\":500,\"in_sequence\":499}}"
echo "handshake trace" >&2
exit 1
EOF
cat >"$WORK/bin/curl" <<'EOF'
#!/usr/bin/env bash
echo "203.0.113.7"
EOF
chmod +x "$WORK/bin/docker" "$WORK/bin/curl"
export PATH="$WORK/bin:$PATH" STUB_DIR="$WORK"

# A softnet_stat row: 15 bare hex columns, no header. $1 processed, $2 dropped,
# $3 time_squeeze -- the live shape measured on 6.8.0-142.
sn() {
  printf '%s %s %s' "$1" "$2" "$3"
  local i; for i in $(seq 4 15); do printf ' 00000000'; done
  printf '\n'
}
SNMP_HDR='Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors'

OUT=
# Runs the shipped block once with the given fixtures and captures its stdout.
# $1 name, $2 snmp_before, $3 snmp_after, $4 softnet_before, $5 softnet_after.
# A fixture of '' means: do not create the file at all (the unreadable case).
run_counters() {
  local name=$1 sb=$2 sa=$3 nb=$4 na=$5
  local dir; dir=$(mktemp -d -p "$WORK")
  : >"$dir/gh_env"
  [ -n "$sb" ] && printf '%s\n' "$sb" >"$dir/snmp"
  [ -n "$nb" ] && printf '%s\n' "$nb" >"$dir/softnet"
  OUT=$( cd "$dir"
    export TUNNELS=1 RELAY=1.2.3.4 SOURCE=69.25.95.192 GROUP=232.1.1.60 \
           TIMEOUT=5 PACKETS=3 GITHUB_ENV="$dir/gh_env" \
           PROC_SNMP="$dir/snmp" PROC_SOFTNET="$dir/softnet" \
           SNMP_AFTER="$sa" SOFTNET_AFTER="$na"
    bash "$WORK/probe.sh" 2>/dev/null )
  CASE=$name
  rm -rf "$dir"
}

# The three helpers match against a here-string, never `printf | grep -q`: under
# pipefail, `grep -q` exiting on its first match can SIGPIPE the printf and make
# the pipeline 141. In want_absent that sends a PRESENT token to the PASS branch,
# i.e. the fabricated-zero check silently fails open.
# Asserts a literal line is present in the captured stdout.
want() {
  if grep -qxF -- "$1" <<<"$OUT"; then
    echo "PASS  $CASE: $1"
  else
    echo "FAIL  $CASE: expected line '$1'"
    printf '%s\n' "$OUT" | grep -E 'softnet|udp_delta|udp_control|unvalidated' | sed 's/^/        got: /'
    FAILED=1
  fi
}
# Asserts NO line contains the token -- the fabricated-zero guard. Presence of
# the _invalid line is not enough on its own: a consumer greps for the VALUE.
want_absent() {
  if grep -qF -- "$1" <<<"$OUT"; then
    echo "FAIL  $CASE: '$1' must be absent (a fabricated zero is worse than no reading)"
    printf '%s\n' "$OUT" | grep -F "$1" | sed 's/^/        got: /'
    FAILED=1
  else
    echo "PASS  $CASE: no '$1' emitted"
  fi
}
want_grep() {
  if grep -qF -- "$1" <<<"$OUT"; then
    echo "PASS  $CASE: contains '$1'"
  else
    echo "FAIL  $CASE: expected '$1'"
    printf '%s\n' "$OUT" | grep -E 'softnet|udp_delta|udp_control|unvalidated' | sed 's/^/        got: /'
    FAILED=1
  fi
}

# ---------------------------------------------------------------------------
# Harness self-check: want_absent must fail CLOSED on a large $OUT.
#
# The here-string above is the guard, and until this case it had no failing
# mutation -- reverting it to `printf | grep -q` left the suite green at 33
# PASS, because no fixture produces an $OUT bigger than the 64 KiB pipe buffer
# and the SIGPIPE therefore never fires. That made the hardening a comment on
# the one assertion family carrying the fabricated-zero contract.
#
# ORDER IS THE WHOLE GUARD: the needle goes FIRST and the filler BEHIND it.
# SIGPIPE needs `grep -q` to exit while printf still has more than a pipe
# buffer left to write, so a needle at the END is read only after printf has
# already written everything -- no SIGPIPE, mutant survives, case inert. That
# was measured, not reasoned: with the needle last this case passed under the
# very mutation it exists to kill.
#
# Deterministic, not probabilistic: matching in the first line leaves ~280 KiB
# unwritten against a 64 KiB buffer, so the pipe form takes the else (PASS)
# branch every time. Needs no fixture and no probe -- it drives the helper
# directly.
# ---------------------------------------------------------------------------
CASE="want_absent fails closed"
_saved_failed=$FAILED
OUT="softnet_delta dropped=0 time_squeeze=0 cpus=2 nf=15
$(yes 'filler line that is not the needle' | head -8000)"
FAILED=0
want_absent "dropped=" >/dev/null
if [ "$FAILED" = 1 ]; then
  echo "PASS  $CASE: present needle in a ${#OUT}-byte \$OUT took the FAIL branch"
  FAILED=$_saved_failed
else
  echo "FAIL  $CASE: a PRESENT needle took the PASS branch -- want_absent is"
  echo "      failing OPEN, so every fabricated-zero assertion below is inert."
  FAILED=1
fi
unset _saved_failed

# ---------------------------------------------------------------------------
# softnet_delta -- happy path. Two CPUs, both counters advancing by DIFFERENT
# amounts, so a parser that summed the wrong column, double-counted a CPU, or
# transposed dropped and time_squeeze produces a different number rather than
# the same one.
#   dropped:      0x10+0x20 = 48 -> 0x15+0x25 = 58   delta 10
#   time_squeeze: 0x100+0x200 = 768 -> 0x110+0x210 = 800   delta 32
# ---------------------------------------------------------------------------
run_counters "softnet happy" \
  "$SNMP_HDR
Udp: 10 0 0 10 5 0 0 0 0" \
  "$SNMP_HDR
Udp: 90 0 0 10 12 0 0 0 0" \
  "$(sn 0000000a 00000010 00000100; sn 0000000b 00000020 00000200)" \
  "$(sn 0000001a 00000015 00000110; sn 0000001b 00000025 00000210)"
want "softnet_delta dropped=10 time_squeeze=32 cpus=2 nf=15"
# The raw lines are emitted so a reader on a kernel whose layout differs can
# re-derive the numbers instead of having to trust this parse.
want_grep "softnet_raw_before=0000000a 00000010 00000100"
want_grep "softnet_raw_after=0000001a 00000015 00000110"
# Same run doubles as the udp_delta happy path: RcvbufErrors 5 -> 12.
want_grep "udp_delta "
want_grep "RcvbufErrors=7"

# ---------------------------------------------------------------------------
# $2/$3 pinned. The live 6.8.0-142 shape: dropped flat at 0 while time_squeeze
# climbs by 0x899 = 2201. A dropped-only read -- or an off-by-one index --
# reports "no backlog pressure" on a host that squeezed 2201 times. That is the
# live-looking zero this whole leg exists to avoid, so hold both numbers.
# ---------------------------------------------------------------------------
run_counters "\$2/\$3 pinned" \
  "$SNMP_HDR
Udp: 10 0 0 10 5 0 0 0 0" "" \
  "$(sn 00d572fa 00000000 00000000)" \
  "$(sn 00d573ff 00000000 00000899)"
want "softnet_delta dropped=0 time_squeeze=2201 cpus=1 nf=15"

# ---------------------------------------------------------------------------
# Validity guards. Each must emit NO `softnet_delta` line at all.
# ---------------------------------------------------------------------------
SNMP_OK="$SNMP_HDR
Udp: 10 0 0 10 5 0 0 0 0"

# Field count moved between the samples -- a kernel that added a column, or a
# truncated read. Position is the only addressing available, so a width change
# invalidates every index.
run_counters "nf changed" "$SNMP_OK" "" \
  "$(sn 0000000a 00000010 00000100)" \
  "0000001a 00000015 00000110 00000000"
want_grep "softnet_delta_invalid reason=shape_changed"
want_absent "dropped="

# CPU count moved -- hotplug, or a partial read. Summing over a different
# population before and after is not a delta.
run_counters "cpu count changed" "$SNMP_OK" "" \
  "$(sn 0000000a 00000010 00000100; sn 0000000b 00000020 00000200)" \
  "$(sn 0000001a 00000015 00000110)"
want_grep "softnet_delta_invalid reason=shape_changed"
want_absent "dropped="

# A row too SHORT to carry the fields, with the same width in both samples so
# the shape_changed guard cannot fire. w[2]/w[3] are then unset, and hex2dec's
# empty-string rejection is the only thing standing between this and a
# fabricated `dropped=0 time_squeeze=0`.
#
# Found by mutation-testing, not by design: an explicit `nf < 3` check used to
# sit alongside hex2dec here and NEITHER could be made to fail, because no case
# exercised a short row at all. Two overlapping guards, zero coverage, and the
# suite green either way.
run_counters "short row, consistent width" "$SNMP_OK" "" \
  "0000000a 00000010" \
  "0000001a 00000015"
want_grep "softnet_delta_invalid reason=unparseable"
want_absent "dropped="

# Non-hex payload: /proc replaced, or a format change. hex2dec returns -1 and
# the row is refused rather than silently parsed as a prefix.
run_counters "non-hex field" "$SNMP_OK" "" \
  "$(sn 0000000a 00000010 00000100)" \
  "$(sn 0000001a zzzzzzzz 00000110)"
want_grep "softnet_delta_invalid reason=unparseable"
want_absent "dropped="

# File absent entirely. This is the case the whole fail-closed posture is for:
# unguarded, awk prints a complete, well-formed `dropped=0 time_squeeze=0`.
run_counters "softnet file absent" "$SNMP_OK" "" "" ""
want_grep "softnet_delta_invalid reason=unparseable"
want_absent "dropped="

# A counter that went BACKWARDS. CPU renumbering, hotplug or a wrap: the
# subtraction is meaningless, not small. Unguarded this prints a NEGATIVE
# delta, which a consumer thresholding on `> 0` reads as "no drops".
run_counters "counter went backwards" "$SNMP_OK" "" \
  "$(sn 0000000a 00000090 00000100)" \
  "$(sn 0000001a 00000010 00000110)"
want_grep "softnet_delta_invalid reason=went_backwards"
want_absent "dropped="

# ---------------------------------------------------------------------------
# udp_delta width guard. Pre-existing and, until this file, untested.
# ---------------------------------------------------------------------------
run_counters "udp header/value width mismatch" \
  "$SNMP_HDR
Udp: 10 0 0 10 5" "" "$(sn 0000000a 00000010 00000100)" ""
want_grep "udp_delta_invalid"
want_absent "RcvbufErrors="

# The case above shortens BOTH samples, so `nh != nb` and `nh != na` each catch
# it alone and neither arm is held. These two change width BETWEEN the samples
# (a column appearing or vanishing mid-run), one arm each. `hdr` is read from
# the after file, so it is full width in both.
run_counters "udp before narrower than after" \
  "$SNMP_HDR
Udp: 10 0 0 10 5" "$SNMP_OK" "$(sn 0000000a 00000010 00000100)" ""
want "udp_delta_invalid hdr=10 before=6 after=10"
want_absent "RcvbufErrors="

run_counters "udp after narrower than before" "$SNMP_OK" \
  "$SNMP_HDR
Udp: 10 0 0 10 5" "$(sn 0000000a 00000010 00000100)" ""
want "udp_delta_invalid hdr=10 before=10 after=6"
want_absent "RcvbufErrors="

# No `Udp:` block at all -- renamed, or /proc/net/snmp reshaped. The header,
# before and after then all split to 0 fields and AGREE, so the two equality
# arms pass and only `nh < 2` refuses the read; without it the probe prints a
# bare, field-less `udp_delta`. The mismatch case above cannot reach that arm.
#
# Pinned as the EXACT _invalid line, with no want_absent: the bare line is a
# prefix of `udp_delta_invalid`, so no substring check can tell the two apart,
# and `want_absent "udp_delta "` passes under the very mutation this case kills.
run_counters "udp block absent" \
  "Ip: Forwarding DefaultTTL
Ip: 1 64" "" "$(sn 0000000a 00000010 00000100)" ""
want "udp_delta_invalid hdr=0 before=0 after=0"

# ---------------------------------------------------------------------------
# The positive control.
#
# In fixture mode PROC_SNMP is static, so the control reads the same value twice
# and correctly reports that it could not prove the dial moves. That is the
# contract: it must say so out loud, with a token a consumer can grep, rather
# than letting a downstream `RcvbufErrors=0` read as a measured zero.
# ---------------------------------------------------------------------------
run_counters "control cannot fire -> unvalidated" "$SNMP_OK" "" \
  "$(sn 0000000a 00000010 00000100)" ""
want_grep "udp_control=unvalidated"
want "udp_counter_unvalidated"

# python3 absent: the control must fail closed on the COUNTER, never on the run.
# The probe still has to reach its verdict and emit its deltas.
mkdir -p "$WORK/nopy"
printf '#!/usr/bin/env bash\nexit 127\n' >"$WORK/nopy/python3"
chmod +x "$WORK/nopy/python3"
( export PATH="$WORK/nopy:$PATH"
  run_counters "python3 absent -> unvalidated, run survives" "$SNMP_OK" "" \
    "$(sn 0000000a 00000010 00000100)" "$(sn 0000001a 00000015 00000110)"
  want_grep "udp_control=unvalidated ctl_error=no_output"
  want "udp_counter_unvalidated"
  want "softnet_delta dropped=5 time_squeeze=16 cpus=1 nf=15"
  exit $FAILED )
[ $? -eq 0 ] || FAILED=1

# ---------------------------------------------------------------------------
# LIVE DIAL. The one case that reads the real /proc and the real loopback, and
# the only one that can distinguish a responsive RcvbufErrors from a dead one.
# Runs on ubuntu-latest, the same runner class that runs the probe, so a failure
# here is a genuine finding about the instrument rather than a fixture problem.
#
# The forcing magnitude is PRINTED rather than asserted. A control licenses the
# INSTRUMENT, not the THRESHOLD: flooding a 4 KiB buffer proves the counter is
# alive, and says nothing about whether the probe's ~1.3k pkt/s at the default
# rcvbuf would move it. Pinning a magnitude here would quietly convert the first
# claim into the second.
# ---------------------------------------------------------------------------
live=$(awk "/<<'PYCTL'/{f=1;next} /^PYCTL\$/{f=0} f" "$WORK/probe.sh" >"$WORK/ctl.py" \
       && python3 "$WORK/ctl.py" 2>/dev/null)
case "$live" in
  udp_control=fired*)
    echo "PASS  live dial: RcvbufErrors is responsive on this host"
    echo "      forcing magnitude (recorded, NOT a threshold): $live" ;;
  *)
    echo "FAIL  live dial: the positive control did not drive RcvbufErrors non-zero."
    echo "      A dead dial reads 0 on both N=1 and N=3, which presents as REFUTING"
    echo "      the receive-side hypothesis. Record any such reading as UNTESTED."
    echo "      got: ${live:-<no output>}"
    FAILED=1 ;;
esac

if [ "$FAILED" = 0 ]; then echo "ALL COUNTER CASES PASS"; else echo "FAILURES"; fi
exit $FAILED
