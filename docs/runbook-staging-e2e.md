# Staging E2E runbook — amt-verify against staging-blockcastd

## Prerequisites

- kubectl access to the `staging-blockcastd` namespace
- A live (S,G) feed: source IP that's currently sending to a known group
- Either:
  - **Direct path** (devbox): set `STAGING_RELAY` to the amt-relay external IP
  - **DRIAD path** (in-cluster pod): leave `STAGING_RELAY` unset; runs from a pod
    where `:53/UDP` reaches kube-dns

## Build the bin

From the amt-protocol repo:

```bash
cargo build --release --no-default-features --features native --bin amt-verify
```

The binary lands at `target/release/amt-verify`.

## Direct path — from devbox

```bash
./target/release/amt-verify \
    --relay 192.0.2.96 \
    --source 69.25.95.10 \
    --group 232.0.0.1 \
    --timeout 30 \
    --json
```

Expected output (one line of JSON):

```json
{"outcome":"ok","relay":"192.0.2.96","family":"v4","group":"232.0.0.1","source":"69.25.95.10","timings_ms":{"first_data":240},"first_packet":{"src":"69.25.95.10:5004","dst_port":5004,"len":1316}}
```

Exit code: 0 on success, 1 on timeout / handshake failure.

## Billing shutdown matrix

Use the same `--relay`, `--source`, `--group`, and `--timeout` values as the
direct-path check. The final flag selects the AMT shutdown shape the relay must
bill:

```bash
# Nominal: Membership Update leave, then AMT Teardown.
./target/release/amt-verify --relay "$STAGING_RELAY" \
    --source "$STAGING_SOURCE" --group "$STAGING_GROUP" --timeout 30 --json

# Non-graceful app leave: skip Membership Update leave, send AMT Teardown.
./target/release/amt-verify --relay "$STAGING_RELAY" \
    --source "$STAGING_SOURCE" --group "$STAGING_GROUP" --timeout 30 --json \
    --no-graceful-leave

# Hard loss: drop the gateway runtime with no leave and no AMT Teardown.
# Staging sets EBPF_BILLING_STALE_TIMEOUT=45s and
# EBPF_BILLING_STALE_SWEEP_INTERVAL=5s, so billing should finalize within
# roughly 50s after first data.
./target/release/amt-verify --relay "$STAGING_RELAY" \
    --source "$STAGING_SOURCE" --group "$STAGING_GROUP" --timeout 30 --json \
    --drop-without-teardown
```

## DRIAD path — from in-cluster pod

```bash
kubectl -n staging-blockcastd run amt-verify-shot --rm -it --restart=Never \
    --image=ghcr.io/blockcast/amt-verify:latest \
    -- --source 69.25.95.10 --group 232.0.0.1 --timeout 30 --json
```

(Image build is out of scope for M5; for ad-hoc verify, `kubectl cp` the
local binary into a debug pod that already has a libc compatible with the
build environment.)

## Running the ignored E2E tests

```bash
STAGING_RELAY=192.0.2.96 \
STAGING_SOURCE=69.25.95.10 \
STAGING_GROUP=232.0.0.1 \
    cargo test --no-default-features --features native \
        --test e2e_staging -- --ignored --nocapture
```

## Troubleshooting

- **Timeout at 30s on `e2e_oneshot_explicit_relay`**: relay reachable but no
  multicast data flowing for the (S,G). Confirm with `tcpdump -i any host
  $STAGING_RELAY` on the relay; check `staging-blockcastd` amt-relay `/health`
  for `mfc_absent_counters` (requires `USE_EBPF=true` — separate work).
- **Timeout on `e2e_driad_then_join`** but `e2e_oneshot_explicit_relay`
  passes: DNS path is broken. Check `/etc/resolv.conf` inside the pod;
  verify `dig` against kube-dns from the pod returns an AMTRELAY record for
  the reversed `STAGING_SOURCE`.
- **Exit 2 (config error)**: clap rejected the args. Re-read the `--help`.
- **`--no-driad` without `--relay`**: rejected at startup with exit 2 —
  defense against silent DNS misconfig in CI.
