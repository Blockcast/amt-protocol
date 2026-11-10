#!/usr/bin/env bash
# Asserts the host libamt_protocol.so built with the `jni` feature exports BOTH
# JNI symbol sets: the primary com.blockcast.amt names and the legacy
# com.blockcast.sdk.amt aliases (src/jni.rs `legacy_symbol!`). pim's AmtGateway
# binds the legacy names, and a missing one only fails on a device, as an
# UnsatisfiedLinkError after a submodule bump -- so the list is written out here,
# not derived from src/jni.rs, or deleting an alias would also delete its check.
#
# Remove the legacy half once pim's AmtGateway moves to com.blockcast.amt; pim
# pins packages/amt-protocol at 61a16b3d.
#
# Usage: bash tests/jni_exports_test.sh [path/to/libamt_protocol.so]
set -euo pipefail

so="${1:-}"
if [ -z "$so" ]; then
  cargo build --release --no-default-features --features jni --locked
  so="${CARGO_TARGET_DIR:-target}/release/libamt_protocol.so"
fi
test -f "$so" || { echo "::error::$so missing"; exit 1; }

methods="
AmtGateway_nativeCreate
AmtGateway_nativeDestroy
AmtGateway_nativeGetState
AmtGateway_nativeGetRelayPort
AmtGateway_nativeStartDiscovery
AmtGateway_nativeHandleAdvertisement
AmtGateway_nativeRequestMembership
AmtGateway_nativeHandleQuery
AmtGateway_nativeSendUpdate
AmtGateway_nativeHandleData
AmtGateway_nativeSendTeardown
AmtGateway_nativeRebindTeardown
AmtGateway_nativeReset
AmtGateway_nativeGetVersion
Driad_nativeBuildQuery
IgmpSsm_nativeCreateJoinReport
IgmpSsm_nativeCreateMultiJoinReport
"

exports=$(nm -D --defined-only "$so" | awk '{print $NF}' | grep '^Java_' | sort)
fail=0
for prefix in Java_com_blockcast_amt_ Java_com_blockcast_sdk_amt_; do
  want=$(for m in $methods; do echo "$prefix$m"; done | sort)
  got=$(grep "^${prefix}" <<<"$exports" || true)
  n=$(grep -c . <<<"$got" || true)
  if [ "$want" != "$got" ]; then
    echo "::error::$prefix exports differ from the expected 17 (got $n):"
    diff <(echo "$want") <(echo "$got") || true
    fail=1
  else
    echo "ok: $prefix* = $n exports"
  fi
done
exit $fail
