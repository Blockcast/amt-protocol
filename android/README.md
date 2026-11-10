# amt-protocol for Android

Kotlin library module over the crate's JNI surface (`src/jni.rs`, Cargo feature `jni`).

- Package `com.blockcast.sdk.amt`: fixed by the exported symbols
  `Java_com_blockcast_sdk_amt_<Class>_<method>`, so the class and native method names
  in `AmtGateway.kt`, `Driad.kt` and `IgmpSsm.kt` must stay in step with `src/jni.rs`.
- `minSdk 21`, Kotlin stdlib only, JUnit 4 for the unit tests.
- The native library is not built here. Drop the per-ABI `libamt_protocol.so` files in
  and Gradle packages them into the AAR.

## Layout

```
android/
  build.gradle.kts             com.android.library + kotlin.android, namespace com.blockcast.sdk.amt
  settings.gradle.kts
  src/main/AndroidManifest.xml INTERNET permission (merged into the app)
  src/main/kotlin/com/blockcast/sdk/amt/
    AmtGateway.kt              RFC 7450 state machine over the natives; no I/O
    Driad.kt                   DRIAD query name (RFC 8777)
    IgmpSsm.kt                 IGMPv3 SSM join reports
    AmtException.kt            AmtError + AmtException
    AmtWire.kt                 message type, advertised relay address, IPv4/UDP payload (pure Kotlin)
    SsmChannel.kt              validated (S,G) pair, strict IPv4 literal parsing (pure Kotlin)
    AmtSession.kt              socket-owning tunnel: open / join / leave / close + listener thread
  src/main/jniLibs/<abi>/libamt_protocol.so   (not committed; see below)
  src/test/kotlin/...          unit tests for the pure-Kotlin parts
```

## Native libraries (jniLibs)

`make jni` at the repository root (needs `cargo-ndk` and an Android NDK, see the root
README) writes `dist/android/<abi>/libamt_protocol.so` for `arm64-v8a`, `armeabi-v7a`,
`x86` and `x86_64`. That is already the `jniLibs` layout:

```bash
cp -r dist/android/. android/src/main/jniLibs/
```

Or take the per-ABI `.so` files from the CI artifact of the Android build job (added
separately) and extract them into `android/src/main/jniLibs/<abi>/`. `*.so` is ignored by
the repository's `.gitignore`, so they are never committed. Only the ABIs present are
packaged; an app running on a missing ABI fails at class load with
`UnsatisfiedLinkError`, so ship at least `arm64-v8a`.

## Build

```bash
gradle -p android test              # pure-Kotlin unit tests; no .so required
gradle -p android assembleRelease   # android/build/outputs/aar/amt-protocol-android-release.aar
```

Needs JDK 17+, Gradle 8.13+ and an Android SDK with platform 36 (`ANDROID_HOME`, or
`sdk.dir` in `android/local.properties`). No Gradle wrapper is committed; `gradle -p android
wrapper` generates one. A CI job for this module can run the same two commands.

## Use

High level, one relay and one or more IPv4 SSM channels:

```kotlin
val session = AmtSession("relay.example.net", object : AmtSession.Listener {
    override fun onPacket(ipPacket: ByteArray) {
        val payload = AmtWire.udpPayload(ipPacket) ?: return  // RTP, MPEG-TS, MMTP...
        // hand payload to the player
    }
    override fun onStopped(error: Exception?) { /* socket failure, or null after close() */ }
})
session.open()                                        // relay discovery; blocks, not for the main thread
session.join(SsmChannel("203.0.113.9", "232.1.1.1"))  // Request / Query / Update; blocks
// receiving on the "amt-rx" thread; refreshed every 60 s by default
session.leave()                                       // Teardown; join() again if wanted
session.close()
```

Low level, with your own socket:

```kotlin
AmtGateway.create("198.51.100.7").use { gw ->
    send(gw.startDiscovery())
    gw.handleAdvertisement(receive())           // state back to IDLE, relay recorded
    send(gw.requestMembership())
    gw.handleQuery(receive())                   // QUERYING
    gw.rebindTeardown()?.let(::send)
    send(gw.sendUpdate(IgmpSsm.joinReport("203.0.113.9", "232.1.1.1")))  // ACTIVE
    while (true) deliver(gw.handleData(receive()))
}
```

Every failure is an `AmtException` whose `error` (`AmtError`) says why; argument errors are
`IllegalArgumentException`. `AmtGateway` is not thread-safe: serialize calls.

## What the JNI surface does not offer

These are limits of `src/jni.rs`, not of this module; extending them means exporting more
natives there.

- IPv6 / MLD joins: `IgmpSsm` is IPv4 only.
- Leaving one group while keeping the tunnel: no IGMP leave-report builder, so
  `AmtSession.leave()` ends the tunnel.
- DRIAD beyond the query name: the AMTRELAY RDATA decoder in `src/driad.rs` is not
  exported. Resolve `Driad.queryName(source)` with `android.net.DnsResolver.rawQuery`
  (API 29+), decode the record, then pass the relay address to `AmtSession`.
- Failure detail: most natives return null on failure, so `AmtError` is classified from the
  gateway state (`INVALID_STATE` vs `REJECTED`); only `handleAdvertisement` reports a code.
- The `enableDriad` flag of `AmtGateway.create` is stored in the native config and not acted on.
