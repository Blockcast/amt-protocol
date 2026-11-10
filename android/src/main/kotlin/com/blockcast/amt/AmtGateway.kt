package com.blockcast.amt

/**
 * RFC 7450 AMT gateway state machine, backed by `libamt_protocol.so`.
 *
 * This class does no network I/O. Each protocol step either returns the encoded
 * datagram to send to the relay or consumes the datagram received from it; the
 * caller owns the UDP socket. [AmtSession] does that for the common case. The
 * sequence (RFC 7450 section 5.2):
 *
 * 1. [startDiscovery], send it to the relay or to an anycast discovery address;
 * 2. receive the Relay Advertisement, [handleAdvertisement];
 * 3. [requestMembership], send it; receive the Membership Query, [handleQuery];
 * 4. [rebindTeardown] (send it when non-null), then [sendUpdate] with an
 *    [IgmpSsm] report, send it: the gateway is now [State.ACTIVE];
 * 5. receive Multicast Data, [handleData] yields the inner IP packet;
 * 6. repeat 3 and 4 periodically to keep the tunnel alive; [sendTeardown] ends it.
 *
 * Instances are not thread-safe: the native handle is a plain pointer with no lock
 * behind it. Serialize every call, [close] included.
 */
class AmtGateway private constructor(private var handle: Long) : AutoCloseable {

    /** Gateway state (RFC 7450 section 5.2), as `nativeGetState` encodes it. */
    enum class State(internal val code: Int) {
        /** Nothing in flight. After discovery this also means "relay known, not joined". */
        IDLE(0),

        /** Relay Discovery sent, waiting for the Relay Advertisement. */
        DISCOVERING(1),

        /** Request sent, waiting for the Membership Query. */
        REQUESTING(2),

        /** Membership Query accepted, Membership Update not sent yet. */
        QUERYING(3),

        /** Membership Update sent; Multicast Data is accepted. */
        ACTIVE(4),

        /** Teardown sent. [reset] returns to [IDLE]. */
        CLOSED(5);

        internal companion object {
            fun fromCode(code: Int): State = entries.firstOrNull { it.code == code }
                ?: throw IllegalStateException("unknown native gateway state $code")
        }
    }

    companion object {
        /** IANA-assigned UDP port for AMT (RFC 7450 section 7). */
        const val DEFAULT_PORT = 2268

        init {
            System.loadLibrary("amt_protocol")
        }

        /**
         * Create a gateway for a relay.
         *
         * @param relayAddress IPv4 or IPv6 literal of the relay, or of an anycast relay
         *   discovery address. Not a hostname: resolve it first.
         * @param relayPort relay UDP port, 1..65535.
         * @param enableDriad recorded in the gateway configuration; the native state machine
         *   does not act on it. See [Driad] for what the JNI surface offers.
         * @throws AmtException [AmtError.INVALID_ADDRESS] when [relayAddress] does not parse.
         */
        @JvmStatic
        @JvmOverloads
        fun create(relayAddress: String, relayPort: Int = DEFAULT_PORT, enableDriad: Boolean = false): AmtGateway {
            require(relayPort in 1..65535) { "relayPort out of range: $relayPort" }
            val handle = nativeCreate(relayAddress, relayPort, enableDriad)
            if (handle == 0L) {
                throw AmtException(AmtError.INVALID_ADDRESS, "relay address is not an IP literal: $relayAddress")
            }
            return AmtGateway(handle)
        }

        /** Version string reported by the native library. */
        @JvmStatic
        fun nativeVersion(): String = nativeGetVersion() ?: "unknown"

        // Bound to the symbols src/jni.rs exports as Java_com_blockcast_amt_AmtGateway_<name>.
        // Names and signatures must match that file exactly.
        @JvmStatic private external fun nativeCreate(relayAddress: String, relayPort: Int, enableDriad: Boolean): Long
        @JvmStatic private external fun nativeDestroy(handle: Long)
        @JvmStatic private external fun nativeGetState(handle: Long): Int
        @JvmStatic private external fun nativeGetRelayPort(handle: Long): Int
        @JvmStatic private external fun nativeStartDiscovery(handle: Long): ByteArray?
        @JvmStatic private external fun nativeHandleAdvertisement(handle: Long, data: ByteArray): Int
        @JvmStatic private external fun nativeRequestMembership(handle: Long, pFlag: Boolean): ByteArray?
        @JvmStatic private external fun nativeHandleQuery(handle: Long, data: ByteArray): ByteArray?
        @JvmStatic private external fun nativeSendUpdate(handle: Long, reportData: ByteArray): ByteArray?
        @JvmStatic private external fun nativeHandleData(handle: Long, data: ByteArray): ByteArray?
        @JvmStatic private external fun nativeSendTeardown(handle: Long): ByteArray?
        @JvmStatic private external fun nativeRebindTeardown(handle: Long): ByteArray?
        @JvmStatic private external fun nativeReset(handle: Long)
        @JvmStatic private external fun nativeGetVersion(): String?
    }

    /** True once [close] has run; every other member then throws [AmtError.CLOSED]. */
    val isClosed: Boolean
        get() = handle == 0L

    /** Current state. */
    val state: State
        get() = State.fromCode(nativeGetState(open()))

    /** Relay UDP port the gateway was created with. */
    val relayPort: Int
        get() = nativeGetRelayPort(open())

    /**
     * Encode a Relay Discovery (section 5.1.1).
     *
     * Allowed in [State.IDLE]; moves to [State.DISCOVERING].
     */
    fun startDiscovery(): ByteArray =
        nativeStartDiscovery(open()) ?: throw refused("start discovery", State.IDLE)

    /**
     * Consume a Relay Advertisement (section 5.1.2).
     *
     * Allowed in [State.DISCOVERING]; returns to [State.IDLE] with the advertised relay
     * recorded. Send every later message to the address the advertisement carries
     * (section 5.2.3.4.3); [AmtWire.advertisedRelayAddress] reads it.
     *
     * @throws AmtException [AmtError.INVALID_NONCE] when it answers a different discovery,
     *   [AmtError.DECODE_ERROR] or [AmtError.UNEXPECTED_MESSAGE] for other datagrams.
     */
    fun handleAdvertisement(datagram: ByteArray) {
        val h = open()
        val wasDiscovering = state == State.DISCOVERING
        val code = nativeHandleAdvertisement(h, datagram)
        if (code != 0) {
            throw AmtException(
                AmtError.forAdvertisementCode(code, wasDiscovering),
                "advertisement refused (native code $code)",
            )
        }
    }

    /**
     * Encode a Request (section 5.1.3).
     *
     * Allowed in [State.IDLE] once a relay is known (bootstrap: moves to [State.REQUESTING])
     * and in [State.ACTIVE] (keepalive: stays active and reuses the tunnel nonce).
     *
     * @param mldQuery the P flag (section 5.1.3.3): false asks the relay for an IGMPv3
     *   General Query, true for an MLDv2 one. Joins built by [IgmpSsm] are IPv4, so leave
     *   it false.
     */
    @JvmOverloads
    fun requestMembership(mldQuery: Boolean = false): ByteArray =
        nativeRequestMembership(open(), mldQuery) ?: throw refused("request membership", State.IDLE, State.ACTIVE)

    /**
     * Consume a Membership Query (section 5.1.4).
     *
     * Allowed in [State.REQUESTING] and [State.ACTIVE]; moves to [State.QUERYING]. Returns
     * the encapsulated IGMP/MLD General Query, which callers building their own reports
     * with [IgmpSsm] can ignore. Check [rebindTeardown] before answering with [sendUpdate].
     */
    fun handleQuery(datagram: ByteArray): ByteArray =
        nativeHandleQuery(open(), datagram) ?: throw refused("handle query", State.REQUESTING, State.ACTIVE)

    /**
     * Encode a Membership Update (section 5.1.5) carrying [report], an IP-encapsulated
     * IGMPv3 or MLDv2 report such as [IgmpSsm.joinReport] builds.
     *
     * Allowed in [State.QUERYING] and [State.ACTIVE]; moves to [State.ACTIVE].
     */
    fun sendUpdate(report: ByteArray): ByteArray =
        nativeSendUpdate(open(), report) ?: throw refused("send update", State.QUERYING, State.ACTIVE)

    /**
     * Decapsulate Multicast Data (section 5.1.6) into the inner IP packet.
     *
     * Allowed in [State.ACTIVE] only. [AmtWire.udpPayload] strips the inner headers.
     */
    fun handleData(datagram: ByteArray): ByteArray =
        nativeHandleData(open(), datagram) ?: throw refused("handle data", State.ACTIVE)

    /**
     * Encode the Teardown (section 5.1.7) for the current tunnel, or return null when the
     * relay never sent Gateway Address fields in its Membership Query, meaning it does
     * not support Teardown and there is nothing to send (section 5.1.4.5).
     *
     * Allowed in [State.ACTIVE]; moves to [State.CLOSED] when a Teardown is returned.
     */
    fun sendTeardown(): ByteArray? {
        val h = open()
        if (state != State.ACTIVE) throw refused("send teardown", State.ACTIVE)
        return nativeSendTeardown(h)
    }

    /**
     * Teardown owed after a Membership Query reported a new gateway endpoint, a NAT
     * rebinding for instance (section 5.2.3.7.1), or null when none is owed. Call after
     * [handleQuery] and before the [sendUpdate] answering it, and send the result first.
     * State is unchanged.
     */
    fun rebindTeardown(): ByteArray? = nativeRebindTeardown(open())

    /** Back to [State.IDLE], forgetting nonces, MAC and groups. The relay stays known. */
    fun reset() = nativeReset(open())

    /** Destroy the native gateway. Idempotent. */
    override fun close() {
        if (handle != 0L) {
            nativeDestroy(handle)
            handle = 0L
        }
    }

    private fun open(): Long =
        handle.takeIf { it != 0L } ?: throw AmtException(AmtError.CLOSED, "gateway is closed")

    /** Classify a null return: wrong state, or a refusal the native side does not explain. */
    private fun refused(op: String, vararg allowed: State): AmtException {
        val now = state
        return if (now !in allowed) {
            AmtException(AmtError.INVALID_STATE, "cannot $op in state $now (needs ${allowed.joinToString(" or ")})")
        } else {
            AmtException(AmtError.REJECTED, "$op refused by the native gateway in state $now")
        }
    }
}
