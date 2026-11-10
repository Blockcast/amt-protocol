package com.blockcast.sdk.amt

import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread
import kotlin.concurrent.withLock

/**
 * An AMT tunnel to one relay: owns the UDP socket, drives [AmtGateway] through RFC 7450
 * section 5.2 and delivers the multicast packets it receives to a [Listener] on a
 * background thread.
 *
 * ```kotlin
 * val session = AmtSession("relay.example.net", object : AmtSession.Listener {
 *     override fun onPacket(ipPacket: ByteArray) {
 *         val payload = AmtWire.udpPayload(ipPacket) ?: return
 *         // feed payload to the player
 *     }
 * })
 * session.open()                                      // relay discovery
 * session.join(SsmChannel("203.0.113.9", "232.1.1.1"))
 * // ...
 * session.close()                                     // teardown, socket and native handle released
 * ```
 *
 * [open] and [join] block on relay replies: call them off the main thread, and never from
 * the listener, which runs on the thread that would have to answer. [leave] and [close]
 * are quick. While joined, the tunnel is refreshed every [refreshIntervalMillis] with a
 * Request/Query/Update exchange (section 5.2.3.4.3); a relay drops a tunnel it has not
 * heard from for its group membership interval (260 s by IGMPv3 defaults), so keep the
 * interval well under that.
 *
 * Only IPv4 SSM channels can be joined: see [SsmChannel] and [IgmpSsm]. Leaving one group
 * while keeping the tunnel up needs an IGMP leave report the native surface does not
 * build, so [leave] ends the whole tunnel.
 *
 * @param relayHost IP literal or hostname of the relay (resolved in [open]), or of an
 *   anycast discovery address; the relay named in the Relay Advertisement takes over
 *   from there (section 5.2.3.4.3).
 * @param listener receives packets and the stop notification, on the receive thread.
 * @param relayPort relay UDP port.
 * @param replyTimeoutMillis how long [open] and [join] wait for each relay reply before
 *   retransmitting.
 * @param attempts transmissions per step before [AmtError.TIMEOUT].
 * @param refreshIntervalMillis tunnel refresh period while joined.
 * @param receiveBufferBytes `SO_RCVBUF` of the tunnel socket, 0 for the platform default.
 *   Raise it for high-rate media so bursts are not dropped before the receive thread runs.
 */
class AmtSession @JvmOverloads constructor(
    private val relayHost: String,
    private val listener: Listener,
    private val relayPort: Int = AmtGateway.DEFAULT_PORT,
    private val replyTimeoutMillis: Long = 2_000,
    private val attempts: Int = 3,
    private val refreshIntervalMillis: Long = 60_000,
    private val receiveBufferBytes: Int = 0,
) : AutoCloseable {

    /** Callbacks, invoked on the session's receive thread. */
    interface Listener {
        /**
         * One inner IP packet from the tunnel. The array is fresh per packet, so it may be
         * kept. [AmtWire.udpPayload] strips the IPv4 and UDP headers.
         */
        fun onPacket(ipPacket: ByteArray)

        /**
         * The receive thread exited. [error] is null after [close]; otherwise it is the
         * socket failure, or the exception [onPacket] threw, that ended the session, which
         * has already been closed.
         */
        fun onStopped(error: Exception?) {}
    }

    private val lock = ReentrantLock()
    private val changed = lock.newCondition()
    private val refreshNanos = TimeUnit.MILLISECONDS.toNanos(refreshIntervalMillis)
    private var gateway: AmtGateway? = null
    private var socket: DatagramSocket? = null
    private var relay: InetSocketAddress? = null
    private var discovered = false
    private var updatesSent = 0L
    private var lastRefreshAt = 0L
    private val channels = LinkedHashSet<SsmChannel>()

    /** Datagrams the gateway refused since [open]: stale nonce, malformed, or wrong state. Diagnostics only. */
    @Volatile
    var droppedDatagrams = 0L
        private set

    init {
        require(relayPort in 1..65535) { "relayPort out of range: $relayPort" }
        require(replyTimeoutMillis > 0) { "replyTimeoutMillis must be positive" }
        require(attempts > 0) { "attempts must be positive" }
        require(refreshIntervalMillis > 0) { "refreshIntervalMillis must be positive" }
        require(receiveBufferBytes >= 0) { "receiveBufferBytes must not be negative" }
    }

    /** Gateway state, or null before [open] and after [close]. */
    val state: AmtGateway.State?
        get() = lock.withLock { gateway?.state }

    /** Channels joined since [open] or the last [leave]. */
    val joinedChannels: Set<SsmChannel>
        get() = lock.withLock { channels.toSet() }

    /**
     * Resolve the relay, bind the tunnel socket, start the receive thread and run relay
     * discovery (section 5.2.3.3). On return the gateway is [AmtGateway.State.IDLE] with
     * the relay known.
     *
     * @throws AmtException [AmtError.TIMEOUT] when no Relay Advertisement arrives; the
     *   session is closed again and [open] may be retried.
     * @throws IOException on resolution or socket failure.
     * @throws IllegalStateException when already open.
     */
    @Throws(IOException::class)
    fun open() {
        val address = InetAddress.getByName(relayHost)
        lock.withLock {
            check(gateway == null) { "session is already open" }
            val gw = AmtGateway.create(checkNotNull(address.hostAddress), relayPort)
            val s = DatagramSocket()
            try {
                if (receiveBufferBytes > 0) s.receiveBufferSize = receiveBufferBytes
                s.soTimeout = TICK_MILLIS
            } catch (e: Exception) {
                s.close()
                gw.close()
                throw e
            }
            gateway = gw
            socket = s
            relay = InetSocketAddress(address, relayPort)
            thread(name = "amt-rx", isDaemon = true) { receiveLoop(s) }
        }
        try {
            exchange(
                what = "relay discovery",
                send = { gw ->
                    // A timed-out attempt leaves the gateway DISCOVERING; a fresh nonce needs IDLE.
                    if (gw.state == AmtGateway.State.DISCOVERING) gw.reset()
                    gw.startDiscovery()
                },
                done = { discovered },
            )
        } catch (e: Exception) {
            close()
            throw e
        }
    }

    /**
     * Join [channel]: Request, Membership Query, Membership Update (section 5.2.3.4).
     * Allowed after [open], before or after other joins. On return the gateway is
     * [AmtGateway.State.ACTIVE] and the channel's packets reach the listener.
     *
     * @throws AmtException [AmtError.TIMEOUT] when the relay does not answer,
     *   [AmtError.INVALID_STATE] before [open].
     * @throws IOException on socket failure.
     */
    @Throws(IOException::class)
    fun join(channel: SsmChannel) {
        val before = lock.withLock {
            if (gateway == null) throw AmtException(AmtError.INVALID_STATE, "session is not open")
            channels += channel
            updatesSent
        }
        try {
            exchange(
                what = "membership for $channel",
                send = { gw ->
                    // Bootstrap retransmit: a Request from REQUESTING is refused, so start over.
                    // From ACTIVE the Request reuses the tunnel nonce and needs no reset.
                    if (gw.state == AmtGateway.State.REQUESTING) gw.reset()
                    gw.requestMembership()
                },
                done = { updatesSent > before },
            )
        } catch (e: Exception) {
            lock.withLock { channels -= channel }
            throw e
        }
    }

    /**
     * End the tunnel: send the Teardown (section 5.2.3.7) when the relay supports one,
     * then return the gateway to [AmtGateway.State.IDLE] with the relay still known, so
     * [join] can be called again. No-op when nothing is joined or the session is closed.
     *
     * @throws IOException on socket failure.
     */
    @Throws(IOException::class)
    fun leave() {
        lock.withLock {
            val gw = gateway ?: return
            if (gw.state == AmtGateway.State.ACTIVE) gw.sendTeardown()?.let(::sendToRelay)
            channels.clear()
            gw.reset()
        }
    }

    /**
     * [leave] (best effort), then release the socket and the native gateway. The listener
     * gets [Listener.onStopped] with null once the receive thread notices. Idempotent.
     */
    override fun close() {
        lock.withLock {
            val gw = gateway ?: return
            try {
                leave()
            } catch (ignored: Exception) {
                // The relay times the tunnel out on its own.
            }
            gateway = null
            gw.close()
            socket?.close()
            socket = null
            changed.signalAll()
        }
    }

    /** Send [send]'s datagram and wait up to [replyTimeoutMillis] for [done], [attempts] times over. */
    private fun exchange(what: String, send: (AmtGateway) -> ByteArray, done: () -> Boolean) {
        repeat(attempts) {
            lock.withLock {
                val gw = gateway ?: throw AmtException(AmtError.CLOSED, "session closed during $what")
                sendToRelay(send(gw))
                var left = TimeUnit.MILLISECONDS.toNanos(replyTimeoutMillis)
                while (!done() && left > 0) left = changed.awaitNanos(left)
                if (done()) return
            }
        }
        throw AmtException(AmtError.TIMEOUT, "$what: no reply from $relay after $attempts x $replyTimeoutMillis ms")
    }

    /** Caller holds [lock]. */
    private fun sendToRelay(datagram: ByteArray) {
        val s = socket ?: throw AmtException(AmtError.CLOSED, "session is closed")
        s.send(DatagramPacket(datagram, datagram.size, checkNotNull(relay)))
    }

    private fun receiveLoop(s: DatagramSocket) {
        val buffer = ByteArray(MAX_DATAGRAM)
        val packet = DatagramPacket(buffer, buffer.size)
        var failure: Exception? = null
        try {
            while (true) {
                packet.setData(buffer, 0, buffer.size)
                try {
                    s.receive(packet)
                } catch (ignored: SocketTimeoutException) {
                    lock.withLock { tick() }
                    continue
                }
                val datagram = packet.data.copyOf(packet.length)
                val ipPacket = lock.withLock { dispatch(datagram) } ?: continue
                listener.onPacket(ipPacket)
            }
        } catch (e: Exception) {
            // A socket we closed ourselves is a normal stop; anything else ends the session.
            if (!s.isClosed) failure = e
        } finally {
            if (failure != null) close()
            listener.onStopped(failure)
        }
    }

    /**
     * Route one datagram through the gateway. Caller holds [lock]. Returns the inner IP
     * packet for Multicast Data, null otherwise.
     */
    private fun dispatch(datagram: ByteArray): ByteArray? {
        val gw = gateway ?: return null
        try {
            when (AmtWire.messageType(datagram)) {
                AmtWire.MULTICAST_DATA -> return gw.handleData(datagram)

                AmtWire.RELAY_ADVERTISEMENT -> {
                    gw.handleAdvertisement(datagram)
                    AmtWire.advertisedRelayAddress(datagram)
                        ?.takeUnless { it.isAnyLocalAddress }
                        ?.let { relay = InetSocketAddress(it, relayPort) }
                    discovered = true
                    changed.signalAll()
                }

                AmtWire.MEMBERSHIP_QUERY -> {
                    gw.handleQuery(datagram)
                    if (channels.isEmpty()) {
                        // A Query for a join that was since abandoned: nothing to report.
                        gw.reset()
                        return null
                    }
                    gw.rebindTeardown()?.let(::sendToRelay)
                    for ((source, members) in channels.groupBy { it.source }) {
                        val report = IgmpSsm.joinReport(source.literal, members.map { it.group.literal })
                        sendToRelay(gw.sendUpdate(report))
                    }
                    updatesSent++
                    lastRefreshAt = System.nanoTime()
                    changed.signalAll()
                }

                else -> droppedDatagrams++
            }
        } catch (ignored: AmtException) {
            // Stale nonce, malformed datagram, or a message for a state we are not in.
            droppedDatagrams++
        }
        return null
    }

    /**
     * Refresh the tunnel when due (section 5.2.3.4.3). Caller holds [lock]. A Request from
     * ACTIVE reuses the tunnel nonce; the Query it draws is answered in [dispatch]. A lost
     * refresh is retried one interval later, so the interval must be a fraction of the
     * relay's membership timer.
     */
    private fun tick() {
        val gw = gateway ?: return
        if (channels.isEmpty() || gw.state != AmtGateway.State.ACTIVE) return
        if (System.nanoTime() - lastRefreshAt < refreshNanos) return
        lastRefreshAt = System.nanoTime()
        sendToRelay(gw.requestMembership())
    }

    /** Dotted-quad text for the native builders, which take strings. */
    private val Inet4Address.literal: String
        get() = checkNotNull(hostAddress)

    private companion object {
        /** Receive timeout, which doubles as the refresh check period. */
        const val TICK_MILLIS = 1_000

        /** Largest UDP datagram. */
        const val MAX_DATAGRAM = 65_535
    }
}
