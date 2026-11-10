package com.blockcast.amt

import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketException
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * [AmtSession] against a loopback fake relay. Needs the host libamt_protocol.so; see
 * `amtNativeDir` in build.gradle.kts.
 */
class AmtSessionTest {
    @Test
    fun refreshesTheTunnelWhileDataIsFlowing() {
        assumeTrue("host libamt_protocol.so not given (-PamtNativeDir)", System.getProperty("amt.nativeDir") != null)
        FakeRelay().use { relay ->
            val received = AtomicInteger()
            AmtSession(
                "127.0.0.1",
                object : AmtSession.Listener {
                    override fun onPacket(ipPacket: ByteArray) {
                        received.incrementAndGet()
                    }
                },
                relayPort = relay.port,
                refreshIntervalMillis = 200,
            ).use { session ->
                session.open()
                session.join(SsmChannel("203.0.113.9", "232.1.1.1"))
                // Data every 5 ms, so receive() never reaches its 1 s timeout.
                Thread.sleep(1_500)
                assertTrue("no data reached the listener", received.get() > 100)
                assertTrue("no refresh Request while data flowed: ${relay.requests.get()}", relay.requests.get() >= 3)
            }
        }
    }

    /** Advertisement, Query, then Multicast Data every 5 ms once an Update arrives (RFC 7450 section 5.1). */
    private class FakeRelay : AutoCloseable {
        private val socket = DatagramSocket(0, InetAddress.getLoopbackAddress())
        val port: Int = socket.localPort
        val requests = AtomicInteger()

        @Volatile
        private var gateway: InetSocketAddress? = null

        init {
            thread(isDaemon = true) { serve() }
            thread(isDaemon = true) { stream() }
        }

        private fun serve() {
            val buffer = ByteArray(2048)
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                while (true) {
                    socket.receive(packet)
                    val nonce = buffer.copyOfRange(4, 8)
                    val reply = when (buffer[0].toInt()) {
                        1 -> byteArrayOf(2, 0, 0, 0) + nonce + byteArrayOf(127, 0, 0, 1)
                        3 -> {
                            requests.incrementAndGet()
                            // Type, flags, Response MAC, Request Nonce, then an opaque query.
                            byteArrayOf(4, 0, 1, 2, 3, 4, 5, 6) + nonce + ByteArray(8)
                        }
                        5 -> {
                            gateway = packet.socketAddress as InetSocketAddress
                            null
                        }
                        else -> null
                    } ?: continue
                    socket.send(DatagramPacket(reply, reply.size, packet.socketAddress))
                }
            } catch (closed: SocketException) {
            }
        }

        private fun stream() {
            val data = byteArrayOf(6, 0) + ByteArray(28)
            try {
                while (true) {
                    gateway?.let { socket.send(DatagramPacket(data, data.size, it)) }
                    Thread.sleep(5)
                }
            } catch (closed: SocketException) {
            }
        }

        override fun close() = socket.close()
    }
}
