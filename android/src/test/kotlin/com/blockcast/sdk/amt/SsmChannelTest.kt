package com.blockcast.sdk.amt

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/** Pure-Kotlin argument validation and error mapping; nothing here loads the native library. */
class SsmChannelTest {
    @Test
    fun acceptsAnIpv4SsmChannel() {
        val channel = SsmChannel("203.0.113.9", "232.1.1.1")
        assertEquals("203.0.113.9", channel.source.hostAddress)
        assertEquals("232.1.1.1", channel.group.hostAddress)
        assertEquals("(203.0.113.9,232.1.1.1)", channel.toString())
        assertEquals(channel, SsmChannel("203.0.113.9", "232.1.1.1"))
        assertEquals(setOf(channel), setOf(channel, SsmChannel("203.0.113.9", "232.1.1.1")))
    }

    @Test
    fun anySourceGroupsAreAllowed() {
        assertEquals("239.255.0.1", SsmChannel("203.0.113.9", "239.255.0.1").group.hostAddress)
    }

    @Test
    fun rejectsBadAddresses() {
        val bad = listOf(
            "relay.example.net" to "232.1.1.1", // hostname: no DNS here
            "2001:db8::9" to "232.1.1.1", // IPv6: the native join builder is IPv4 only
            "203.0.113.9" to "10.1.2.3", // group is unicast
            "232.1.1.1" to "232.1.1.2", // source is multicast
            "203.0.113.9" to "256.1.1.1", // octet out of range
            "203.0.113.09" to "232.1.1.1", // leading zero
            "203.0.113" to "232.1.1.1", // three octets
            "" to "232.1.1.1",
            "203.0.113.9 " to "232.1.1.1", // trailing space
        )
        for ((source, group) in bad) {
            assertThrows("$source -> $group", IllegalArgumentException::class.java) { SsmChannel(source, group) }
        }
    }

    @Test
    fun parseIpv4IsStrict() {
        assertEquals("0.0.0.0", SsmChannel.parseIpv4("0.0.0.0")!!.hostAddress)
        assertEquals("255.255.255.255", SsmChannel.parseIpv4("255.255.255.255")!!.hostAddress)
        assertNull(SsmChannel.parseIpv4("1.2.3"))
        assertNull(SsmChannel.parseIpv4("1.2.3.4.5"))
        assertNull(SsmChannel.parseIpv4("+1.2.3.4"))
        assertNull(SsmChannel.parseIpv4("1.2.3.0x4"))
        assertNull(SsmChannel.parseIpv4("1.2.3.004"))
        assertNull(SsmChannel.parseIpv4("1..3.4"))
    }

    @Test
    fun advertisementCodesMapToErrors() {
        assertEquals(AmtError.CLOSED, AmtError.forAdvertisementCode(-1, wasDiscovering = true))
        assertEquals(AmtError.REJECTED, AmtError.forAdvertisementCode(-2, wasDiscovering = true))
        assertEquals(AmtError.DECODE_ERROR, AmtError.forAdvertisementCode(-3, wasDiscovering = true))
        assertEquals(AmtError.INVALID_NONCE, AmtError.forAdvertisementCode(-4, wasDiscovering = true))
        assertEquals(AmtError.INVALID_STATE, AmtError.forAdvertisementCode(-4, wasDiscovering = false))
        assertEquals(AmtError.UNEXPECTED_MESSAGE, AmtError.forAdvertisementCode(-5, wasDiscovering = true))
        assertEquals(AmtError.REJECTED, AmtError.forAdvertisementCode(-42, wasDiscovering = true))
        assertEquals("DECODE_ERROR: bad", AmtException(AmtError.DECODE_ERROR, "bad").message)
    }

    @Test
    fun sessionValidatesItsArgumentsWithoutTouchingTheNetwork() {
        val listener = object : AmtSession.Listener {
            override fun onPacket(ipPacket: ByteArray) = Unit
        }
        assertThrows(IllegalArgumentException::class.java) { AmtSession("relay.example.net", listener, relayPort = 0) }
        assertThrows(IllegalArgumentException::class.java) { AmtSession("relay.example.net", listener, relayPort = 65_536) }
        assertThrows(IllegalArgumentException::class.java) { AmtSession("relay.example.net", listener, attempts = 0) }
        assertThrows(IllegalArgumentException::class.java) { AmtSession("relay.example.net", listener, replyTimeoutMillis = 0) }
        assertThrows(IllegalArgumentException::class.java) { AmtSession("relay.example.net", listener, receiveBufferBytes = -1) }

        val session = AmtSession("relay.example.net", listener)
        assertNull(session.state) // not open
        assertEquals(emptySet<SsmChannel>(), session.joinedChannels)
        assertThrows(AmtException::class.java) { session.join(SsmChannel("203.0.113.9", "232.1.1.1")) }
        session.close() // never opened: a no-op
    }
}
