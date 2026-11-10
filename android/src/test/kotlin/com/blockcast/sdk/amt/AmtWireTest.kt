package com.blockcast.sdk.amt

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AmtWireTest {
    @Test
    fun messageTypeIsTheFirstOctet() {
        assertEquals(AmtWire.RELAY_DISCOVERY, AmtWire.messageType(byteArrayOf(1, 0, 0, 0, 1, 2, 3, 4)))
        assertEquals(AmtWire.MULTICAST_DATA, AmtWire.messageType(byteArrayOf(6, 0, 0x45)))
        assertEquals(-1, AmtWire.messageType(ByteArray(0)))
        // A non-zero version nibble is not masked off: the native decoder rejects it too.
        assertEquals(0x16, AmtWire.messageType(byteArrayOf(0x16)))
    }

    @Test
    fun advertisedRelayAddressIpv4() {
        val adv = byteArrayOf(2, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 198.toByte(), 51, 100, 7)
        assertEquals("198.51.100.7", AmtWire.advertisedRelayAddress(adv)!!.hostAddress)
    }

    @Test
    fun advertisedRelayAddressIpv6() {
        val v6 = ByteArray(16).also {
            it[0] = 0x20
            it[1] = 0x01
            it[2] = 0x0d
            it[3] = 0xb8.toByte()
            it[15] = 1
        }
        val adv = byteArrayOf(2, 0, 0, 0, 0, 0, 0, 0) + v6
        assertEquals("2001:db8:0:0:0:0:0:1", AmtWire.advertisedRelayAddress(adv)!!.hostAddress)
    }

    @Test
    fun advertisedRelayAddressRejectsOtherShapes() {
        assertNull(AmtWire.advertisedRelayAddress(byteArrayOf(2, 0, 0, 0, 1, 2, 3, 4))) // no address
        assertNull(AmtWire.advertisedRelayAddress(byteArrayOf(2, 0, 0, 0, 1, 2, 3, 4, 10, 0, 0))) // truncated
        assertNull(AmtWire.advertisedRelayAddress(byteArrayOf(4, 0, 0, 0, 1, 2, 3, 4, 10, 0, 0, 1))) // a Query
        assertNull(AmtWire.advertisedRelayAddress(ByteArray(0)))
    }

    @Test
    fun udpPayloadStripsIpv4AndUdpHeaders() {
        val payload = "hello".toByteArray()
        assertArrayEquals(payload, AmtWire.udpPayload(ipv4Udp(payload)))
        // IHL=6: a Router Alert option, as the IGMP encapsulation uses.
        assertArrayEquals(payload, AmtWire.udpPayload(ipv4Udp(payload, options = byteArrayOf(0x94.toByte(), 4, 0, 0))))
    }

    @Test
    fun udpPayloadHonoursTheLengthFields() {
        val padded = ipv4Udp("hello".toByteArray()) + byteArrayOf(9, 9, 9) // bytes past Total Length
        assertArrayEquals("hello".toByteArray(), AmtWire.udpPayload(padded))
    }

    @Test
    fun udpPayloadRejectsNonUdpAndTruncatedPackets() {
        val tcp = ipv4Udp("x".toByteArray()).also { it[9] = 6 }
        assertNull(AmtWire.udpPayload(tcp))
        assertNull(AmtWire.udpPayload(ipv4Udp("hello".toByteArray()).copyOf(25))) // cut inside the UDP header
        assertNull(AmtWire.udpPayload(ByteArray(0)))
        assertNull(AmtWire.udpPayload(ByteArray(48).also { it[0] = 0x60 })) // IPv6
    }

    /** Minimal IPv4+UDP packet from 203.0.113.9:5000 to 232.1.1.1:5004, checksums zero. */
    private fun ipv4Udp(payload: ByteArray, options: ByteArray = ByteArray(0)): ByteArray {
        val ihl = 20 + options.size
        val total = ihl + 8 + payload.size
        val header = ByteArray(ihl)
        header[0] = (0x40 or (ihl / 4)).toByte()
        header[2] = (total ushr 8).toByte()
        header[3] = total.toByte()
        header[8] = 64
        header[9] = 17
        byteArrayOf(203.toByte(), 0, 113, 9).copyInto(header, 12)
        byteArrayOf(232.toByte(), 1, 1, 1).copyInto(header, 16)
        options.copyInto(header, 20)
        val udpLength = 8 + payload.size
        val udp = byteArrayOf(
            0x13, 0x88.toByte(), 0x13, 0x8c.toByte(),
            (udpLength ushr 8).toByte(), udpLength.toByte(), 0, 0,
        )
        return header + udp + payload
    }
}
