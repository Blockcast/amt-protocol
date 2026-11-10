package com.blockcast.amt

import java.net.InetAddress
import java.net.SocketAddress

/**
 * The few bytes of RFC 7450 and IPv4 framing the host side needs to route datagrams.
 * Everything else is decoded natively. Pure Kotlin, no native library.
 */
object AmtWire {
    /** AMT message types (RFC 7450 section 5.1.1): the value of the first octet. */
    const val RELAY_DISCOVERY = 1
    const val RELAY_ADVERTISEMENT = 2
    const val REQUEST = 3
    const val MEMBERSHIP_QUERY = 4
    const val MEMBERSHIP_UPDATE = 5
    const val MULTICAST_DATA = 6
    const val TEARDOWN = 7

    /**
     * Message type of an AMT [datagram], or -1 when it is empty. The version nibble is
     * included on purpose: the native decoder requires it to be zero as well.
     */
    fun messageType(datagram: ByteArray): Int =
        if (datagram.isEmpty()) -1 else datagram[0].toInt() and 0xFF

    /**
     * Whether a datagram of [type] from [from] may reach the gateway when [relay] is the
     * learned relay. Multicast Data carries no MAC and a Query's MAC only binds the nonce,
     * so both must come from the relay. Everything else passes: an anycast discovery reply
     * may come from the relay's unicast address, and the native side checks its nonce.
     */
    fun acceptedFrom(type: Int, from: SocketAddress, relay: SocketAddress?): Boolean =
        (type != MULTICAST_DATA && type != MEMBERSHIP_QUERY) || from == relay

    /**
     * Relay unicast address carried in a Relay Advertisement (section 5.1.2), where the
     * gateway sends every later message (section 5.2.3.4.3). Octets 8.. hold an IPv4 or
     * IPv6 address, so the datagram is 12 or 24 octets long; null for anything else.
     */
    fun advertisedRelayAddress(datagram: ByteArray): InetAddress? {
        if (messageType(datagram) != RELAY_ADVERTISEMENT) return null
        return when (datagram.size) {
            12, 24 -> InetAddress.getByAddress(datagram.copyOfRange(8, datagram.size))
            else -> null
        }
    }

    /**
     * UDP payload of an IPv4 [ipPacket] as [AmtGateway.handleData] returns it, or null
     * when the packet is not IPv4/UDP or is truncated. Multicast media (RTP, MPEG-TS,
     * MMTP) travels here. IPv6 is not handled: this module's joins are IPv4 only.
     */
    fun udpPayload(ipPacket: ByteArray): ByteArray? {
        if (ipPacket.size < 20 || (ipPacket[0].toInt() and 0xFF) ushr 4 != 4) return null
        val ihl = (ipPacket[0].toInt() and 0x0F) * 4
        if (ihl < 20 || (ipPacket[9].toInt() and 0xFF) != 17 || ipPacket.size < ihl + 8) return null
        val totalLength = u16(ipPacket, 2)
        val udpLength = u16(ipPacket, ihl + 4)
        val end = minOf(ipPacket.size, totalLength, ihl + udpLength)
        if (end < ihl + 8) return null
        return ipPacket.copyOfRange(ihl + 8, end)
    }

    private fun u16(bytes: ByteArray, at: Int): Int =
        ((bytes[at].toInt() and 0xFF) shl 8) or (bytes[at + 1].toInt() and 0xFF)
}
