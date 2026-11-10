package com.blockcast.amt

import java.net.Inet4Address
import java.net.InetAddress

/**
 * A source-specific multicast channel: the (S,G) pair an [AmtSession] joins.
 *
 * Both addresses are IPv4, since the native join builder is ([IgmpSsm]). [group] must
 * be multicast; 232.0.0.0/8 is the SSM range (RFC 4607), but any-source groups are
 * accepted because relays forward (S,G) joins for them too.
 */
data class SsmChannel(
    /** Unicast IPv4 address of the sender. */
    val source: Inet4Address,
    /** IPv4 multicast group. */
    val group: Inet4Address,
) {
    init {
        require(!source.isMulticastAddress) { "source must be unicast: ${source.hostAddress}" }
        require(group.isMulticastAddress) { "group must be multicast (224.0.0.0/4): ${group.hostAddress}" }
    }

    /**
     * From IPv4 literals, parsed with [parseIpv4] (no DNS).
     *
     * @throws IllegalArgumentException when either is not an IPv4 literal, or the roles are wrong.
     */
    constructor(source: String, group: String) : this(ipv4(source, "source"), ipv4(group, "group"))

    override fun toString(): String = "(${source.hostAddress},${group.hostAddress})"

    companion object {
        /**
         * Strict dotted-quad parse: four decimal octets 0..255, no leading zeros (the
         * native parser rejects them too), no DNS. Null for anything else.
         */
        @JvmStatic
        fun parseIpv4(literal: String): Inet4Address? {
            val parts = literal.split('.')
            if (parts.size != 4) return null
            val bytes = ByteArray(4)
            for (i in 0..3) {
                val part = parts[i]
                val wellFormed = part.length in 1..3 &&
                    part.all { it in '0'..'9' } &&
                    (part.length == 1 || part[0] != '0')
                if (!wellFormed) return null
                val value = part.toInt()
                if (value > 255) return null
                bytes[i] = value.toByte()
            }
            return InetAddress.getByAddress(bytes) as Inet4Address
        }

        private fun ipv4(literal: String, role: String): Inet4Address =
            parseIpv4(literal) ?: throw IllegalArgumentException("$role is not an IPv4 literal: $literal")
    }
}
