package com.blockcast.amt

/**
 * DRIAD (RFC 8777) helpers.
 *
 * The JNI surface exports only the query-name step. The AMTRELAY record lookup and
 * its RDATA decoding live in the crate (`src/driad.rs`) but are not exported, so
 * resolve the name with a DNS client that can ask for TYPE 260
 * (`android.net.DnsResolver.rawQuery` on API 29+), decode the answer, and hand the
 * relay address to [AmtGateway.create] or [AmtSession].
 */
object Driad {
    init {
        System.loadLibrary("amt_protocol")
    }

    /**
     * Reverse-DNS name whose AMTRELAY records name relays for a multicast [source]
     * (RFC 8777 section 4.1): `d.c.b.a.in-addr.arpa` for IPv4, the nibble form under
     * `ip6.arpa` for IPv6.
     *
     * @throws AmtException [AmtError.INVALID_ADDRESS] when [source] is not an IP literal.
     */
    @JvmStatic
    fun queryName(source: String): String =
        nativeBuildQuery(source) ?: throw AmtException(AmtError.INVALID_ADDRESS, "not an IP literal: $source")

    // Java_com_blockcast_amt_Driad_nativeBuildQuery in src/jni.rs.
    @JvmStatic private external fun nativeBuildQuery(sourceAddress: String): String?
}
