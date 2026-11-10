package com.blockcast.amt

import android.annotation.TargetApi
import android.net.DnsResolver
import android.net.Network
import android.os.Build
import android.os.CancellationSignal
import java.io.IOException
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit

/**
 * DRIAD (RFC 8777): find the AMT relay for a multicast source from its AMTRELAY records.
 *
 * ```kotlin
 * val relay = Driad.resolveRelay("203.0.113.9")   // API 29+, blocks
 * AmtSession(relay, listener).apply { open(); join(SsmChannel("203.0.113.9", "232.1.1.1")) }
 * ```
 *
 * The query is built and the answer decoded by the crate (`src/driad.rs`); only the
 * transport is Android's. Below API 29, send [dnsQuery] with your own DNS client and pass
 * the answer to [relayFromResponse].
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

    /**
     * DNS query message for the AMTRELAY records of [source], with an EDNS(0) OPT record
     * so a resolver can return every relay. [transactionId] must be in 0..0xFFFF; higher
     * bits are dropped.
     *
     * @throws AmtException [AmtError.INVALID_ADDRESS] when [source] is not an IP literal.
     */
    @JvmStatic
    fun dnsQuery(source: String, transactionId: Int): ByteArray =
        nativeBuildDnsQuery(source, transactionId)
            ?: throw AmtException(AmtError.INVALID_ADDRESS, "not an IP literal: $source")

    /**
     * The relay to use from the DNS answer to [query]: an IP literal, or a host name that
     * [AmtSession] resolves. Lowest precedence wins, random among equals (RFC 8777
     * section 4.2.1). Null when the answer's transaction ID or question does not match
     * [query], or it holds no usable AMTRELAY record.
     */
    @JvmStatic
    fun relayFromResponse(query: ByteArray, response: ByteArray): String? = nativeParseDnsResponse(query, response)

    /**
     * Look up the relay for [source] through the system resolver of [network] (null for the
     * default network). Blocks: not for the main thread.
     *
     * @throws AmtException [AmtError.INVALID_ADDRESS] when [source] is not an IP literal.
     * @throws IOException when the lookup fails, times out, or returns no usable relay.
     * @throws UnsupportedOperationException below API 29.
     */
    @JvmStatic
    @JvmOverloads
    @TargetApi(29)
    @Throws(IOException::class)
    fun resolveRelay(source: String, network: Network? = null, timeoutMillis: Long = 5_000): String {
        if (Build.VERSION.SDK_INT < 29) throw UnsupportedOperationException("DnsResolver.rawQuery needs API 29")
        val query = dnsQuery(source, random.nextInt(0x10000))
        val done = CountDownLatch(1)
        var answer: ByteArray? = null
        var answerRcode = 0
        var failure: Exception? = null
        val cancel = CancellationSignal()
        DnsResolver.getInstance().rawQuery(
            network, query, DnsResolver.FLAG_EMPTY, Executor { it.run() }, cancel,
            object : DnsResolver.Callback<ByteArray> {
                override fun onAnswer(a: ByteArray, rcode: Int) {
                    answer = a
                    answerRcode = rcode
                    done.countDown()
                }

                override fun onError(e: DnsResolver.DnsException) {
                    failure = e
                    done.countDown()
                }
            },
        )
        val answered = try {
            done.await(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
            cancel.cancel()
            Thread.currentThread().interrupt()
            throw java.io.InterruptedIOException("AMTRELAY lookup for $source interrupted")
        }
        if (!answered) {
            cancel.cancel()
            throw IOException("AMTRELAY lookup for $source timed out")
        }
        failure?.let { throw IOException("AMTRELAY lookup for $source failed", it) }
        return relayFromResponse(query, checkNotNull(answer))
            ?: throw IOException("no usable AMTRELAY record for $source (${queryName(source)}, rcode $answerRcode)")
    }

    private val random = SecureRandom()

    // Java_com_blockcast_amt_Driad_native* in src/jni.rs.
    @JvmStatic private external fun nativeBuildQuery(sourceAddress: String): String?
    @JvmStatic private external fun nativeBuildDnsQuery(sourceAddress: String, transactionId: Int): ByteArray?
    @JvmStatic private external fun nativeParseDnsResponse(query: ByteArray, response: ByteArray): String?
}
