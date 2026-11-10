package com.blockcast.amt

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/** [Driad] query/answer round trip through the natives. Needs the host libamt_protocol.so. */
class DriadTest {
    @Before
    fun needsNative() {
        assumeTrue("host libamt_protocol.so not given (-PamtNativeDir)", System.getProperty("amt.nativeDir") != null)
    }

    @Test
    fun picksTheLowestPrecedenceRelay() {
        val query = Driad.dnsQuery("203.0.113.9", 0x1234)
        assertArrayEquals(byteArrayOf(0x12, 0x34), query.copyOfRange(0, 2))
        val response = answer(
            query,
            amtRelay(precedence = 20, ipv4 = byteArrayOf(198.toByte(), 51, 100, 2)),
            amtRelay(precedence = 10, ipv4 = byteArrayOf(198.toByte(), 51, 100, 1)),
        )
        assertEquals("198.51.100.1", Driad.relayFromResponse(query, response))
    }

    @Test
    fun rejectsAnAnswerToAnotherQuery() {
        val query = Driad.dnsQuery("203.0.113.9", 0x1234)
        val response = answer(Driad.dnsQuery("203.0.113.9", 0x4321), amtRelay(10, byteArrayOf(198.toByte(), 51, 100, 1)))
        assertNull(Driad.relayFromResponse(query, response))
    }

    @Test(expected = AmtException::class)
    fun refusesANonLiteralSource() {
        Driad.dnsQuery("not-an-ip", 1)
    }

    /** RDATA of an AMTRELAY record (RFC 8777 section 4.2): D-bit clear, relay type 1. */
    private fun amtRelay(precedence: Int, ipv4: ByteArray) = byteArrayOf(precedence.toByte(), 0x01) + ipv4

    /** A response to [query]: its header and question, then one AMTRELAY answer per [rdatas]. */
    private fun answer(query: ByteArray, vararg rdatas: ByteArray): ByteArray {
        val opt = 11 // the EDNS(0) OPT record dnsQuery appends
        val out = query.copyOf(query.size - opt)
        out[2] = (out[2].toInt() or 0x80).toByte() // QR
        out[7] = rdatas.size.toByte() // ANCOUNT
        out[11] = 0 // ARCOUNT
        var msg = out
        for (rdata in rdatas) {
            msg += byteArrayOf(0xC0.toByte(), 0x0C, 0x01, 0x04, 0x00, 0x01, 0, 0, 0x0E, 0x10, 0, rdata.size.toByte()) + rdata
        }
        return msg
    }
}
