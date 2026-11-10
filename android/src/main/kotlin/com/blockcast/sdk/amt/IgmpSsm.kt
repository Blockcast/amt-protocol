package com.blockcast.sdk.amt

/**
 * IGMPv3 source-specific join reports (RFC 3376), IP-encapsulated the way the relay
 * expects, for [AmtGateway.sendUpdate].
 *
 * IPv4 only: the JNI surface exports no MLDv2 builder and no leave report.
 */
object IgmpSsm {
    init {
        System.loadLibrary("amt_protocol")
    }

    /**
     * Report joining one (S,G) channel.
     *
     * @throws AmtException [AmtError.INVALID_ADDRESS] when either argument is not an IPv4 literal.
     */
    @JvmStatic
    fun joinReport(source: String, group: String): ByteArray =
        nativeCreateJoinReport(source, group)
            ?: throw AmtException(AmtError.INVALID_ADDRESS, "not IPv4 literals: source=$source group=$group")

    /**
     * Report joining several [groups] from one [source].
     *
     * @throws IllegalArgumentException when [groups] is empty.
     * @throws AmtException [AmtError.INVALID_ADDRESS] when an argument is not an IPv4 literal.
     */
    @JvmStatic
    fun joinReport(source: String, groups: List<String>): ByteArray {
        require(groups.isNotEmpty()) { "groups is empty" }
        return nativeCreateMultiJoinReport(source, groups.toTypedArray())
            ?: throw AmtException(AmtError.INVALID_ADDRESS, "not IPv4 literals: source=$source groups=$groups")
    }

    // Java_com_blockcast_sdk_amt_IgmpSsm_<name> in src/jni.rs.
    @JvmStatic private external fun nativeCreateJoinReport(sourceAddress: String, groupAddress: String): ByteArray?
    @JvmStatic private external fun nativeCreateMultiJoinReport(sourceAddress: String, groupAddresses: Array<String>): ByteArray?
}
