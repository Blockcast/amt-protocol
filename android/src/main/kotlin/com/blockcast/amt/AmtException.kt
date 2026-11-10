package com.blockcast.amt

/**
 * Why an AMT operation failed.
 *
 * Most natives in `src/jni.rs` report failure as a null return, so the Kotlin layer
 * classifies it from what it knows: the argument it passed and the gateway state at
 * the time of the call.
 */
enum class AmtError {
    /** An address string is not the IP literal the native side expects (IPv4 for SSM joins). */
    INVALID_ADDRESS,

    /** The operation is not allowed in the gateway's current [AmtGateway.State] (RFC 7450 section 5.2). */
    INVALID_STATE,

    /** A Relay Advertisement carried a nonce that does not match the pending Relay Discovery. */
    INVALID_NONCE,

    /** The datagram is not a well-formed AMT message. */
    DECODE_ERROR,

    /** The datagram is a well-formed AMT message of a type this call does not accept. */
    UNEXPECTED_MESSAGE,

    /**
     * The native gateway refused the input for a reason the JNI surface does not report:
     * a nonce or MAC mismatch, a message of the wrong type, or a JNI conversion failure.
     */
    REJECTED,

    /** No reply from the relay within the configured timeout and attempts. */
    TIMEOUT,

    /** The gateway handle has been destroyed with [AmtGateway.close]. */
    CLOSED;

    internal companion object {
        /**
         * Map the result code of `nativeHandleAdvertisement` (src/jni.rs) to an error.
         *
         * `-4` covers both "wrong state" and "nonce mismatch" on the native side;
         * [wasDiscovering], the state read before the call, splits them.
         */
        fun forAdvertisementCode(code: Int, wasDiscovering: Boolean): AmtError = when (code) {
            -1 -> CLOSED
            -2 -> REJECTED
            -3 -> DECODE_ERROR
            -4 -> if (wasDiscovering) INVALID_NONCE else INVALID_STATE
            -5 -> UNEXPECTED_MESSAGE
            else -> REJECTED
        }
    }
}

/** Thrown by every AMT operation in this module; [error] says why. */
class AmtException(val error: AmtError, message: String, cause: Throwable? = null) :
    Exception("$error: $message", cause)
