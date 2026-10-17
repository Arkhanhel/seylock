// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//
// Kotlin API for SeyLock: reach your own servers from networks that block
// them. A thin layer over the C ABI in include/seylock.h, through JNA; see
// README.md and PROTOCOL.md for what the calls do.

package io.github.arkhanhel.seylock

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.ptr.PointerByReference
import com.sun.jna.ptr.ShortByReference
import java.net.URL

/** The C functions, bound by JNA. Internal: use [SeyLock]. */
@Suppress("FunctionName")
internal interface Ffi : Library {
    fun seylock_version(): Pointer?
    fun seylock_endpoints_verify(
        signedJson: String,
        verifyingKeyB64: String,
        nowMs: Long,
        currentIssuedAtMs: Long,
        outDoc: PointerByReference?,
    ): Int
    fun seylock_start(policyJson: String, outPort: ShortByReference, outToken: PointerByReference): Int
    fun seylock_update(policyJson: String): Int
    fun seylock_set_network(networkId: String): Int
    fun seylock_status_json(): Pointer?
    fun seylock_stop(): Int
    fun seylock_string_free(s: Pointer?)

    companion object {
        val lib: Ffi by lazy {
            Native.load("seylock", Ffi::class.java, mapOf(Library.OPTION_STRING_ENCODING to "UTF-8"))
        }
    }
}

/** Why a SeyLock call failed. Raw codes follow include/seylock.h. */
sealed class SeyLockException(message: String) : Exception(message) {
    /** The endpoint list was rejected; [code] (1 to 11) names the rule it broke. */
    class ListRejected(val code: Int) : SeyLockException("endpoint list rejected (code $code)")
    /** `start` was called while a proxy is running. */
    class AlreadyRunning : SeyLockException("a proxy is already running")
    /** The call needs a running proxy and there is none. */
    class NotRunning : SeyLockException("no proxy is running")
    /** The loopback port could not be bound. */
    class BindFailed : SeyLockException("the loopback port could not be bound")
    /** The policy JSON is invalid. */
    class InvalidPolicy : SeyLockException("the policy JSON is invalid")
    /** An internal error or an invalid argument. */
    class Internal(val code: Int) : SeyLockException("internal error (code $code)")

    companion object {
        internal fun of(code: Int): SeyLockException = when (code) {
            in 1..99 -> ListRejected(code)
            101 -> AlreadyRunning()
            102 -> NotRunning()
            103 -> BindFailed()
            104 -> InvalidPolicy()
            else -> Internal(code)
        }
    }
}

/** A running SeyLock proxy: where it listens and the token it requires. */
data class Proxy(val port: Int, val token: String) {
    /**
     * The same URL, pointed at the local proxy: scheme, host and port are
     * replaced; path and query are kept.
     */
    fun url(original: URL): URL {
        val path = original.path.ifEmpty { "/" }
        val query = original.query?.let { "?$it" } ?: ""
        return URL("http", "127.0.0.1", port, path + query)
    }

    /** Headers to add to every request sent through the proxy to [service]. */
    fun headers(service: String): Map<String, String> =
        mapOf("x-transport-token" to token, "x-transport-service" to service)
}

/** The SeyLock library. All calls are safe from any thread. */
object SeyLock {
    private val ffi get() = Ffi.lib

    /** Library version, for example "0.2.0". */
    val version: String get() = take(ffi.seylock_version()) ?: ""

    /**
     * Verifies a signed endpoint list against the pinned Ed25519 public key and
     * returns the accepted list as JSON, ready for the policy.
     *
     * @param currentIssuedAtMs `issued_at_ms` of the list already accepted, or 0.
     * @param nowMs the device clock, Unix milliseconds.
     */
    fun verifyList(
        signedJson: String,
        publicKeyBase64: String,
        currentIssuedAtMs: Long = 0,
        nowMs: Long = System.currentTimeMillis(),
    ): String {
        val out = PointerByReference()
        val code = ffi.seylock_endpoints_verify(signedJson, publicKeyBase64, nowMs, currentIssuedAtMs, out)
        // Taken (and freed) whatever the outcome.
        val json = take(out.value)
        if (code != 0 || json == null) throw SeyLockException.of(if (code == 0) 100 else code)
        return json
    }

    /** Starts the process-wide proxy: `{"list": <accepted list>, "network_id": "...", "race": {}}`. */
    fun start(policyJson: String): Proxy {
        val port = ShortByReference()
        val token = PointerByReference()
        val code = ffi.seylock_start(policyJson, port, token)
        val tokenString = take(token.value)
        if (code != 0 || tokenString == null) throw SeyLockException.of(if (code == 0) 100 else code)
        return Proxy(port.value.toInt() and 0xFFFF, tokenString)
    }

    /** Replaces the list, network and permissions of the running proxy. */
    fun update(policyJson: String) = check(ffi.seylock_update(policyJson))

    /**
     * Tells the proxy the device changed networks. Pass an opaque id, for
     * example a salted hash of the Wi-Fi name, never the name itself.
     */
    fun setNetwork(networkId: String) = check(ffi.seylock_set_network(networkId))

    /** The running proxy's state as JSON, or null if none is running. */
    fun statusJson(): String? = take(ffi.seylock_status_json())

    /** Stops the proxy. Returns whether one was running. */
    fun stop(): Boolean = ffi.seylock_stop() == 0

    private fun check(code: Int) {
        if (code != 0) throw SeyLockException.of(code)
    }

    /** Copies a string returned by the library and frees the original. */
    private fun take(p: Pointer?): String? {
        if (p == null) return null
        return try {
            p.getString(0, "UTF-8")
        } finally {
            ffi.seylock_string_free(p)
        }
    }
}
