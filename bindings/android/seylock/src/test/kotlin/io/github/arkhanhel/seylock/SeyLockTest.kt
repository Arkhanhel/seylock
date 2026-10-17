// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//
// Runs on the build machine's JVM against the host build of the library
// (cargo build --release), so the Kotlin layer is tested without a device.

package io.github.arkhanhel.seylock

import java.io.File
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.ServerSocket
import kotlin.concurrent.thread
import java.net.URL
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The proxy is process-wide; only [endToEndThroughTheProxy] starts it. */
class SeyLockTest {
    @Test
    fun version() {
        assertTrue(SeyLock.version, SeyLock.version.startsWith("0."))
    }

    @Test
    fun rejectedListsAreTypedErrors() {
        try {
            SeyLock.verifyList("not json", "AAAA")
            fail("expected a rejection")
        } catch (e: SeyLockException.ListRejected) {
            assertEquals(1, e.code)
        }
    }

    /** A signed list from the test vectors verifies through the Kotlin API. */
    @Test
    fun acceptsASignedVector() {
        val file = File(System.getProperty("seylock.vectors")).readText()
        val key = Regex("\"public_key_b64\":\\s*\"([^\"]+)\"").find(file)!!.groupValues[1]
        // The fields of one vector, from its name to the next vector's name
        // (keys are sorted, so now_ms and signed follow name).
        val block = file.substringAfter("\"name\": \"v2 accepted\"").substringBefore("\"name\":")
        val nowMs = Regex("\"now_ms\":\\s*(\\d+)").find(block)!!.groupValues[1].toLong()
        val signed = jsonString(Regex("\"signed\":\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").find(block)!!.groupValues[1])
        val json = SeyLock.verifyList(signed, key, nowMs = nowMs)
        assertTrue(json, json.contains("\"v\":2"))
    }

    /** Decodes the body of a JSON string literal. */
    private fun jsonString(raw: String): String {
        val out = StringBuilder()
        var i = 0
        while (i < raw.length) {
            val c = raw[i]
            if (c != '\\') { out.append(c); i++; continue }
            when (val e = raw[i + 1]) {
                'n' -> out.append('\n')
                't' -> out.append('\t')
                'r' -> out.append('\r')
                'u' -> { out.append(raw.substring(i + 2, i + 6).toInt(16).toChar()); i += 4 }
                else -> out.append(e)
            }
            i += 2
        }
        return out.toString()
    }

    @Test
    fun urlAndHeaders() {
        val proxy = Proxy(4567, "t0k")
        assertEquals(
            URL("http://127.0.0.1:4567/v1/send?x=1"),
            proxy.url(URL("https://user:pw@api.example.org/v1/send?x=1")),
        )
        assertEquals(URL("http://127.0.0.1:4567/"), proxy.url(URL("https://api.example.org")))
        assertEquals(
            mapOf("x-transport-token" to "t0k", "x-transport-service" to "api"),
            proxy.headers("api"),
        )
    }

    /** HttpURLConnection -> SeyLock proxy -> a local HTTP server, and the lifecycle. */
    @Test
    fun endToEndThroughTheProxy() {
        // A minimal HTTP server on loopback that answers with the request
        // path (android.jar has no com.sun.net.httpserver).
        val server = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        thread(isDaemon = true) {
            while (!server.isClosed) {
                val socket = runCatching { server.accept() }.getOrNull() ?: break
                socket.use { s ->
                    val requestLine = s.getInputStream().bufferedReader().readLine() ?: ""
                    val body = "path=${requestLine.split(' ').getOrElse(1) { "?" }}"
                    s.getOutputStream().write(
                        ("HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n" +
                            "Connection: close\r\n\r\n$body").toByteArray(),
                    )
                }
            }
        }
        try {
            val policy = """
                {"list":{"v":2,"issued_at_ms":1,"expires_at_ms":9000000000000,
                 "services":{"api":"http://127.0.0.1:${server.localPort}"},
                 "paths":[{"kind":"direct"}]},"network_id":"test","race":{}}
            """.trimIndent()
            assertNull(SeyLock.statusJson())
            try {
                SeyLock.update(policy); fail("expected NotRunning")
            } catch (_: SeyLockException.NotRunning) {
            }
            val proxy = SeyLock.start(policy)
            try {
                try {
                    SeyLock.start(policy); fail("expected AlreadyRunning")
                } catch (_: SeyLockException.AlreadyRunning) {
                }
                val conn = proxy.url(URL("https://api.example.org/hello")).openConnection() as HttpURLConnection
                proxy.headers("api").forEach { (k, v) -> conn.setRequestProperty(k, v) }
                assertEquals(200, conn.responseCode)
                assertEquals("direct", conn.getHeaderField("x-transport-path"))
                assertEquals("path=/hello", conn.inputStream.bufferedReader().readText())

                SeyLock.setNetwork("cell:1")
                assertTrue(SeyLock.statusJson()!!.contains("\"network_id\":\"cell:1\""))
                SeyLock.update(policy)
            } finally {
                assertTrue(SeyLock.stop())
            }
            assertFalse(SeyLock.stop())
        } finally {
            server.close()
        }
    }
}
