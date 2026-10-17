// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//
// Runs on an Android device or emulator: the library is the AAR's own
// libseylock.so, loaded by JNA's Android build.

package io.github.arkhanhel.seylock

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.ServerSocket
import java.net.URL
import kotlin.concurrent.thread
import android.security.NetworkSecurityPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SeyLockDeviceTest {
    /** The shipped configuration opens plain HTTP to the proxy and nowhere else. */
    @Test
    fun shippedNetworkSecurityConfigAllowsOnlyLoopback() {
        val policy = NetworkSecurityPolicy.getInstance()
        assertTrue(policy.isCleartextTrafficPermitted("127.0.0.1"))
        assertFalse(policy.isCleartextTrafficPermitted("example.org"))
        assertFalse(policy.isCleartextTrafficPermitted("localhost"))
    }

    @Test
    fun aRequestGoesThroughTheProxyOnAndroid() {
        assertTrue(SeyLock.version.startsWith("0."))
        try {
            SeyLock.verifyList("not json", "AAAA"); fail("expected a rejection")
        } catch (e: SeyLockException.ListRejected) {
            assertEquals(1, e.code)
        }

        val server = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        thread(isDaemon = true) {
            while (!server.isClosed) {
                val socket = runCatching { server.accept() }.getOrNull() ?: break
                socket.use { s ->
                    val line = s.getInputStream().bufferedReader().readLine() ?: ""
                    val body = "path=${line.split(' ').getOrElse(1) { "?" }}"
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
                 "paths":[{"kind":"direct"}]},"network_id":"device","race":{}}
            """.trimIndent()
            val proxy = SeyLock.start(policy)
            try {
                val conn = proxy.url(URL("https://api.example.org/hello")).openConnection() as HttpURLConnection
                proxy.headers("api").forEach { (k, v) -> conn.setRequestProperty(k, v) }
                assertEquals(200, conn.responseCode)
                assertEquals("direct", conn.getHeaderField("x-transport-path"))
                assertEquals("path=/hello", conn.inputStream.bufferedReader().readText())
            } finally {
                assertTrue(SeyLock.stop())
            }
        } finally {
            server.close()
        }
    }
}
