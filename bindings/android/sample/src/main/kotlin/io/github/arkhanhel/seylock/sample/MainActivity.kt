// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi

package io.github.arkhanhel.seylock.sample

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import io.github.arkhanhel.seylock.SeyLock
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

/**
 * Starts SeyLock with a one-path list and sends one HTTPS request through it.
 * A real application verifies a signed list with [SeyLock.verifyList] first;
 * see INTEGRATING.md.
 */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val view = TextView(this).apply { setPadding(48, 48, 48, 48) }
        setContentView(view)
        thread {
            val result = runCatching { oneRequest() }.getOrElse { "failed: $it" }
            Log.i(TAG, result)
            runOnUiThread { view.text = result }
        }
    }

    private fun oneRequest(): String {
        val policy = """
            {"list":{"v":2,"issued_at_ms":1,"expires_at_ms":9000000000000,
             "services":{"api":"https://example.com"},"paths":[{"kind":"direct"}]},
             "network_id":"sample","race":{},"response_timeout_ms":20000}
        """.trimIndent()
        val proxy = SeyLock.start(policy)
        try {
            val conn = proxy.url(URL("https://example.com/")).openConnection() as HttpURLConnection
            proxy.headers("api").forEach { (k, v) -> conn.setRequestProperty(k, v) }
            return "SeyLock ${SeyLock.version}: HTTP ${conn.responseCode} " +
                "via ${conn.getHeaderField("x-transport-path")}"
        } finally {
            SeyLock.stop()
        }
    }

    private companion object {
        const val TAG = "SeyLockSample"
    }
}
