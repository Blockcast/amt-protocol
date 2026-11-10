package com.blockcast.amt.sample

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import com.blockcast.amt.AmtSession
import com.blockcast.amt.AmtWire
import com.blockcast.amt.Driad
import com.blockcast.amt.SsmChannel
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * Joins one (S,G) over AMT and counts datagrams. The relay comes from DRIAD unless one is
 * typed in. Values can also be passed as intent extras `source`, `group`, `relay`:
 * `adb shell am start -n com.blockcast.amt.sample/.MainActivity --es source 203.0.113.9 --es group 232.1.1.1`
 */
class MainActivity : Activity() {
    private val ui = Handler(Looper.getMainLooper())
    private val packets = AtomicLong()
    private val bytes = AtomicLong()
    private var session: AmtSession? = null

    // Bumped by every start()/stop(); a join thread whose generation is stale closes its own session.
    private var gen = 0
    private lateinit var status: TextView
    private lateinit var counter: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        fun field(hint: String, extra: String) = EditText(this).apply {
            this.hint = hint
            inputType = InputType.TYPE_CLASS_TEXT
            setText(intent.getStringExtra(extra) ?: "")
        }
        val source = field("source (S)", "source")
        val group = field("group (G)", "group")
        val relay = field("relay (blank: DRIAD)", "relay")
        status = TextView(this)
        counter = TextView(this)
        val join = Button(this).apply { text = "Join" }
        val leave = Button(this).apply { text = "Leave" }
        join.setOnClickListener {
            start(source.text.toString().trim(), group.text.toString().trim(), relay.text.toString().trim())
        }
        leave.setOnClickListener { stop() }
        setContentView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(32, 32, 32, 32)
                listOf(source, group, relay, join, leave, status, counter).forEach { addView(it) }
            },
        )
        ui.post(object : Runnable {
            override fun run() {
                counter.text = "packets ${packets.get()}  bytes ${bytes.get()}  dropped ${session?.droppedDatagrams ?: 0}"
                ui.postDelayed(this, 500)
            }
        })
    }

    private fun start(source: String, group: String, relayInput: String) {
        stop()
        val mine = synchronized(this) { ++gen }
        packets.set(0)
        bytes.set(0)
        thread(name = "amt-join") {
            var s: AmtSession? = null
            try {
                val channel = SsmChannel(source, group)
                val relay = relayInput.ifEmpty {
                    show("DRIAD lookup for $source…")
                    Driad.resolveRelay(source)
                }
                show("relay $relay: discovery…")
                s = AmtSession(
                    relay,
                    object : AmtSession.Listener {
                        override fun onPacket(ipPacket: ByteArray) {
                            packets.incrementAndGet()
                            bytes.addAndGet((AmtWire.udpPayload(ipPacket)?.size ?: 0).toLong())
                        }

                        override fun onStopped(error: Exception?) {
                            if (error != null) show("stopped: $error")
                        }
                    },
                    receiveBufferBytes = 4 shl 20,
                )
                if (!synchronized(this) { (gen == mine).also { if (it) session = s } }) return@thread s.close()
                s.open()
                // stop() may have closed s before open() ran; open() would then have reopened it.
                if (synchronized(this) { gen != mine }) return@thread s.close()
                s.join(channel)
                show("joined $channel via $relay")
            } catch (e: Exception) {
                show("failed: $e")
                synchronized(this) { if (session === s) session = null }
                s?.close()
            }
        }
    }

    private fun stop() {
        val s = synchronized(this) {
            gen++
            session.also { session = null }
        } ?: return
        thread(name = "amt-close") { s.close() }
    }

    private fun show(text: String) = ui.post { status.text = text }

    override fun onDestroy() {
        stop()
        ui.removeCallbacksAndMessages(null)
        super.onDestroy()
    }
}
