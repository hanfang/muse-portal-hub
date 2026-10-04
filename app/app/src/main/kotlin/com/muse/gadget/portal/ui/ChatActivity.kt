package com.muse.gadget.portal.ui

import android.app.Activity
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.ListView
import android.widget.TextView
import com.muse.gadget.identity.Identity
import com.muse.gadget.pairing.PairingSession
import com.muse.gadget.portal.R

/**
 * Minimal chat UI skeleton: message list + input + send, backed by
 * `:protocol`. The real session wiring (ChatSession, SubscribeParser,
 * VoiceNoteEncoder) plugs into [onSendClicked] / [onTalkPressed].
 */
class ChatActivity : Activity() {
    private lateinit var adapter: ArrayAdapter<String>
    private val messages = ArrayList<String>()

    // Device identity: in production this is persisted (cf. identity.py).
    private val nodeId = "homelink-000001"
    private val pairingSession: PairingSession by lazy {
        PairingSession(
            nodeId = nodeId,
            deviceId = Identity.deviceId("02:00:00:00:00:01"),
            mac = "02:00:00:00:00:01",
            firmwareVersion = "0.1.0",
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat)

        adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, messages)
        findViewById<ListView>(R.id.messageList).adapter = adapter
        findViewById<TextView>(R.id.statusView).text =
            "BLE name: ${Identity.bleName(nodeId)} (model=${Identity.PAIRING_MODEL})"

        val input = findViewById<EditText>(R.id.inputView)
        findViewById<Button>(R.id.sendButton).setOnClickListener {
            onSendClicked(input.text.toString())
            input.text.clear()
        }
        findViewById<Button>(R.id.talkButton).setOnTouchListener { _, _ ->
            // TODO: hold-to-talk -> AudioRecord 16kHz mono -> VoiceNoteEncoder ->
            //       ChatStreams voice note -> ChatSession transport.
            false
        }
    }

    private fun onSendClicked(text: String) {
        if (text.isBlank()) return
        addMessage("you: $text")
        // TODO: ChatStreams.textBody(text, nodeId, sessionId=null) ->
        //       transport.encryptHttpRequest("POST", "/chat/stream", body, headers) ->
        //       WS binary frame. Replies arrive on /chat/subscribe -> SubscribeParser.
        addMessage("muse: … (session not connected in skeleton)")
    }

    private fun addMessage(line: String) {
        messages.add(line)
        adapter.notifyDataSetChanged()
    }
}
