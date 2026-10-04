package com.muse.gadget.session

import com.muse.gadget.util.Json
import com.muse.gadget.util.JsonValue
import com.muse.gadget.util.boolField
import com.muse.gadget.util.field
import com.muse.gadget.util.strField

/**
 * NDJSON parser for `POST /chat/subscribe` events (spec §3.3).
 *
 * Rules (mirroring `muse_chat_session.cpp` `on_event`):
 * - lines without `type == "event"` are ignored (e.g. the `ack` line);
 * - only `seq` strictly greater than the last seen seq is processed;
 * - `delta.message_start` opens a slot, `delta.text_append` appends,
 *   `delta.message_done` closes it (full text wins over the accumulation);
 * - `display_text_ready == false` defers the done event until a later
 *   `message_done` (or an explicit [settleDeferred]);
 * - `message.assistant` delivers a whole message at once;
 * - `agent.status` / `task.status` drive the busy indicator.
 */
class SubscribeParser {
    sealed interface Event {
        data class MessageStart(val id: String) : Event
        data class TextAppend(val id: String, val text: String) : Event
        data class MessageDone(val id: String, val fullText: String) : Event
        data class Busy(val busy: Boolean) : Event
    }

    private data class Slot(
        val id: String,
        val text: StringBuilder = StringBuilder(),
        var pendingDone: String? = null, // display_text_ready=false full text, awaiting confirm
    )

    private var lastSeq: Long = -1
    private val slots = LinkedHashMap<String, Slot>()
    private var busy: Boolean = false

    /** Feed one NDJSON line; returns the events it produced. */
    fun feedLine(line: String): List<Event> {
        val trimmed = line.trim()
        if (trimmed.isEmpty()) return emptyList()
        val root = try {
            Json.parseObj(trimmed)
        } catch (e: Exception) {
            return emptyList() // malformed line: skip like feed_lines does
        }
        if (root.strField("type") != "event") return emptyList()
        val seq = (root.field("seq") as? JsonValue.Num)?.raw?.toLongOrNull() ?: return emptyList()
        if (seq <= lastSeq) return emptyList()
        lastSeq = seq
        val name = root.strField("event") ?: return emptyList()
        val payload = root.field("payload") as? JsonValue.Obj ?: return emptyList()
        return when (name) {
            "delta.message_start" -> onMessageStart(payload)
            "delta.text_append" -> onTextAppend(payload)
            "delta.message_done" -> onMessageDone(payload)
            "message.assistant" -> onWholeMessage(payload)
            "agent.status" -> onAgentStatus(payload)
            "task.status" -> onTaskStatus(payload)
            else -> emptyList()
        }
    }

    /**
     * Emits deferred `message_done` events when a turn settles without a
     * confirming done (spec: a turn settles after a few seconds of silence).
     */
    fun settleDeferred(): List<Event> {
        val out = ArrayList<Event>()
        for (slot in slots.values) {
            val pending = slot.pendingDone
            if (pending != null) {
                slot.pendingDone = null
                out.add(Event.MessageDone(slot.id, pending))
            }
        }
        return out
    }

    fun reset() {
        lastSeq = -1
        slots.clear()
        busy = false
    }

    private fun slotFor(payload: JsonValue.Obj): Slot {
        val id = payload.strField("message_id") ?: payload.strField("id") ?: "msg"
        return slots.getOrPut(id) { Slot(id) }
    }

    private fun onMessageStart(payload: JsonValue.Obj): List<Event> {
        val slot = slotFor(payload)
        return listOf(Event.MessageStart(slot.id))
    }

    private fun onTextAppend(payload: JsonValue.Obj): List<Event> {
        val slot = slotFor(payload)
        val text = payload.strField("text") ?: ""
        slot.text.append(text)
        return listOf(Event.TextAppend(slot.id, text))
    }

    private fun onMessageDone(payload: JsonValue.Obj): List<Event> {
        val slot = slotFor(payload)
        val full = payload.strField("display_text") ?: payload.strField("content") ?: slot.text.toString()
        val ready = payload.boolField("display_text_ready")
        if (ready == false) {
            // Not final yet: stash; a later message_done (or turn settle) completes it.
            slot.pendingDone = full
            return emptyList()
        }
        slot.pendingDone = null
        return listOf(Event.MessageDone(slot.id, full))
    }

    private fun onWholeMessage(payload: JsonValue.Obj): List<Event> {
        val slot = slotFor(payload)
        val full = payload.strField("display_text") ?: payload.strField("content") ?: ""
        slot.text.clear()
        slot.text.append(full)
        slot.pendingDone = null
        return listOf(Event.MessageStart(slot.id), Event.MessageDone(slot.id, full))
    }

    private fun setBusy(next: Boolean): List<Event> {
        if (next == busy) return emptyList()
        busy = next
        return listOf(Event.Busy(next))
    }

    private fun onAgentStatus(payload: JsonValue.Obj): List<Event> {
        val code = payload.strField("activity_code") ?: return emptyList()
        return setBusy(code != "online" && code != "idle")
    }

    private fun onTaskStatus(payload: JsonValue.Obj): List<Event> {
        val status = payload.strField("status") ?: return emptyList()
        return setBusy(status != "completed" && status != "failed")
    }
}
