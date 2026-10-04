package com.muse.gadget

import com.muse.gadget.session.SubscribeParser
import com.muse.gadget.session.SubscribeParser.Event
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class NdjsonParserTest {
    private fun feed(p: SubscribeParser, vararg lines: String): List<Event> =
        lines.flatMap { p.feedLine(it) }

    @Test
    fun `full turn with seq dedup`() {
        val p = SubscribeParser()
        val events = feed(
            p,
            """{"type":"ack","seq":0}""",
            """{"type":"event","seq":1,"event":"delta.message_start","payload":{"message_id":"m1"}}""",
            """{"type":"event","seq":2,"event":"delta.text_append","payload":{"message_id":"m1","text":"Hello"}}""",
            """{"type":"event","seq":2,"event":"delta.text_append","payload":{"message_id":"m1","text":" DUP"}}""",
            """{"type":"event","seq":3,"event":"delta.text_append","payload":{"message_id":"m1","text":" world"}}""",
            """{"type":"event","seq":4,"event":"delta.message_done","payload":{"message_id":"m1","display_text":"Hello world"}}""",
        )
        assertEquals(
            listOf(
                Event.MessageStart("m1"),
                Event.TextAppend("m1", "Hello"),
                Event.TextAppend("m1", " world"),
                Event.MessageDone("m1", "Hello world"),
            ),
            events,
        )
    }

    @Test
    fun `display_text_ready false defers the done event`() {
        val p = SubscribeParser()
        val events = feed(
            p,
            """{"type":"event","seq":1,"event":"delta.message_start","payload":{"message_id":"m1"}}""",
            """{"type":"event","seq":2,"event":"delta.text_append","payload":{"message_id":"m1","text":"partial"}}""",
            """{"type":"event","seq":3,"event":"delta.message_done","payload":{"message_id":"m1","display_text":"partial","display_text_ready":false}}""",
        )
        // no MessageDone yet
        assertTrue(events.none { it is Event.MessageDone })
        // turn settles -> deferred done is emitted
        assertEquals(
            listOf(Event.MessageDone("m1", "partial")),
            p.settleDeferred(),
        )
        // a confirming later done supersedes the deferred one
        val p2 = SubscribeParser()
        feed(
            p2,
            """{"type":"event","seq":1,"event":"delta.message_start","payload":{"message_id":"m1"}}""",
            """{"type":"event","seq":2,"event":"delta.message_done","payload":{"message_id":"m1","display_text":"v1","display_text_ready":false}}""",
            """{"type":"event","seq":3,"event":"delta.message_done","payload":{"message_id":"m1","display_text":"v2 final"}}""",
        )
        assertEquals(emptyList<Event>(), p2.settleDeferred())
    }

    @Test
    fun `message_assistant delivers a whole message`() {
        val p = SubscribeParser()
        val events = feed(
            p,
            """{"type":"event","seq":1,"event":"message.assistant","payload":{"id":"m2","content":"Hi there"}}""",
        )
        assertEquals(
            listOf(Event.MessageStart("m2"), Event.MessageDone("m2", "Hi there")),
            events,
        )
    }

    @Test
    fun `agent and task status drive busy`() {
        val p = SubscribeParser()
        assertEquals(
            listOf(Event.Busy(true)),
            feed(p, """{"type":"event","seq":1,"event":"agent.status","payload":{"activity_code":"thinking"}}"""),
        )
        // same state -> no event
        assertEquals(
            emptyList<Event>(),
            feed(p, """{"type":"event","seq":2,"event":"agent.status","payload":{"activity_code":"working"}}"""),
        )
        assertEquals(
            listOf(Event.Busy(false)),
            feed(p, """{"type":"event","seq":3,"event":"agent.status","payload":{"activity_code":"idle"}}"""),
        )
        assertEquals(
            listOf(Event.Busy(true)),
            feed(p, """{"type":"event","seq":4,"event":"task.status","payload":{"status":"running"}}"""),
        )
        assertEquals(
            listOf(Event.Busy(false)),
            feed(p, """{"type":"event","seq":5,"event":"task.status","payload":{"status":"completed"}}"""),
        )
    }

    @Test
    fun `malformed lines and unknown events are ignored`() {
        val p = SubscribeParser()
        val events = feed(
            p,
            "",
            "not json",
            """{"type":"event","seq":"nan","event":"delta.text_append","payload":{}}""",
            """{"type":"event","seq":1,"event":"something.else","payload":{}}""",
            """{"no":"type"}""",
        )
        assertEquals(emptyList<Event>(), events)
    }

    @Test
    fun `message_done falls back to content then accumulation`() {
        val p = SubscribeParser()
        val events = feed(
            p,
            """{"type":"event","seq":1,"event":"delta.message_start","payload":{"message_id":"m1"}}""",
            """{"type":"event","seq":2,"event":"delta.text_append","payload":{"message_id":"m1","text":"abc"}}""",
            """{"type":"event","seq":3,"event":"delta.message_done","payload":{"message_id":"m1","content":"full-content"}}""",
        )
        assertEquals(Event.MessageDone("m1", "full-content"), events.last())
        val p2 = SubscribeParser()
        val e2 = feed(
            p2,
            """{"type":"event","seq":1,"event":"delta.message_start","payload":{"message_id":"m1"}}""",
            """{"type":"event","seq":2,"event":"delta.text_append","payload":{"message_id":"m1","text":"abc"}}""",
            """{"type":"event","seq":3,"event":"delta.message_done","payload":{"message_id":"m1"}}""",
        )
        assertEquals(Event.MessageDone("m1", "abc"), e2.last())
    }
}
