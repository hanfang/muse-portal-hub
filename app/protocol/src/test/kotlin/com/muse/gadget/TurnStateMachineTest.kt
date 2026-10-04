package com.muse.gadget

import com.muse.gadget.session.TurnStateMachine
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class TurnStateMachineTest {
    @Test
    fun `idle to listen to wait_reply on 3s silence`() {
        var now = 0L
        val t = TurnStateMachine({ now }, settleSilenceMs = 3000)
        assertEquals(TurnStateMachine.Phase.IDLE, t.phase)
        assertTrue(t.beginTurn())
        assertEquals(TurnStateMachine.Phase.LISTEN, t.phase)
        // second begin is rejected while busy
        assertFalse(t.beginTurn())

        now = 2999
        assertFalse(t.poll())
        // audio activity resets the silence timer
        t.onAudioActivity()
        now = 5999
        assertFalse(t.poll())
        now = 6000
        assertTrue(t.poll())
        assertEquals(TurnStateMachine.Phase.WAIT_REPLY, t.phase)
        // poll fires only once
        assertFalse(t.poll())

        t.onReplyDone()
        assertEquals(TurnStateMachine.Phase.IDLE, t.phase)
    }

    @Test
    fun `cancel returns to idle`() {
        var now = 0L
        val t = TurnStateMachine({ now })
        t.beginTurn()
        t.cancel()
        assertEquals(TurnStateMachine.Phase.IDLE, t.phase)
        assertTrue(t.beginTurn())

        now = 10_000
        assertTrue(t.poll())
        t.cancel()
        assertEquals(TurnStateMachine.Phase.IDLE, t.phase)
    }

    @Test
    fun `onReplyDone only applies in wait_reply`() {
        val t = TurnStateMachine({ 0 })
        t.onReplyDone() // no-op in IDLE
        assertEquals(TurnStateMachine.Phase.IDLE, t.phase)
        t.beginTurn()
        t.onReplyDone() // no-op in LISTEN
        assertEquals(TurnStateMachine.Phase.LISTEN, t.phase)
    }
}
