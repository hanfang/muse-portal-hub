package com.muse.gadget.session

/**
 * Turn state machine (spec: P_IDLE / P_LISTEN / P_WAIT_REPLY).
 *
 * A turn starts in LISTEN (audio being captured); once the input has been
 * silent for [settleSilenceMs] the turn is handed to the Muse and the machine
 * moves to WAIT_REPLY. There is no explicit end-of-turn event: the reply is
 * done when the subscribe stream reports `message_done` (see [SubscribeParser]).
 */
class TurnStateMachine(
    private val clockMs: () -> Long = { System.currentTimeMillis() },
    private val settleSilenceMs: Long = 3000,
) {
    enum class Phase { IDLE, LISTEN, WAIT_REPLY }

    var phase: Phase = Phase.IDLE
        private set

    private var lastActivityMs: Long = 0

    /** Starts a turn; returns false unless currently IDLE. */
    fun beginTurn(): Boolean {
        if (phase != Phase.IDLE) return false
        phase = Phase.LISTEN
        lastActivityMs = clockMs()
        return true
    }

    /** Call while audio is still arriving (resets the silence timer). */
    fun onAudioActivity() {
        if (phase == Phase.LISTEN) lastActivityMs = clockMs()
    }

    /**
     * Drives the LISTEN -> WAIT_REPLY transition.
     * @return true exactly once when the turn settles and should be sent.
     */
    fun poll(): Boolean {
        if (phase == Phase.LISTEN && clockMs() - lastActivityMs > settleSilenceMs) {
            phase = Phase.WAIT_REPLY
            return true
        }
        return false
    }

    /** The reply finished (subscribe `message_done` + settle). */
    fun onReplyDone() {
        if (phase == Phase.WAIT_REPLY) phase = Phase.IDLE
    }

    /** User barge-in / new turn: back to IDLE (caller sends the stream reset). */
    fun cancel() {
        phase = Phase.IDLE
    }
}
