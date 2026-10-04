package com.muse.gadget.portal.voice

/**
 * Turn lifecycle for one "hey muse" interaction. Pure logic; the Android
 * [VoiceService] drives it and performs the side effects.
 *
 * ```
 * IDLE --Wake--> RECORDING --RecordEndpoint--> SENDING --ReplyReceived--> SPEAKING --SpeakDone--> IDLE
 *                     |                            |                           |
 *                     +--RecordTimeout--> SENDING --+--ReplyFailed--> IDLE <--+--SpeakFailed--> IDLE
 *                     any --Cancel--> IDLE
 * ```
 */
class VoiceTurnStateMachine {
    enum class State { IDLE, RECORDING, SENDING, SPEAKING }

    sealed interface Event {
        /** openWakeWord fired. */
        data class Wake(val score: Float) : Event
        /** VAD endpointed the query utterance. */
        data object RecordEndpoint : Event
        /** Max query duration hit; send what we have. */
        data object RecordTimeout : Event
        /** Muse reply text arrived. */
        data class ReplyReceived(val text: String) : Event
        /** Muse request failed. */
        data object ReplyFailed : Event
        /** TTS finished playing the reply. */
        data object SpeakDone : Event
        /** TTS failed. */
        data object SpeakFailed : Event
        /** User/system cancel; always lands back in IDLE. */
        data object Cancel : Event
    }

    var state: State = State.IDLE
        private set

    /** Applies [event]; returns the new state. Unknown transitions are ignored. */
    fun onEvent(event: Event): State {
        if (event is Event.Cancel) {
            state = State.IDLE
            return state
        }
        state = when (state) {
            State.IDLE -> when (event) {
                is Event.Wake -> State.RECORDING
                else -> state
            }
            State.RECORDING -> when (event) {
                is Event.RecordEndpoint -> State.SENDING
                is Event.RecordTimeout -> State.SENDING
                else -> state
            }
            State.SENDING -> when (event) {
                is Event.ReplyReceived -> State.SPEAKING
                is Event.ReplyFailed -> State.IDLE
                else -> state
            }
            State.SPEAKING -> when (event) {
                is Event.SpeakDone -> State.IDLE
                is Event.SpeakFailed -> State.IDLE
                else -> state
            }
        }
        return state
    }
}
