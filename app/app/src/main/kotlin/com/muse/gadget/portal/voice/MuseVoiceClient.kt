package com.muse.gadget.portal.voice

/**
 * Sends a voice note to Muse and returns the reply text.
 *
 * P3 ships the interface + a fake. The real implementation (P4) wires the
 * `:protocol` transport: [com.muse.gadget.audio.VoiceNoteEncoder] chunks ->
 * `ChatStreams` voice-note body -> `ChatSession` WS transport ->
 * `SubscribeParser` reply assembly.
 */
interface MuseVoiceClient {
    /** Sends 16kHz mono PCM16 with a WAV header; returns Muse's reply text. */
    @Throws(Exception::class)
    fun sendVoiceNote(wavBytes: ByteArray): String

    fun close() {}
}

/** Test/dev stub: no network, returns a canned reply. */
class FakeMuseVoiceClient(
    var replyTemplate: String = "(dev stub) voice note received (%d bytes)",
) : MuseVoiceClient {
    var lastSentBytes: Int = 0
        private set
    var calls: Int = 0
        private set

    override fun sendVoiceNote(wavBytes: ByteArray): String {
        calls++
        lastSentBytes = wavBytes.size
        return replyTemplate.format(wavBytes.size)
    }
}
