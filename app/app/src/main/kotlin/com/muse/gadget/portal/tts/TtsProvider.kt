package com.muse.gadget.portal.tts

/**
 * Pluggable text-to-speech.
 *
 * v1 implementation: [EdgeTtsProvider] (Microsoft Edge Read Aloud over
 * WebSocket — free, no API key, unofficial endpoint).
 * v1.x fallback slot: Sherpa-ONNX + Piper (fully offline); add a second
 * implementation of this interface and switch the provider in [VoiceService].
 */
interface TtsProvider {
    interface Listener {
        fun onSpeakStart() {}
        fun onSpeakDone() {}
        fun onSpeakError(error: Throwable) {}
    }

    fun setListener(listener: Listener?)

    /** Speaks [text]; any in-flight utterance is stopped first. */
    fun speak(text: String)

    /** Stops playback immediately. */
    fun stop()

    fun release()
}
