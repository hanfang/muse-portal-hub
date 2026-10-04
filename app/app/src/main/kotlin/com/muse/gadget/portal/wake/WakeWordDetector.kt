package com.muse.gadget.portal.wake

/**
 * Abstraction over the wake-word engine. v1 implementation is
 * [OpenWakeWordDetector] (openwakeword-android, ONNX Runtime, fully on-device).
 *
 * The interface exists so the engine can be swapped (or faked in tests)
 * without touching [com.muse.gadget.portal.voice.VoiceService].
 */
interface WakeWordDetector {
    /** Detection threshold in [0, 1]; higher = fewer false wakes. Default 0.5. */
    fun setThreshold(threshold: Float)

    /** Starts listening; [onWake] fires on the main thread per detection. */
    fun start(onWake: (score: Float) -> Unit)

    /** Stops listening; safe to call when not started. */
    fun stop()

    fun release()
}
