package com.muse.gadget.portal.wake

import kotlin.math.log10

/**
 * Lightweight energy-based voice activity detection with an adaptive noise
 * floor, plus utterance endpointing. Tuned for 16kHz mono PCM16 frames.
 *
 * All thresholds are constructor parameters so they can be tuned on-device
 * without code changes (see `wake/` tuning notes in P3_REPORT.md).
 */
class EnergyVad(
    private val frameSamples: Int = FRAME_SAMPLES,
    /** dB above the noise floor that counts as speech. */
    private val speechDb: Double = 8.0,
    /** Noise-floor adaptation rate (only adapted on non-speech frames). */
    private val noiseAlpha: Double = 0.05,
    /** Frames to stay "in speech" after energy drops (hangover). */
    private val hangoverFrames: Int = 5,
) {
    companion object {
        /** 20ms at 16kHz. */
        const val FRAME_SAMPLES = 320
    }

    private var noiseEnergy = 1.0
    private var hangover = 0

    /** True while speech is active (includes hangover tail). */
    var inSpeech: Boolean = false
        private set

    /** Feed one [frameSamples]-long frame; returns [inSpeech] after update. */
    fun process(frame: ShortArray): Boolean {
        require(frame.size == frameSamples) { "expected $frameSamples samples, got ${frame.size}" }
        var sum = 0.0
        for (s in frame) sum += s * s.toDouble()
        val energy = sum / frame.size + 1e-9
        val isSpeechFrame = 10 * log10(energy / noiseEnergy) > speechDb
        if (isSpeechFrame) {
            hangover = hangoverFrames
        } else {
            noiseEnergy += noiseAlpha * (energy - noiseEnergy)
        }
        // Hangover: stay in speech for exactly [hangoverFrames] frames after
        // the last speech frame; decrement after evaluating so the count is exact.
        inSpeech = isSpeechFrame || hangover > 0
        if (!isSpeechFrame && hangover > 0) hangover--
        return inSpeech
    }

    fun reset() {
        noiseEnergy = 1.0
        hangover = 0
        inSpeech = false
    }
}

/**
 * Decides when a captured utterance is complete: [silenceTimeoutMs] of
 * continuous non-speech after speech was seen, or [maxDurationMs] total.
 * Pure logic over [EnergyVad]; feed 20ms frames with a millisecond clock.
 */
class UtteranceEndpoint(
    private val vad: EnergyVad = EnergyVad(),
    private val silenceTimeoutMs: Long = 1200,
    private val maxDurationMs: Long = 15_000,
) {
    private var startMs: Long = 0
    private var lastSpeechMs: Long = 0
    private var sawSpeech = false
    private var started = false

    fun start(nowMs: Long) {
        vad.reset()
        startMs = nowMs
        lastSpeechMs = nowMs
        sawSpeech = false
        started = true
    }

    /**
     * Returns true when the utterance is complete and recording should stop.
     * Safe to call only after [start].
     */
    fun process(frame: ShortArray, nowMs: Long): Boolean {
        check(started) { "call start() first" }
        val speech = vad.process(frame)
        if (speech) {
            sawSpeech = true
            lastSpeechMs = nowMs
        }
        if (nowMs - startMs >= maxDurationMs) return true
        return sawSpeech && nowMs - lastSpeechMs >= silenceTimeoutMs
    }
}
