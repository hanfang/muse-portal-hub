package com.muse.gadget.audio

import java.util.Base64

/**
 * Voice-note body encoding (spec §3.2): 16kHz mono PCM16 with a 44-byte WAV
 * header whose lengths are 0xFFFFFFFF (streaming; the server tolerates it),
 * then base64 (standard, padded) in 6144-byte PCM chunks -> 8192 chars each.
 */
object VoiceNoteEncoder {
    const val SAMPLE_RATE = 16000
    const val CHANNELS = 1
    const val BITS_PER_SAMPLE = 16
    const val NOTE_PART_BYTES = 6144
    const val NOTE_MAX_BYTES = SAMPLE_RATE * 2 * 20 // 20s; the server only listens to the first 15s

    /** Exact 44-byte header. All multi-byte fields little-endian. */
    fun wavHeader(): ByteArray {
        val out = ByteArray(44)
        fun putStr(off: Int, s: String) = s.toByteArray(Charsets.US_ASCII).copyInto(out, off)
        fun putU32(off: Int, v: Long) {
            for (i in 0 until 4) out[off + i] = (v ushr (8 * i)).toByte()
        }
        fun putU16(off: Int, v: Int) {
            out[off] = v.toByte()
            out[off + 1] = (v ushr 8).toByte()
        }
        putStr(0, "RIFF")
        putU32(4, 0xFFFFFFFFL)
        putStr(8, "WAVE")
        putStr(12, "fmt ")
        putU32(16, 16) // Subchunk1Size
        putU16(20, 1) // PCM
        putU16(22, CHANNELS)
        putU32(24, SAMPLE_RATE.toLong())
        putU32(28, (SAMPLE_RATE * CHANNELS * BITS_PER_SAMPLE / 8).toLong()) // byte rate 32000
        putU16(32, (CHANNELS * BITS_PER_SAMPLE / 8)) // block align = 2
        putU16(34, BITS_PER_SAMPLE)
        putStr(36, "data")
        putU32(40, 0xFFFFFFFFL)
        return out
    }

    /**
     * Splits raw PCM16 bytes into base64 chunks (standard alphabet, padded):
     * every 6144 input bytes become exactly 8192 characters.
     */
    fun encodeChunks(pcm: ByteArray): List<String> {
        require(pcm.size % 2 == 0) { "PCM16 must have an even byte count" }
        val enc = Base64.getEncoder()
        val chunks = ArrayList<String>()
        var off = 0
        while (off < pcm.size) {
            val end = minOf(off + NOTE_PART_BYTES, pcm.size)
            chunks.add(enc.encodeToString(pcm.copyOfRange(off, end)))
            off = end
        }
        return chunks
    }
}
