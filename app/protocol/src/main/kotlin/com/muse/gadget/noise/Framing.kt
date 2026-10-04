package com.muse.gadget.noise

import java.security.SecureRandom

/** Noise transport framing, ported from `noise/framing.py`. */
object Framing {
    const val MAX_CHUNK_PAYLOAD = 65489
    const val MAX_PENDING_ASSEMBLIES = 16
    const val MAX_TOTAL_CHUNKS = 256
    const val MAX_ASSEMBLY_BYTES = 16 * 1024 * 1024
    const val ASSEMBLY_TTL_SECONDS = 60L

    data class NoiseTransportFrame(
        val chunkId: Long = 0,
        val chunkIndex: Long = 0,
        val totalChunks: Long = 1,
        val payload: ByteArray = ByteArray(0),
    )

    fun encodeNoiseFrame(f: NoiseTransportFrame): ByteArray {
        var out = ByteArray(0)
        if (f.chunkId != 0L) out += Proto.int64Field(1, f.chunkId)
        if (f.chunkIndex != 0L) out += Proto.uint32Field(2, f.chunkIndex)
        // The proto default for total_chunks is 1 (decode treats "absent" as 1),
        // so omit it when it equals the default, per proto3 semantics.
        if (f.totalChunks != 1L) out += Proto.uint32Field(3, f.totalChunks)
        if (f.payload.isNotEmpty()) out += Proto.bytesField(4, f.payload)
        return out
    }

    fun decodeNoiseFrame(data: ByteArray): NoiseTransportFrame {
        var chunkId = 0L
        var chunkIndex = 0L
        var totalChunks = 1L
        var payload = ByteArray(0)
        var off = 0
        while (off < data.size) {
            val (fn, wt, p) = Proto.readKey(data, off)
            off = p
            when (fn) {
                1 -> {
                    require(wt == Proto.WIRE_VARINT); val (raw, p2) = Proto.readVarint(data, off)
                    off = p2; chunkId = Proto.decodeInt64(raw)
                }
                2 -> {
                    require(wt == Proto.WIRE_VARINT); val (raw, p2) = Proto.readVarint(data, off)
                    off = p2; chunkIndex = Proto.decodeUint32(raw)
                }
                3 -> {
                    require(wt == Proto.WIRE_VARINT); val (raw, p2) = Proto.readVarint(data, off)
                    off = p2; totalChunks = Proto.decodeUint32(raw)
                }
                4 -> {
                    require(wt == Proto.WIRE_DELIMITED); val (raw, p2) = Proto.readDelimited(data, off)
                    off = p2; payload = raw
                }
                else -> off = Proto.skipField(data, off, wt)
            }
        }
        return NoiseTransportFrame(chunkId, chunkIndex, totalChunks, payload)
    }

    /**
     * Splits [data] into chunked frames. `chunk_id` is random int64 unless given
     * (tests pin it for determinism).
     */
    fun encodeNoiseFrames(data: ByteArray, chunkId: Long? = null): List<ByteArray> {
        val id = chunkId ?: run {
            val b = ByteArray(8).also { SecureRandom().nextBytes(it) }
            var v = 0L
            for (x in b) v = (v shl 8) or (x.toLong() and 0xFF)
            v
        }
        val total = maxOf(1, (data.size + MAX_CHUNK_PAYLOAD - 1) / MAX_CHUNK_PAYLOAD)
        require(total <= MAX_TOTAL_CHUNKS) {
            "payload too large for noise framing (${data.size} bytes, $total chunks > $MAX_TOTAL_CHUNKS)"
        }
        if (data.isEmpty()) {
            return listOf(
                encodeNoiseFrame(NoiseTransportFrame(id, 0, 1, ByteArray(0))),
            )
        }
        return (0 until total).map { i ->
            val start = i * MAX_CHUNK_PAYLOAD
            val chunk = data.copyOfRange(start, minOf(start + MAX_CHUNK_PAYLOAD, data.size))
            encodeNoiseFrame(NoiseTransportFrame(id, i.toLong(), total.toLong(), chunk))
        }
    }

    private class Assembly(
        val chunks: MutableMap<Long, ByteArray> = HashMap(),
        val total: Long,
        var totalBytes: Long = 0,
        val createdAtMs: Long,
        var lastUpdatedMs: Long,
    )

    /**
     * Reassembles chunked frames. Returns the payload once complete, null while
     * waiting. Any protocol violation poisons the decoder (like the reference).
     */
    class NoiseFrameDecoder(private val clockMs: () -> Long = { System.currentTimeMillis() }) {
        private val pending = HashMap<Long, Assembly>()
        private var poisoned = false

        /** Returns the reassembled payload, or null if more chunks are needed. */
        fun decode(frameBytes: ByteArray): ByteArray? {
            if (poisoned) throw IllegalStateException("NoiseFrameDecoder: poisoned after prior failure")
            try {
                val f = decodeNoiseFrame(frameBytes)
                require(f.totalChunks in 1..MAX_TOTAL_CHUNKS) { "invalid totalChunks: ${f.totalChunks}" }
                require(f.chunkIndex in 0 until f.totalChunks) {
                    "chunkIndex ${f.chunkIndex} out of range [0, ${f.totalChunks})"
                }
                require(f.payload.size <= MAX_CHUNK_PAYLOAD) {
                    "payload too large for noise frame (${f.payload.size} bytes)"
                }
                evictExpired()
                var asm = pending[f.chunkId]
                if (asm == null) {
                    require(pending.size < MAX_PENDING_ASSEMBLIES) { "too many pending noise frame assemblies" }
                    val now = clockMs()
                    asm = Assembly(total = f.totalChunks, createdAtMs = now, lastUpdatedMs = now)
                    pending[f.chunkId] = asm
                }
                if (asm.total != f.totalChunks) {
                    pending.remove(f.chunkId)
                    throw IllegalArgumentException(
                        "inconsistent totalChunks for chunkId: expected ${asm.total}, got ${f.totalChunks}",
                    )
                }
                if (asm.chunks.containsKey(f.chunkIndex)) {
                    pending.remove(f.chunkId)
                    throw IllegalArgumentException("duplicate chunkIndex ${f.chunkIndex}")
                }
                asm.lastUpdatedMs = clockMs()
                asm.totalBytes += f.payload.size
                if (asm.totalBytes > MAX_ASSEMBLY_BYTES) {
                    pending.remove(f.chunkId)
                    throw IllegalArgumentException("assembly exceeded byte budget")
                }
                asm.chunks[f.chunkIndex] = f.payload
                if (asm.chunks.size < asm.total) return null
                pending.remove(f.chunkId)
                if (asm.total == 1L) return asm.chunks[0]!!
                return (0 until asm.total).map { asm.chunks[it]!! }
                    .fold(ByteArray(0)) { acc, b -> acc + b }
            } catch (e: Exception) {
                poisoned = true
                throw e
            }
        }

        private fun evictExpired() {
            val now = clockMs()
            val expired = pending.filter { now - it.value.createdAtMs > ASSEMBLY_TTL_SECONDS * 1000 }.keys
            for (k in expired) pending.remove(k)
        }
    }
}
