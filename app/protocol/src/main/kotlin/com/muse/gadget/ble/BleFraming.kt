package com.muse.gadget.ble

import com.muse.gadget.identity.Identity

/**
 * BLE chunked framing shared by the GATT peripheral: every message is split
 * into `0xFE, index, total, payload` chunks (see `ble_framing.py` /
 * `ble_server.c`: `CHUNK_MAGIC 0xFE` + 3-byte header, max 160-byte notifies).
 *
 * Pure JVM so the reassembly logic is unit-testable; the Android
 * `BluetoothGattServer` in `:app` feeds raw writes into [BleFraming].
 */
object BleFraming {
    /** Splits [message] into framed chunks of at most [maxPayload] bytes. */
    fun encode(message: ByteArray, maxPayload: Int = Identity.MAX_NOTIFY_CHUNK - 4): List<ByteArray> {
        require(maxPayload in 1..252)
        val total = maxOf(1, (message.size + maxPayload - 1) / maxPayload)
        require(total <= 256) { "message too large for BLE framing" }
        if (message.isEmpty()) {
            return listOf(byteArrayOf(Identity.CHUNK_MAGIC, 0, 1))
        }
        return (0 until total).map { i ->
            val start = i * maxPayload
            val chunk = message.copyOfRange(start, minOf(start + maxPayload, message.size))
            byteArrayOf(Identity.CHUNK_MAGIC, i.toByte(), total.toByte()) + chunk
        }
    }

    /** Reassembles framed chunks; returns the message once all parts arrived. */
    class Reassembler {
        private val parts = HashMap<Int, ByteArray>()
        private var total: Int = -1
        var poisoned = false
            private set

        /** Returns the complete message, or null while waiting. */
        fun feed(chunk: ByteArray): ByteArray? {
            if (poisoned) throw IllegalStateException("BleFraming: poisoned")
            try {
                require(chunk.size >= 3 && chunk[0] == Identity.CHUNK_MAGIC) { "bad chunk magic" }
                val index = chunk[1].toInt() and 0xFF
                val count = chunk[2].toInt() and 0xFF
                require(count in 1..256) { "bad chunk total" }
                require(index < count) { "chunk index out of range" }
                if (total == -1) total = count
                require(total == count) { "inconsistent chunk total" }
                require(!parts.containsKey(index)) { "duplicate chunk" }
                parts[index] = chunk.copyOfRange(3, chunk.size)
                if (parts.size < total) return null
                return (0 until total).map { parts[it]!! }
                    .fold(ByteArray(0)) { acc, b -> acc + b }
            } catch (e: Exception) {
                poisoned = true
                throw e
            }
        }

        fun reset() {
            parts.clear()
            total = -1
            poisoned = false
        }
    }
}
