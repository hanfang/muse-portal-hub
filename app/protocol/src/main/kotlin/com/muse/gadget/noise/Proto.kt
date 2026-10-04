package com.muse.gadget.noise

/** Manual protobuf codec, ported from `noise/_proto.py`. No runtime dependency. */
class ProtoException(message: String) : IllegalArgumentException(message)

object Proto {
    const val WIRE_VARINT = 0
    const val WIRE_FIXED64 = 1
    const val WIRE_DELIMITED = 2
    const val WIRE_FIXED32 = 5
    private const val MAX_FIELD_NUMBER = (1 shl 29) - 1

    /**
     * Unsigned 64-bit varint. Negative [value]s are rejected (use [int64Field]
     * for signed int64, which encodes negatives from their two's-complement
     * bit pattern as 10 bytes, per protobuf).
     */
    fun encodeVarint(value: Long): ByteArray {
        if (value < 0) throw ProtoException("varint value must be non-negative")
        return encodeVarintBits(value)
    }

    /**
     * Encodes the raw 64-bit pattern as a varint (no sign check). Used for
     * signed int64 fields, whose negative values are sign-extended to 64 bits
     * and occupy 10 bytes on the wire, per protobuf.
     */
    private fun encodeVarintBits(value: Long): ByteArray {
        val out = ByteArrayOutputStream2()
        var v = value
        while (true) {
            val b = (v and 0x7F).toByte()
            v = v ushr 7
            if (v != 0L) {
                out.write((b.toInt() or 0x80).toByte())
            } else {
                out.write(b)
                return out.toByteArray()
            }
        }
    }

    fun signedInt64Value(value: Long): Long = value // two's complement bit pattern

    fun signedInt32Value(value: Int): Long = value.toLong() and 0xFFFFFFFFL

    fun decodeInt64(raw: Long): Long = raw // reinterpret bits as signed

    fun decodeInt32(raw: Long): Int {
        // readVarint returns the raw 64-bit pattern as a signed Long, which is
        // already the correct signed interpretation (this is what the Python
        // reference's `value - (1 << 64) if value >= 1 << 63 else value` computes;
        // note `1L shl 63` is Long.MIN_VALUE so a signed comparison against it
        // is always true — do NOT "correct" it that way).
        if (raw < -(1L shl 31) || raw > (1L shl 31) - 1) throw ProtoException("int32 value out of range")
        return raw.toInt()
    }

    fun decodeUint32(raw: Long): Long {
        if (raw < 0 || raw > 0xFFFFFFFFL) throw ProtoException("uint32 value out of range")
        return raw
    }

    fun encodeKey(fieldNumber: Int, wireType: Int): ByteArray {
        require(fieldNumber != 0 && fieldNumber <= MAX_FIELD_NUMBER &&
            !(fieldNumber in 19000..19999)) { "invalid field number" }
        require(wireType in listOf(WIRE_VARINT, WIRE_FIXED64, WIRE_DELIMITED, WIRE_FIXED32)) {
            "invalid wire type"
        }
        return encodeVarint(((fieldNumber shl 3) or wireType).toLong())
    }

    fun varintField(fieldNumber: Int, value: Long): ByteArray =
        encodeKey(fieldNumber, WIRE_VARINT) + encodeVarint(value)

    fun int64Field(fieldNumber: Int, value: Long): ByteArray =
        encodeKey(fieldNumber, WIRE_VARINT) + encodeVarintBits(signedInt64Value(value))

    fun int32Field(fieldNumber: Int, value: Int): ByteArray =
        varintField(fieldNumber, signedInt32Value(value))

    fun uint32Field(fieldNumber: Int, value: Long): ByteArray {
        if (value < 0 || value > 0xFFFFFFFFL) throw ProtoException("uint32 value out of range")
        return varintField(fieldNumber, value)
    }

    fun boolField(fieldNumber: Int, value: Boolean): ByteArray =
        varintField(fieldNumber, if (value) 1 else 0)

    fun delimitedField(fieldNumber: Int, payload: ByteArray): ByteArray =
        encodeKey(fieldNumber, WIRE_DELIMITED) + encodeVarint(payload.size.toLong()) + payload

    fun stringField(fieldNumber: Int, value: String): ByteArray =
        delimitedField(fieldNumber, value.toByteArray(Charsets.UTF_8))

    fun bytesField(fieldNumber: Int, value: ByteArray): ByteArray =
        delimitedField(fieldNumber, value)

    /** Reads a varint; returns (value, newOffset). Unsigned 64-bit result as Long bits. */
    fun readVarint(data: ByteArray, offset: Int): Pair<Long, Int> {
        var value = 0L
        var shift = 0
        var pos = offset
        for (i in 0 until 10) {
            if (pos >= data.size) throw ProtoException("truncated varint")
            val b = data[pos++].toInt() and 0xFF
            if (i == 9 && (b and 0xFE) != 0) throw ProtoException("malformed varint")
            value = value or ((b and 0x7F).toLong() shl shift)
            if ((b and 0x80) == 0) return value to pos
            shift += 7
        }
        throw ProtoException("malformed varint")
    }

    fun readKey(data: ByteArray, offset: Int): Triple<Int, Int, Int> {
        val (key, pos) = readVarint(data, offset)
        val fieldNumber = (key ushr 3).toInt()
        val wireType = (key and 0x07).toInt()
        if (fieldNumber == 0 || fieldNumber > MAX_FIELD_NUMBER || fieldNumber in 19000..19999) {
            throw ProtoException("invalid field number")
        }
        if (wireType !in listOf(WIRE_VARINT, WIRE_FIXED64, WIRE_DELIMITED, WIRE_FIXED32)) {
            throw ProtoException("invalid wire type")
        }
        return Triple(fieldNumber, wireType, pos)
    }

    fun readDelimited(data: ByteArray, offset: Int): Pair<ByteArray, Int> {
        val (length, pos) = readVarint(data, offset)
        if (length > Int.MAX_VALUE) throw ProtoException("delimited field too large")
        val end = pos + length.toInt()
        if (end > data.size) throw ProtoException("truncated delimited field")
        return data.copyOfRange(pos, end) to end
    }

    fun skipField(data: ByteArray, offset: Int, wireType: Int): Int = when (wireType) {
        WIRE_VARINT -> readVarint(data, offset).second
        WIRE_FIXED64 -> {
            if (offset + 8 > data.size) throw ProtoException("truncated fixed64 field")
            offset + 8
        }
        WIRE_DELIMITED -> readDelimited(data, offset).second
        WIRE_FIXED32 -> {
            if (offset + 4 > data.size) throw ProtoException("truncated fixed32 field")
            offset + 4
        }
        else -> throw ProtoException("invalid wire type")
    }

    private class ByteArrayOutputStream2 {
        private val buf = ArrayList<Byte>()
        fun write(b: Byte) { buf.add(b) }
        fun toByteArray(): ByteArray = buf.toByteArray()
    }
}
