package com.muse.gadget.noise

/** Service envelope messages, ported from `noise/envelope.py`. */

enum class ServiceType(val code: Int) {
    DAEMON(0), SENTINEL(1), VAULT(2), AUTHD(3);

    companion object {
        fun fromCode(code: Long): ServiceType =
            values().firstOrNull { it.code == code.toInt() }
                ?: throw ProtoException("unknown service type")
    }
}

enum class ResetCode(val code: Int) {
    UNSPECIFIED(0), CANCELLED(1), TIMEOUT(2), PROTOCOL_ERROR(3),
    REFUSED_STREAM(4), INTERNAL_ERROR(5), SERVICE_UNAVAILABLE(6);

    companion object {
        fun fromCode(code: Int): ResetCode =
            values().firstOrNull { it.code == code }
                ?: throw ProtoException("unknown reset code")
    }
}

data class Header(val key: String = "", val value: String = "")
data class ApplicationRequest(
    val verb: String = "",
    val path: String = "",
    val headers: List<Header> = emptyList(),
    val body: ByteArray = ByteArray(0),
    val endBody: Boolean = false,
)
data class ApplicationResponse(
    val status: Int = 0,
    val headers: List<Header> = emptyList(),
    val body: ByteArray = ByteArray(0),
    val endBody: Boolean = false,
)
data class BodyChunk(val data: ByteArray = ByteArray(0), val endBody: Boolean = false)
data class Reset(val code: ResetCode = ResetCode.UNSPECIFIED, val reason: String = "")

sealed interface ServiceFrameValue
data class ServiceFrame(
    val streamId: Long = 0,
    val kind: Kind? = null,
    val value: ServiceFrameValue? = null,
) {
    enum class Kind { REQUEST, RESPONSE, BODY_CHUNK, RESET }

    companion object {
        fun request(streamId: Long, r: ApplicationRequest) =
            ServiceFrame(streamId, Kind.REQUEST, Req(r))

        fun response(streamId: Long, r: ApplicationResponse) =
            ServiceFrame(streamId, Kind.RESPONSE, Resp(r))

        fun bodyChunk(streamId: Long, c: BodyChunk) =
            ServiceFrame(streamId, Kind.BODY_CHUNK, Chunk(c))

        fun reset(streamId: Long, r: Reset) =
            ServiceFrame(streamId, Kind.RESET, Rst(r))
    }
}

// Make the value types implement the sealed interface via delegation wrappers.
data class Req(val r: ApplicationRequest) : ServiceFrameValue
data class Resp(val r: ApplicationResponse) : ServiceFrameValue
data class Chunk(val c: BodyChunk) : ServiceFrameValue
data class Rst(val r: Reset) : ServiceFrameValue

data class ServiceRequest(
    val service: ServiceType = ServiceType.DAEMON,
    val payload: ByteArray = ByteArray(0),
)
data class ServiceResponse(val payload: ByteArray = ByteArray(0))

private fun utf8(bytes: ByteArray): String = try {
    java.nio.charset.Charset.forName("UTF-8").newDecoder()
        .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
        .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        .decode(java.nio.ByteBuffer.wrap(bytes))
        .toString()
} catch (e: Exception) {
    throw ProtoException("invalid utf-8 string")
}

object Envelope {
    // -- Header ------------------------------------------------------------
    fun encodeHeader(h: Header): ByteArray {
        var out = ByteArray(0)
        if (h.key.isNotEmpty()) out += Proto.stringField(1, h.key)
        if (h.value.isNotEmpty()) out += Proto.stringField(2, h.value)
        return out
    }

    fun decodeHeader(data: ByteArray): Header {
        var key = ""
        var value = ""
        var off = 0
        while (off < data.size) {
            val (fn, wt, p) = Proto.readKey(data, off)
            off = p
            when (fn) {
                1 -> {
                    require(wt == Proto.WIRE_DELIMITED) { "Header.key wrong wire type" }
                    val (raw, p2) = Proto.readDelimited(data, off); off = p2
                    key = utf8(raw)
                }
                2 -> {
                    require(wt == Proto.WIRE_DELIMITED) { "Header.value wrong wire type" }
                    val (raw, p2) = Proto.readDelimited(data, off); off = p2
                    value = utf8(raw)
                }
                else -> off = Proto.skipField(data, off, wt)
            }
        }
        return Header(key, value)
    }

    // -- ApplicationRequest --------------------------------------------------
    fun encodeApplicationRequest(r: ApplicationRequest): ByteArray {
        var out = ByteArray(0)
        if (r.verb.isNotEmpty()) out += Proto.stringField(1, r.verb)
        if (r.path.isNotEmpty()) out += Proto.stringField(2, r.path)
        for (h in r.headers) out += Proto.delimitedField(3, encodeHeader(h))
        if (r.body.isNotEmpty()) out += Proto.bytesField(4, r.body)
        if (r.endBody) out += Proto.boolField(5, true)
        return out
    }

    fun decodeApplicationRequest(data: ByteArray): ApplicationRequest {
        var verb = ""; var path = ""
        val headers = ArrayList<Header>()
        var body = ByteArray(0); var endBody = false
        var off = 0
        while (off < data.size) {
            val (fn, wt, p) = Proto.readKey(data, off)
            off = p
            when (fn) {
                1 -> {
                    require(wt == Proto.WIRE_DELIMITED); val (raw, p2) = Proto.readDelimited(data, off)
                    off = p2; verb = utf8(raw)
                }
                2 -> {
                    require(wt == Proto.WIRE_DELIMITED); val (raw, p2) = Proto.readDelimited(data, off)
                    off = p2; path = utf8(raw)
                }
                3 -> {
                    require(wt == Proto.WIRE_DELIMITED); val (raw, p2) = Proto.readDelimited(data, off)
                    off = p2; headers.add(decodeHeader(raw))
                }
                4 -> {
                    require(wt == Proto.WIRE_DELIMITED); val (raw, p2) = Proto.readDelimited(data, off)
                    off = p2; body = raw
                }
                5 -> {
                    require(wt == Proto.WIRE_VARINT); val (raw, p2) = Proto.readVarint(data, off)
                    off = p2; endBody = raw != 0L
                }
                else -> off = Proto.skipField(data, off, wt)
            }
        }
        return ApplicationRequest(verb, path, headers, body, endBody)
    }

    // -- ApplicationResponse -------------------------------------------------
    fun encodeApplicationResponse(r: ApplicationResponse): ByteArray {
        var out = ByteArray(0)
        if (r.status != 0) out += Proto.int32Field(1, r.status)
        for (h in r.headers) out += Proto.delimitedField(2, encodeHeader(h))
        if (r.body.isNotEmpty()) out += Proto.bytesField(3, r.body)
        if (r.endBody) out += Proto.boolField(4, true)
        return out
    }

    fun decodeApplicationResponse(data: ByteArray): ApplicationResponse {
        var status = 0
        val headers = ArrayList<Header>()
        var body = ByteArray(0); var endBody = false
        var off = 0
        while (off < data.size) {
            val (fn, wt, p) = Proto.readKey(data, off)
            off = p
            when (fn) {
                1 -> {
                    require(wt == Proto.WIRE_VARINT); val (raw, p2) = Proto.readVarint(data, off)
                    off = p2; status = Proto.decodeInt32(raw)
                }
                2 -> {
                    require(wt == Proto.WIRE_DELIMITED); val (raw, p2) = Proto.readDelimited(data, off)
                    off = p2; headers.add(decodeHeader(raw))
                }
                3 -> {
                    require(wt == Proto.WIRE_DELIMITED); val (raw, p2) = Proto.readDelimited(data, off)
                    off = p2; body = raw
                }
                4 -> {
                    require(wt == Proto.WIRE_VARINT); val (raw, p2) = Proto.readVarint(data, off)
                    off = p2; endBody = raw != 0L
                }
                else -> off = Proto.skipField(data, off, wt)
            }
        }
        return ApplicationResponse(status, headers, body, endBody)
    }

    // -- BodyChunk -----------------------------------------------------------
    fun encodeBodyChunk(c: BodyChunk): ByteArray {
        var out = ByteArray(0)
        if (c.data.isNotEmpty()) out += Proto.bytesField(1, c.data)
        if (c.endBody) out += Proto.boolField(2, true)
        return out
    }

    fun decodeBodyChunk(data: ByteArray): BodyChunk {
        var chunkData = ByteArray(0); var endBody = false
        var off = 0
        while (off < data.size) {
            val (fn, wt, p) = Proto.readKey(data, off)
            off = p
            when (fn) {
                1 -> {
                    require(wt == Proto.WIRE_DELIMITED); val (raw, p2) = Proto.readDelimited(data, off)
                    off = p2; chunkData = raw
                }
                2 -> {
                    require(wt == Proto.WIRE_VARINT); val (raw, p2) = Proto.readVarint(data, off)
                    off = p2; endBody = raw != 0L
                }
                else -> off = Proto.skipField(data, off, wt)
            }
        }
        return BodyChunk(chunkData, endBody)
    }

    // -- Reset ---------------------------------------------------------------
    fun encodeReset(r: Reset): ByteArray {
        var out = ByteArray(0)
        if (r.code != ResetCode.UNSPECIFIED) out += Proto.int32Field(1, r.code.code)
        if (r.reason.isNotEmpty()) out += Proto.stringField(2, r.reason)
        return out
    }

    fun decodeReset(data: ByteArray): Reset {
        var code = ResetCode.UNSPECIFIED; var reason = ""
        var off = 0
        while (off < data.size) {
            val (fn, wt, p) = Proto.readKey(data, off)
            off = p
            when (fn) {
                1 -> {
                    require(wt == Proto.WIRE_VARINT); val (raw, p2) = Proto.readVarint(data, off)
                    off = p2; code = ResetCode.fromCode(Proto.decodeInt32(raw))
                }
                2 -> {
                    require(wt == Proto.WIRE_DELIMITED); val (raw, p2) = Proto.readDelimited(data, off)
                    off = p2; reason = utf8(raw)
                }
                else -> off = Proto.skipField(data, off, wt)
            }
        }
        return Reset(code, reason)
    }

    // -- ServiceFrame ----------------------------------------------------------
    fun encodeServiceFrame(f: ServiceFrame): ByteArray {
        var out = ByteArray(0)
        if (f.streamId != 0L) out += Proto.int64Field(1, f.streamId)
        when (f.kind) {
            null -> if (f.value != null) throw ProtoException("ServiceFrame value without kind")
            ServiceFrame.Kind.REQUEST -> {
                val r = (f.value as? Req)?.r ?: throw ProtoException("request value wrong type")
                out += Proto.delimitedField(2, encodeApplicationRequest(r))
            }
            ServiceFrame.Kind.RESPONSE -> {
                val r = (f.value as? Resp)?.r ?: throw ProtoException("response value wrong type")
                out += Proto.delimitedField(3, encodeApplicationResponse(r))
            }
            ServiceFrame.Kind.BODY_CHUNK -> {
                val c = (f.value as? Chunk)?.c ?: throw ProtoException("body_chunk value wrong type")
                out += Proto.delimitedField(4, encodeBodyChunk(c))
            }
            ServiceFrame.Kind.RESET -> {
                val r = (f.value as? Rst)?.r ?: throw ProtoException("reset value wrong type")
                out += Proto.delimitedField(5, encodeReset(r))
            }
        }
        return out
    }

    fun decodeServiceFrame(data: ByteArray): ServiceFrame {
        var streamId = 0L
        var kind: ServiceFrame.Kind? = null
        var value: ServiceFrameValue? = null
        var off = 0
        while (off < data.size) {
            val (fn, wt, p) = Proto.readKey(data, off)
            off = p
            when (fn) {
                1 -> {
                    require(wt == Proto.WIRE_VARINT); val (raw, p2) = Proto.readVarint(data, off)
                    off = p2; streamId = Proto.decodeInt64(raw)
                }
                2 -> {
                    require(wt == Proto.WIRE_DELIMITED); val (raw, p2) = Proto.readDelimited(data, off)
                    off = p2; kind = ServiceFrame.Kind.REQUEST; value = Req(decodeApplicationRequest(raw))
                }
                3 -> {
                    require(wt == Proto.WIRE_DELIMITED); val (raw, p2) = Proto.readDelimited(data, off)
                    off = p2; kind = ServiceFrame.Kind.RESPONSE; value = Resp(decodeApplicationResponse(raw))
                }
                4 -> {
                    require(wt == Proto.WIRE_DELIMITED); val (raw, p2) = Proto.readDelimited(data, off)
                    off = p2; kind = ServiceFrame.Kind.BODY_CHUNK; value = Chunk(decodeBodyChunk(raw))
                }
                5 -> {
                    require(wt == Proto.WIRE_DELIMITED); val (raw, p2) = Proto.readDelimited(data, off)
                    off = p2; kind = ServiceFrame.Kind.RESET; value = Rst(decodeReset(raw))
                }
                else -> off = Proto.skipField(data, off, wt)
            }
        }
        return ServiceFrame(streamId, kind, value)
    }

    // -- ServiceRequest / ServiceResponse --------------------------------------
    fun encodeServiceRequest(r: ServiceRequest): ByteArray {
        var out = ByteArray(0)
        if (r.service != ServiceType.DAEMON) out += Proto.varintField(1, r.service.code.toLong())
        if (r.payload.isNotEmpty()) out += Proto.bytesField(2, r.payload)
        return out
    }

    fun decodeServiceRequest(data: ByteArray): ServiceRequest {
        var service = ServiceType.DAEMON
        var payload = ByteArray(0)
        var off = 0
        while (off < data.size) {
            val (fn, wt, p) = Proto.readKey(data, off)
            off = p
            when (fn) {
                1 -> {
                    require(wt == Proto.WIRE_VARINT); val (raw, p2) = Proto.readVarint(data, off)
                    off = p2; service = ServiceType.fromCode(raw)
                }
                2 -> {
                    require(wt == Proto.WIRE_DELIMITED); val (raw, p2) = Proto.readDelimited(data, off)
                    off = p2; payload = raw
                }
                else -> off = Proto.skipField(data, off, wt)
            }
        }
        return ServiceRequest(service, payload)
    }

    fun encodeServiceResponse(r: ServiceResponse): ByteArray {
        if (r.payload.isEmpty()) return ByteArray(0)
        return Proto.bytesField(1, r.payload)
    }

    fun decodeServiceResponse(data: ByteArray): ServiceResponse {
        var payload = ByteArray(0)
        var off = 0
        while (off < data.size) {
            val (fn, wt, p) = Proto.readKey(data, off)
            off = p
            when (fn) {
                1 -> {
                    require(wt == Proto.WIRE_DELIMITED); val (raw, p2) = Proto.readDelimited(data, off)
                    off = p2; payload = raw
                }
                else -> off = Proto.skipField(data, off, wt)
            }
        }
        return ServiceResponse(payload)
    }
}
