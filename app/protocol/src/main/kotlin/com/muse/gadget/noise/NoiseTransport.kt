package com.muse.gadget.noise

/** Encrypted Noise transport, ported from `noise/transport.py`. */
object NoiseTransportConstants {
    val EMPTY_AD = ByteArray(0)
}

data class EncryptedFrames(val streamId: Long, val frames: List<ByteArray>)

sealed interface DecryptedFrameValue
data class DecryptedFrame(
    val kind: Kind,
    val streamId: Long,
    val value: DecryptedFrameValue,
) {
    enum class Kind { RESPONSE, BODY_CHUNK, RESET }
}

data class ResponseValue(val r: ApplicationResponse) : DecryptedFrameValue
data class BodyChunkValue(val c: BodyChunk) : DecryptedFrameValue
data class ResetValue(val r: Reset) : DecryptedFrameValue

class NoiseTransportException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

class NoiseTransport(
    private val send: CipherState,
    private val recv: CipherState,
) {
    private val decoder = Framing.NoiseFrameDecoder()
    private var nextStreamId = 1L
    private var dead = false

    private fun assertAlive() {
        if (dead) throw NoiseTransportException("NoiseTransport: dead after prior failure")
    }

    private fun markDead(e: Exception): Nothing {
        dead = true
        throw NoiseTransportException("NoiseTransport failure", e)
    }

    fun encryptHttpRequest(
        method: String,
        path: String,
        body: ByteArray = ByteArray(0),
        service: ServiceType = ServiceType.DAEMON,
        headers: List<Header> = emptyList(),
    ): EncryptedFrames = sendApplicationRequest(method, path, body, service, headers, endBody = true)

    fun startStreamRequest(
        method: String,
        path: String,
        service: ServiceType = ServiceType.DAEMON,
        headers: List<Header> = emptyList(),
    ): EncryptedFrames = sendApplicationRequest(method, path, ByteArray(0), service, headers, endBody = false)

    private fun sendApplicationRequest(
        method: String,
        path: String,
        body: ByteArray,
        service: ServiceType,
        headers: List<Header>,
        endBody: Boolean,
    ): EncryptedFrames {
        assertAlive()
        try {
            val streamId = nextStreamId++
            val frame = ServiceFrame.request(
                streamId,
                ApplicationRequest(verb = method, path = path, headers = headers, body = body, endBody = endBody),
            )
            return EncryptedFrames(streamId, encryptRequest(service, frame))
        } catch (e: Exception) {
            markDead(e)
        }
    }

    fun encryptBodyChunk(
        streamId: Long,
        data: ByteArray,
        service: ServiceType = ServiceType.DAEMON,
        endBody: Boolean = false,
    ): List<ByteArray> {
        assertAlive()
        try {
            return encryptRequest(
                service,
                ServiceFrame.bodyChunk(streamId, BodyChunk(data, endBody)),
            )
        } catch (e: Exception) {
            markDead(e)
        }
    }

    fun encryptReset(
        streamId: Long,
        service: ServiceType = ServiceType.DAEMON,
        reason: String = "",
        code: ResetCode = ResetCode.CANCELLED,
    ): List<ByteArray> {
        assertAlive()
        try {
            return encryptRequest(
                service,
                ServiceFrame.reset(streamId, Reset(code, reason)),
            )
        } catch (e: Exception) {
            markDead(e)
        }
    }

    /**
     * Decrypts one WS binary frame. Returns null while a multi-chunk message
     * is still assembling. The server must never send `request` frames.
     */
    fun decryptFrame(ciphertext: ByteArray): DecryptedFrame? {
        assertAlive()
        try {
            val plain = recv.decryptWithAd(NoiseTransportConstants.EMPTY_AD, ciphertext)
            val reassembled = decoder.decode(plain) ?: return null
            val response = Envelope.decodeServiceResponse(reassembled)
            if (response.payload.isEmpty()) {
                throw NoiseTransportException("empty ServiceResponse payload")
            }
            val frame = Envelope.decodeServiceFrame(response.payload)
            return when (frame.kind) {
                ServiceFrame.Kind.RESPONSE -> {
                    val r = (frame.value as? Resp)?.r
                        ?: throw NoiseTransportException("invalid response frame")
                    DecryptedFrame(DecryptedFrame.Kind.RESPONSE, frame.streamId, ResponseValue(r))
                }
                ServiceFrame.Kind.BODY_CHUNK -> {
                    val c = (frame.value as? Chunk)?.c
                        ?: throw NoiseTransportException("invalid body_chunk frame")
                    DecryptedFrame(DecryptedFrame.Kind.BODY_CHUNK, frame.streamId, BodyChunkValue(c))
                }
                ServiceFrame.Kind.RESET -> {
                    val r = (frame.value as? Rst)?.r
                        ?: throw NoiseTransportException("invalid reset frame")
                    DecryptedFrame(DecryptedFrame.Kind.RESET, frame.streamId, ResetValue(r))
                }
                ServiceFrame.Kind.REQUEST ->
                    throw NoiseTransportException("NoiseTransport: unexpected request frame from server")
                null -> throw NoiseTransportException("ServiceFrame without kind")
            }
        } catch (e: NoiseTransportException) {
            dead = true
            throw e
        } catch (e: Exception) {
            markDead(e)
        }
    }

    private fun encryptRequest(service: ServiceType, frame: ServiceFrame): List<ByteArray> {
        val frameBytes = Envelope.encodeServiceFrame(frame)
        val requestBytes = Envelope.encodeServiceRequest(ServiceRequest(service, frameBytes))
        return Framing.encodeNoiseFrames(requestBytes)
            .map { send.encryptWithAd(NoiseTransportConstants.EMPTY_AD, it) }
    }

    companion object {
        fun decodeRequestEnvelope(data: ByteArray): ServiceFrame {
            val req = Envelope.decodeServiceRequest(data)
            return Envelope.decodeServiceFrame(req.payload)
        }

        fun encodeResponseEnvelope(frame: ServiceFrame): ByteArray =
            Envelope.encodeServiceResponse(ServiceResponse(Envelope.encodeServiceFrame(frame)))

        /** Symmetric counterpart of [decodeRequestEnvelope] for the response path. */
        fun decodeResponseEnvelope(data: ByteArray): ServiceFrame {
            val resp = Envelope.decodeServiceResponse(data)
            return Envelope.decodeServiceFrame(resp.payload)
        }
    }
}
