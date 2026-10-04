package com.muse.gadget

import com.muse.gadget.noise.ApplicationRequest
import com.muse.gadget.noise.ApplicationResponse
import com.muse.gadget.noise.BodyChunk
import com.muse.gadget.noise.Chunk
import com.muse.gadget.noise.Envelope
import com.muse.gadget.noise.Framing
import com.muse.gadget.noise.Header
import com.muse.gadget.noise.NoiseTransport
import com.muse.gadget.noise.Proto
import com.muse.gadget.noise.Req
import com.muse.gadget.noise.Reset
import com.muse.gadget.noise.ResetCode
import com.muse.gadget.noise.Resp
import com.muse.gadget.noise.Rst
import com.muse.gadget.noise.ServiceFrame
import com.muse.gadget.noise.ServiceRequest
import com.muse.gadget.noise.ServiceResponse
import com.muse.gadget.noise.ServiceType
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class ProtoEnvelopeFramingTest {
    // -- varint ---------------------------------------------------------------
    @Test
    fun `varint round trip boundaries`() {
        for (v in listOf(0L, 1L, 127L, 128L, 300L, 16384L, Long.MAX_VALUE)) {
            val enc = Proto.encodeVarint(v)
            val (dec, pos) = Proto.readVarint(enc, 0)
            assertEquals(v, dec)
            assertEquals(enc.size, pos)
        }
        // 300 encodes as 0xAC 0x02
        assertArrayEquals(byteArrayOf(0xAC.toByte(), 0x02), Proto.encodeVarint(300))
        assertThrows<IllegalArgumentException> { Proto.encodeVarint(-1) }
    }

    @Test
    fun `negative int64 encodes as 10 bytes`() {
        val enc = Proto.int64Field(1, -1)
        // key (1 byte) + 10-byte varint
        assertEquals(11, enc.size)
        val frame = Framing.decodeNoiseFrame(enc)
        assertEquals(-1L, frame.chunkId)
    }

    // -- NoiseTransportFrame ----------------------------------------------------
    @Test
    fun `noise transport frame round trip`() {
        val f = Framing.NoiseTransportFrame(
            chunkId = -123456789012345L,
            chunkIndex = 2,
            totalChunks = 5,
            payload = byteArrayOf(1, 2, 3),
        )
        val back = Framing.decodeNoiseFrame(Framing.encodeNoiseFrame(f))
        assertEquals(f.chunkId, back.chunkId)
        assertEquals(f.chunkIndex, back.chunkIndex)
        assertEquals(f.totalChunks, back.totalChunks)
        assertArrayEquals(f.payload, back.payload)
        // default-valued fields are omitted on the wire
        val minimal = Framing.encodeNoiseFrame(Framing.NoiseTransportFrame())
        assertEquals(0, minimal.size)
    }

    @Test
    fun `multi chunk assembly out of order`() {
        val data = ByteArray(200_000) { (it % 251).toByte() }
        val frames = Framing.encodeNoiseFrames(data, chunkId = 42)
        assertEquals(4, frames.size) // 65489*3 = 196467 < 200000
        val decoder = Framing.NoiseFrameDecoder()
        // deliver out of order: 2, 0, 3, 1
        assertNull(decoder.decode(frames[2]))
        assertNull(decoder.decode(frames[0]))
        assertNull(decoder.decode(frames[3]))
        val done = decoder.decode(frames[1])
        assertArrayEquals(data, done)
    }

    @Test
    fun `decoder poisons on duplicate chunk`() {
        val frames = Framing.encodeNoiseFrames(ByteArray(130_000) { 7 }, chunkId = 9)
        val decoder = Framing.NoiseFrameDecoder()
        decoder.decode(frames[0])
        assertThrows<IllegalArgumentException> { decoder.decode(frames[0]) }
        assertThrows<IllegalStateException> { decoder.decode(frames[1]) }
    }

    @Test
    fun `decoder rejects inconsistent totals`() {
        val frames = Framing.encodeNoiseFrames(ByteArray(130_000) { 7 }, chunkId = 9)
        val decoder = Framing.NoiseFrameDecoder()
        decoder.decode(frames[0])
        // hand-crafted frame with same chunk id but different total
        val bad = Framing.encodeNoiseFrame(
            Framing.NoiseTransportFrame(chunkId = 9, chunkIndex = 1, totalChunks = 3, payload = ByteArray(10)),
        )
        assertThrows<IllegalArgumentException> { decoder.decode(bad) }
    }

    @Test
    fun `empty payload encodes as a single empty frame`() {
        val frames = Framing.encodeNoiseFrames(ByteArray(0), chunkId = 1)
        assertEquals(1, frames.size)
        val decoder = Framing.NoiseFrameDecoder()
        assertArrayEquals(ByteArray(0), decoder.decode(frames[0]))
    }

    // -- envelope -----------------------------------------------------------------
    @Test
    fun `service frame request round trip`() {
        val frame = ServiceFrame.request(
            7,
            ApplicationRequest(
                verb = "POST",
                path = "/chat/stream",
                headers = listOf(Header("Content-Type", "application/json"), Header("x-app-id", "hatch-web")),
                body = "{\"a\":1}".toByteArray(),
                endBody = true,
            ),
        )
        val back = Envelope.decodeServiceFrame(Envelope.encodeServiceFrame(frame))
        assertEquals(7L, back.streamId)
        assertEquals(ServiceFrame.Kind.REQUEST, back.kind)
        val req = (back.value as Req).r
        assertEquals("POST", req.verb)
        assertEquals("/chat/stream", req.path)
        assertEquals(2, req.headers.size)
        assertEquals("x-app-id", req.headers[1].key)
        assertArrayEquals("{\"a\":1}".toByteArray(), req.body)
        assertTrue(req.endBody)
    }

    @Test
    fun `service frame response and reset round trip`() {
        val resp = ServiceFrame.response(
            3, ApplicationResponse(status = 200, body = "ok".toByteArray(), endBody = true),
        )
        val back = Envelope.decodeServiceFrame(Envelope.encodeServiceFrame(resp))
        val r = (back.value as Resp).r
        assertEquals(200, r.status)
        assertTrue(r.endBody)

        val rst = ServiceFrame.reset(9, Reset(ResetCode.CANCELLED, "cancelled"))
        val backRst = Envelope.decodeServiceFrame(Envelope.encodeServiceFrame(rst))
        val rr = (backRst.value as Rst).r
        assertEquals(ResetCode.CANCELLED, rr.code)
        assertEquals("cancelled", rr.reason)
    }

    @Test
    fun `body chunk round trip`() {
        val c = ServiceFrame.bodyChunk(11, BodyChunk("data123".toByteArray(), endBody = false))
        val back = Envelope.decodeServiceFrame(Envelope.encodeServiceFrame(c))
        val bc = (back.value as Chunk).c
        assertArrayEquals("data123".toByteArray(), bc.data)
        assertEquals(false, bc.endBody)
    }

    @Test
    fun `service request omits default daemon service`() {
        val enc = Envelope.encodeServiceRequest(ServiceRequest(ServiceType.DAEMON, "p".toByteArray()))
        val back = Envelope.decodeServiceRequest(enc)
        assertEquals(ServiceType.DAEMON, back.service)
        assertArrayEquals("p".toByteArray(), back.payload)
        // non-default service is preserved
        val enc2 = Envelope.encodeServiceRequest(ServiceRequest(ServiceType.VAULT, ByteArray(0)))
        assertEquals(ServiceType.VAULT, Envelope.decodeServiceRequest(enc2).service)
    }

    @Test
    fun `service response empty payload encodes empty`() {
        assertEquals(0, Envelope.encodeServiceResponse(ServiceResponse(ByteArray(0))).size)
    }

    @Test
    fun `request and response envelope helpers`() {
        val frame = ServiceFrame.request(1, ApplicationRequest(verb = "POST", path = "/x"))
        val env = NoiseTransport.decodeRequestEnvelope(
            Envelope.encodeServiceRequest(ServiceRequest(ServiceType.DAEMON, Envelope.encodeServiceFrame(frame))),
        )
        assertEquals(1L, env.streamId)
        assertEquals(ServiceFrame.Kind.REQUEST, env.kind)
        val back = NoiseTransport.decodeResponseEnvelope(NoiseTransport.encodeResponseEnvelope(frame))
        assertEquals(1L, back.streamId)
    }

    @Test
    fun `unknown fields are skipped`() {
        // field 99 (varint) + valid chunk_id field
        val raw = Proto.varintField(99, 123) + Proto.int64Field(1, 5)
        val f = Framing.decodeNoiseFrame(raw)
        assertEquals(5L, f.chunkId)
    }
}
