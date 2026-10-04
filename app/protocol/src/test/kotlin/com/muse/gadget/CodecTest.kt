package com.muse.gadget

import com.muse.gadget.api.MuseAccountApi
import com.muse.gadget.api.VmInfo
import com.muse.gadget.audio.VoiceNoteEncoder
import com.muse.gadget.ble.BleFraming
import com.muse.gadget.identity.Identity
import com.muse.gadget.session.ChatStreams
import com.muse.gadget.session.WsUpgrade
import com.muse.gadget.util.Json
import com.muse.gadget.util.field
import com.muse.gadget.util.JsonValue
import com.muse.gadget.util.strField
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.Base64

class VoiceNoteEncoderTest {
    @Test
    fun `wav header is exactly 44 bytes with the spec layout`() {
        val h = VoiceNoteEncoder.wavHeader()
        assertEquals(44, h.size)
        fun str(off: Int, len: Int) = h.copyOfRange(off, off + len).toString(Charsets.US_ASCII)
        fun u32(off: Int): Long {
            var v = 0L
            for (i in 0 until 4) v = v or ((h[off + i].toLong() and 0xFF) shl (8 * i))
            return v
        }
        fun u16(off: Int): Int = (h[off].toInt() and 0xFF) or ((h[off + 1].toInt() and 0xFF) shl 8)
        assertEquals("RIFF", str(0, 4))
        assertEquals(0xFFFFFFFFL, u32(4))
        assertEquals("WAVE", str(8, 4))
        assertEquals("fmt ", str(12, 4))
        assertEquals(16L, u32(16))
        assertEquals(1, u16(20)) // PCM
        assertEquals(1, u16(22)) // mono
        assertEquals(16000L, u32(24))
        assertEquals(32000L, u32(28)) // byte rate
        assertEquals(2, u16(32)) // block align
        assertEquals(16, u16(34)) // bits per sample
        assertEquals("data", str(36, 4))
        assertEquals(0xFFFFFFFFL, u32(40))
    }

    @Test
    fun `6144 bytes of pcm become one 8192 char base64 chunk`() {
        val pcm = ByteArray(6144) { it.toByte() }
        val chunks = VoiceNoteEncoder.encodeChunks(pcm)
        assertEquals(1, chunks.size)
        assertEquals(8192, chunks[0].length)
        // standard alphabet with padding
        assertTrue(chunks[0].all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '+' || it == '/' || it == '=' })
        assertArrayEquals(pcm, Base64.getDecoder().decode(chunks[0]))
    }

    @Test
    fun `chunking splits on 6144 byte boundaries`() {
        val pcm = ByteArray(6144 * 2 + 100) { (it % 256).toByte() }
        val chunks = VoiceNoteEncoder.encodeChunks(pcm)
        assertEquals(3, chunks.size)
        assertEquals(8192, chunks[0].length)
        assertEquals(8192, chunks[1].length)
        val joined = chunks.joinToString("")
        assertArrayEquals(pcm, Base64.getDecoder().decode(joined))
    }

    @Test
    fun `odd byte count is rejected`() {
        assertThrows<IllegalArgumentException> { VoiceNoteEncoder.encodeChunks(ByteArray(3)) }
    }

    @Test
    fun `voice note head and tail constants`() {
        assertTrue(ChatStreams.VOICE_NOTE_HEAD.startsWith("{\"message\":\"\",\"output_modality\":\"text\""))
        assertTrue(ChatStreams.VOICE_NOTE_HEAD.endsWith("\"data_base64\":\""))
        assertTrue(ChatStreams.VOICE_NOTE_HEAD.contains("\"mime_type\":\"audio/wav\""))
        assertEquals("\"}]}", ChatStreams.VOICE_NOTE_TAIL)
    }
}

class ChatStreamsTest {
    @Test
    fun `text body carries message and optional fields`() {
        val body = Json.parseObj(ChatStreams.textBody("hello", "homelink-000001", "sess-1").toString(Charsets.UTF_8))
        assertEquals("hello", body.strField("message"))
        assertEquals("text", body.strField("output_modality"))
        assertEquals("homelink-000001", body.strField("device_id"))
        assertEquals("sess-1", body.strField("session_id"))
        // chat_id must never be sent (server ignores it)
        assertNull(body.field("chat_id"))
        val minimal = Json.parseObj(ChatStreams.textBody("hi").toString(Charsets.UTF_8))
        assertNull(minimal.field("device_id"))
        assertNull(minimal.field("session_id"))
    }

    @Test
    fun `chat headers use hatch-web app id`() {
        val headers = ChatStreams.chatHeaders("muse-0123456789abcdef")
        val map = headers.associate { it.key to it.value }
        assertEquals("application/json", map["Content-Type"])
        assertEquals("muse-0123456789abcdef", map["x-request-id"])
        assertEquals(Identity.APP_ID, map["x-app-id"])
    }

    @Test
    fun `request id shape is validated`() {
        assertEquals("muse-0123456789abcdef", ChatStreams.newRequestId("0123456789abcdef"))
        assertThrows<IllegalArgumentException> { ChatStreams.newRequestId("xyz") }
    }

    @Test
    fun `subscribe body is an empty object`() {
        assertArrayEquals("{}".toByteArray(), ChatStreams.subscribeBody())
        val headers = ChatStreams.subscribeHeaders().associate { it.key to it.value }
        assertEquals("application/x-ndjson", headers["Accept"])
    }
}

class WsUpgradeTest {
    @Test
    fun `vm_id escaping matches python quote semantics`() {
        // "vm 1&x" from the python test -> "vm%201%26x"
        assertEquals("vm%201%26x", WsUpgrade.escapeVmId("vm 1&x"))
        assertEquals("abc-_.!~*'()", WsUpgrade.escapeVmId("abc-_.!~*'()"))
        assertEquals("a%2Fb", WsUpgrade.escapeVmId("a/b"))
        // non-ASCII -> UTF-8 percent-encoded uppercase
        assertEquals("%E4%B8%AD", WsUpgrade.escapeVmId("中"))
    }

    @Test
    fun `upgrade request uses the fixed websocket key`() {
        val req = WsUpgrade.buildRequest("hatch.metaaivm.com", "vm 1&x", "tok123")
        assertTrue(req.startsWith("GET /v1/noise?vm_id=vm%201%26x HTTP/1.1\r\n"))
        assertTrue(req.contains("Host: hatch.metaaivm.com\r\n"))
        assertTrue(req.contains("Authorization: Bearer tok123\r\n"))
        assertTrue(req.contains("Upgrade: websocket\r\n"))
        assertTrue(req.contains("Sec-WebSocket-Version: 13\r\n"))
        assertTrue(req.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"))
        assertTrue(req.endsWith("\r\n\r\n"))
    }

    @Test
    fun `noise url builder`() {
        assertEquals(
            "wss://gw.example/v1/noise?vm_id=vm%201%26x",
            WsUpgrade.noiseUrl("gw.example", "vm 1&x"),
        )
    }
}

class MuseAccountApiTest {
    @Test
    fun `fetch_vms selects the default vm`() {
        val body = """
            {"vm_list":[
              {"vm_id":"a","vm_ws_url":"wss://a/x","vm_auth_token":"ta","default":false},
              {"vm_id":"b","vm_ws_url":"wss://b/x","vm_auth_token":"tb","default":true},
              {"vm_id":"c","vm_url":"wss://c/x","vm_auth_token":"tc"}
            ]}
        """.trimIndent()
        val vms = MuseAccountApi.parseVmList(body)
        assertEquals(3, vms.size)
        assertEquals("b", MuseAccountApi.selectVm(vms)!!.vmId)
        // vm_url fallback works
        assertEquals("wss://c/x", vms[2].wsUrl)
    }

    @Test
    fun `vm_id falls back to the first dns label`() {
        val body = """{"vm_list":[{"vm_ws_url":"wss://abc123.hatch.metaaivm.com/v1/noise","vm_auth_token":"t"}]}"""
        val vms = MuseAccountApi.parseVmList(body)
        assertEquals("abc123", vms[0].vmId)
        assertEquals("abc123", MuseAccountApi.vmIdFromUrl("wss://abc123.hatch.metaaivm.com/v1/noise"))
    }

    @Test
    fun `error responses yield no vms`() {
        assertEquals(
            emptyList<VmInfo>(),
            MuseAccountApi.parseVmList("""{"error_title":"nope","backend_error_code":"x"}"""),
        )
        assertEquals(emptyList<VmInfo>(), MuseAccountApi.parseVmList("not json"))
        assertNull(MuseAccountApi.selectVm(emptyList()))
    }

    @Test
    fun `refresh prefix stripping`() {
        assertEquals("abc", MuseAccountApi.stripRefreshPrefix("hatch_refresh:abc"))
        assertEquals("abc", MuseAccountApi.stripRefreshPrefix("abc"))
        assertEquals("Bearer hatch_refresh:abc", MuseAccountApi.refreshAuthHeader("xxx:hatch_refresh:abc"))
        assertEquals("Bearer hatch_refresh:abc", MuseAccountApi.refreshAuthHeader("abc"))
    }

    @Test
    fun `refresh body and response parsing`() {
        val body = Json.parseObj(MuseAccountApi.refreshBody("hatch-link:02:00:00:00:00:01", "mgst_x"))
        assertEquals("hatch-link:02:00:00:00:00:01", body.strField("device_id"))
        assertEquals("mgst_x", body.strField("sdk_token"))
        val noToken = Json.parseObj(MuseAccountApi.refreshBody("d", null))
        assertNull(noToken.field("sdk_token"))

        val parsed = MuseAccountApi.parseRefreshResponse(
            """{"payload":{"access_token":"a1","refresh_token":"r1"}}""",
        )
        assertEquals("a1" to "r1", parsed)
        // top-level shape also accepted
        assertEquals(
            "a1" to "r1",
            MuseAccountApi.parseRefreshResponse("""{"access_token":"a1","refresh_token":"r1"}"""),
        )
        assertNull(MuseAccountApi.parseRefreshResponse("""{"payload":{}}"""))
    }

    @Test
    fun `api root prefers api_url_v2`() {
        assertEquals("https://api.muse.ai", MuseAccountApi.apiRoot(""))
        assertEquals("https://example.com", MuseAccountApi.apiRoot("https://example.com/"))
        assertEquals("https://api.muse.ai/fetch_vms", MuseAccountApi.fetchVmsUrl(MuseAccountApi.apiRoot("")))
        assertEquals(
            "https://api.muse.ai/device_token/refresh",
            MuseAccountApi.refreshUrl(MuseAccountApi.apiRoot("")),
        )
    }
}

class BleFramingTest {
    @Test
    fun `encode decode round trip with tiny chunks`() {
        val msg = "hello ble".toByteArray()
        val chunks = BleFraming.encode(msg, maxPayload = 4)
        assertEquals(3, chunks.size)
        assertTrue(chunks.all { it[0] == Identity.CHUNK_MAGIC })
        val r = BleFraming.Reassembler()
        assertNull(r.feed(chunks[2]))
        assertNull(r.feed(chunks[0]))
        assertArrayEquals(msg, r.feed(chunks[1]))
    }

    @Test
    fun `empty message is one chunk`() {
        val chunks = BleFraming.encode(ByteArray(0))
        assertEquals(1, chunks.size)
        assertArrayEquals(ByteArray(0), BleFraming.Reassembler().feed(chunks[0]))
    }

    @Test
    fun `bad magic poisons the reassembler`() {
        val r = BleFraming.Reassembler()
        assertThrows<IllegalArgumentException> { r.feed(byteArrayOf(0x00, 0, 1)) }
        assertThrows<IllegalStateException> { r.feed(byteArrayOf(Identity.CHUNK_MAGIC, 0, 1)) }
    }

    @Test
    fun `duplicate chunk is rejected`() {
        val chunks = BleFraming.encode("abcdef".toByteArray(), maxPayload = 3)
        val r = BleFraming.Reassembler()
        r.feed(chunks[0])
        assertThrows<IllegalArgumentException> { r.feed(chunks[0]) }
    }
}

class JsonTest {
    @Test
    fun `round trip with escapes and unicode`() {
        val v = Json.parse("{\"a\":\"x\\u4e2d\\n\",\"b\":[1,-2.5,true,null],\"c\":{}}")
        val o = v as JsonValue.Obj
        assertEquals("x中\n", (o.fields["a"] as JsonValue.Str).value)
        val arr = o.fields["b"] as JsonValue.Arr
        assertEquals("1", (arr.items[0] as JsonValue.Num).raw)
        assertEquals("-2.5", (arr.items[1] as JsonValue.Num).raw)
        val s = Json.stringify(v)
        assertEquals(v, Json.parse(s))
    }

    @Test
    fun `malformed input throws`() {
        for (bad in listOf("", "{", "{\"a\":}", "[1,]", "{\"a\" 1}", "\"\\x\"")) {
            assertThrows<IllegalArgumentException>("should reject: $bad") { Json.parse(bad) }
        }
    }

    @Test
    fun `stringify escapes control characters`() {
        val s = Json.stringify(Json.obj("k" to Json.str("a\"b\\c\u0001")))
        assertEquals("{\"k\":\"a\\\"b\\\\c\\u0001\"}", s)
    }
}
