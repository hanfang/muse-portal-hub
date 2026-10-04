package com.muse.gadget

import com.muse.gadget.noise.CipherState
import com.muse.gadget.noise.NoiseParams
import com.muse.gadget.noise.NoiseProtocolException
import com.muse.gadget.noise.NoiseXXInitiator
import com.muse.gadget.noise.NoiseXXResponder
import com.muse.gadget.noise.X25519
import com.muse.gadget.noise.buildNoiseNonceIv
import com.muse.gadget.util.Json
import com.muse.gadget.util.field
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.KeyPair

/**
 * Noise XX tests: byte-level cross-check against the Python reference
 * (fixed seeds in `vectors/noise_xx_fixed.json`) plus a live in-process
 * handshake between initiator and responder (mirrors `test_link_client.py`'s
 * FakeVm, which does a real Noise handshake).
 */
class NoiseXxTest {
    private fun keypair(seedHex: String, pubHex: String): KeyPair {
        val priv = X25519.privateKeyFromRaw(TestUtil.hexToBytes(seedHex))
        val pub = X25519.publicKeyFromRaw(TestUtil.hexToBytes(pubHex))
        return KeyPair(pub, priv)
    }

    @Test
    fun `low order points table has seven 32 byte entries`() {
        // Byte-for-byte verified against noise_xx.X25519_LOW_ORDER_POINTS.
        for (p in NoiseParams.X25519_LOW_ORDER_POINTS) {
            assertEquals(32, p.size)
        }
        assertEquals(7, NoiseParams.X25519_LOW_ORDER_POINTS.size)
        assertArrayEquals(ByteArray(32), NoiseParams.X25519_LOW_ORDER_POINTS[0])
        assertEquals(0x01, NoiseParams.X25519_LOW_ORDER_POINTS[1][0].toInt() and 0xFF)
        assertEquals(0x00.toByte(), NoiseParams.X25519_LOW_ORDER_POINTS[2][31])
        assertEquals(0xE0.toByte(), NoiseParams.X25519_LOW_ORDER_POINTS[2][0])
    }

    private data class Fixed(val m: Map<String, String>) {
        operator fun get(k: String): String = m[k] ?: error("missing $k")
        fun bytes(k: String): ByteArray = TestUtil.hexToBytes(get(k))
    }

    private fun fixed(): Fixed {
        val root = Json.parse(TestUtil.loadVectors("noise_xx_fixed.json"))
            as com.muse.gadget.util.JsonValue.Obj
        val seeds = root.field("seeds") as com.muse.gadget.util.JsonValue.Obj
        val pubs = root.field("pubs") as com.muse.gadget.util.JsonValue.Obj
        val m = HashMap<String, String>()
        for ((k, v) in seeds.fields) m["seed_$k"] = (v as com.muse.gadget.util.JsonValue.Str).value
        for ((k, v) in pubs.fields) m["pub_$k"] = (v as com.muse.gadget.util.JsonValue.Str).value
        for (k in listOf("msg1", "msg2", "msg3", "handshake_hash", "ct_i2r", "ct_r2i")) {
            m[k] = (root.field(k) as com.muse.gadget.util.JsonValue.Str).value
        }
        m["msg2_payload"] = (root.field("msg2_payload") as com.muse.gadget.util.JsonValue.Str).value
        return Fixed(m)
    }

    @Test
    fun `handshake bytes match the python reference exactly`() {
        val f = fixed()
        val initKeys = listOf(
            keypair(f["seed_e_i"], f["pub_e_i"]),
            keypair(f["seed_s_i"], f["pub_s_i"]),
        ).iterator()
        val respKeys = listOf(
            keypair(f["seed_e_r"], f["pub_e_r"]),
            keypair(f["seed_s_r"], f["pub_s_r"]),
        ).iterator()
        val init = NoiseXXInitiator { initKeys.next() }
        val resp = NoiseXXResponder("responder-hello".toByteArray()) { respKeys.next() }
        init.initialize()
        resp.initialize()

        val msg1 = init.writeMessage1()
        assertArrayEquals(f.bytes("msg1"), msg1, "msg1 mismatch")

        val msg2 = resp.readMessage1AndWriteMessage2(msg1)
        assertArrayEquals(f.bytes("msg2"), msg2, "msg2 mismatch")

        val payload = init.readMessage2(msg2)
        assertEquals("responder-hello", payload.toString(Charsets.UTF_8))

        val msg3 = init.writeMessage3()
        assertArrayEquals(f.bytes("msg3"), msg3, "msg3 mismatch")
        resp.readMessage3(msg3)

        assertArrayEquals(f.bytes("handshake_hash"), init.handshakeHash())
        assertArrayEquals(f.bytes("handshake_hash"), resp.handshakeHash())

        val (iSend, iRecv) = init.split()
        val (rSend, rRecv) = resp.split()

        // Transport ciphertext must match the reference byte-for-byte
        // (same keys, same nonce 0, empty AD).
        assertArrayEquals(f.bytes("ct_i2r"), iSend.encryptWithAd(ByteArray(0), "hello-initiator".toByteArray()))
        assertArrayEquals(f.bytes("ct_r2i"), rSend.encryptWithAd(ByteArray(0), "hello-responder".toByteArray()))
        // Cross-decrypt.
        assertEquals(
            "hello-initiator",
            rRecv.decryptWithAd(ByteArray(0), f.bytes("ct_i2r")).toString(Charsets.UTF_8),
        )
        assertEquals(
            "hello-responder",
            iRecv.decryptWithAd(ByteArray(0), f.bytes("ct_r2i")).toString(Charsets.UTF_8),
        )
    }

    @Test
    fun `in-process handshake exchanges frames both ways`() {
        // Mirrors test_link_client.py's FakeVm: real Noise handshake, then
        // encrypted application frames in both directions.
        val init = NoiseXXInitiator()
        val resp = NoiseXXResponder()
        init.initialize()
        resp.initialize()
        val msg2 = resp.readMessage1AndWriteMessage2(init.writeMessage1())
        init.readMessage2(msg2)
        resp.readMessage3(init.writeMessage3())
        val (iSend, iRecv) = init.split()
        val (rSend, rRecv) = resp.split()
        assertArrayEquals(init.handshakeHash(), resp.handshakeHash())

        repeat(5) { i ->
            val a = iSend.encryptWithAd(ByteArray(0), "i->$i".toByteArray())
            assertEquals("i->$i", rRecv.decryptWithAd(ByteArray(0), a).toString(Charsets.UTF_8))
            val b = rSend.encryptWithAd(ByteArray(0), "r->$i".toByteArray())
            assertEquals("r->$i", iRecv.decryptWithAd(ByteArray(0), b).toString(Charsets.UTF_8))
        }
    }

    @Test
    fun `nonce layout is 4 zero bytes plus big-endian counter`() {
        assertArrayEquals(
            byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
            buildNoiseNonceIv(1),
        )
        assertArrayEquals(ByteArray(12), buildNoiseNonceIv(0))
        assertThrows<NoiseProtocolException> { buildNoiseNonceIv(-1) }
    }

    @Test
    fun `low order peer key is rejected`() {
        val init = NoiseXXInitiator()
        val resp = NoiseXXResponder()
        init.initialize()
        resp.initialize()
        // msg1 with an all-zeros ephemeral key: DH must refuse it.
        assertThrows<NoiseProtocolException> {
            resp.readMessage1AndWriteMessage2(ByteArray(32))
        }
        // wrong phase sequencing is rejected
        val init2 = NoiseXXInitiator()
        assertThrows<NoiseProtocolException> { init2.writeMessage1() } // not initialized
        init2.initialize()
        init2.writeMessage1()
        assertThrows<NoiseProtocolException> { init2.writeMessage1() } // wrong phase
        assertThrows<NoiseProtocolException> { init2.split() } // too early
    }

    @Test
    fun `decrypt failure poisons the cipher state`() {
        val init = NoiseXXInitiator()
        val resp = NoiseXXResponder()
        init.initialize(); resp.initialize()
        val msg2 = resp.readMessage1AndWriteMessage2(init.writeMessage1())
        init.readMessage2(msg2)
        resp.readMessage3(init.writeMessage3())
        val (iSend, _) = init.split()
        val (_, rRecv) = resp.split()

        val ct = iSend.encryptWithAd(ByteArray(0), "secret".toByteArray())
        ct[5] = (ct[5].toInt() xor 1).toByte()
        assertThrows<NoiseProtocolException> { rRecv.decryptWithAd(ByteArray(0), ct) }
        // poisoned: even valid ops now fail
        val ct2 = iSend.encryptWithAd(ByteArray(0), "more".toByteArray())
        assertThrows<NoiseProtocolException> { rRecv.decryptWithAd(ByteArray(0), ct2) }
        assertThrows<NoiseProtocolException> { rRecv.encryptWithAd(ByteArray(0), "x".toByteArray()) }
    }

    @Test
    fun `unkeyed cipher state passes plaintext through`() {
        val c = CipherState()
        assertEquals("hi", c.encryptWithAd(ByteArray(0), "hi".toByteArray()).toString(Charsets.UTF_8))
    }

    @Test
    fun `x25519 raw key round trip`() {
        val kp = X25519.generateKeypair()
        val raw = X25519.rawPublicKey(kp.public)
        assertEquals(32, raw.size)
        val kp2 = X25519.generateKeypair()
        val s1 = X25519.dh(kp.private, X25519.rawPublicKey(kp2.public))
        val s2 = X25519.dh(kp2.private, raw)
        assertArrayEquals(s1, s2)
        assertEquals(32, s1.size)
        assertTrue(s1.any { it != 0.toByte() })
    }
}
