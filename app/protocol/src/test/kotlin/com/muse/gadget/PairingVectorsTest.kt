package com.muse.gadget

import com.muse.gadget.TestUtil.toHex

import com.muse.gadget.pairing.PairingCrypto
import com.muse.gadget.util.Json
import com.muse.gadget.util.strField
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/** Shared test helpers. */
object TestUtil {
    fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0)
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    fun loadVectors(name: String): String =
        TestUtil::class.java.getResource("/vectors/$name")!!.readText()
}

/**
 * 1:1 translation of the Python pairing tests against
 * `tests/vectors/link_pairing_v5.json` (3 vectors).
 */
class PairingVectorsTest {
    private data class Vec(val m: Map<String, String>) {
        operator fun get(k: String): String = m[k] ?: error("missing $k")
    }

    private fun vectors(): List<Vec> {
        val root = Json.parse(TestUtil.loadVectors("link_pairing_v5.json"))
        val arr = (root as com.muse.gadget.util.JsonValue.Obj)
            .fields["vectors"] as com.muse.gadget.util.JsonValue.Arr
        return arr.items.map { item ->
            val o = item as com.muse.gadget.util.JsonValue.Obj
            Vec(o.fields.mapValues { (_, v) -> scalarString(v) })
        }
    }

    private fun scalarString(v: com.muse.gadget.util.JsonValue): String = when (v) {
        is com.muse.gadget.util.JsonValue.Str -> v.value
        is com.muse.gadget.util.JsonValue.Num -> v.raw
        com.muse.gadget.util.JsonValue.True -> "true"
        com.muse.gadget.util.JsonValue.False -> "false"
        else -> error("non-scalar vector field: $v")
    }

    @Test
    fun `three vectors present`() {
        assertEquals(3, vectors().size)
    }

    @Test
    fun `transcript matches every vector byte-for-byte`() {
        for (v in vectors()) {
            val built = PairingCrypto.buildTranscript(
                community = v["community"] == "True" || v["community"] == "true",
                authEpoch = v["pairing_auth_epoch"].toInt(),
                policy = v["pairing_policy"],
                deviceId = v["device_id"],
                nodeId = v["node_id"],
                mac = v["mac"],
                firmwareVersion = v["firmware_version"],
                mobilePub = v["mobile_pub"],
                devicePub = v["device_pub"],
                mobileNonce = v["mobile_nonce"],
                deviceNonce = v["device_nonce"],
            )
            assertEquals(v["transcript"], built, "transcript mismatch in ${v["name"]}")
            val hash = PairingCrypto.b64urlEncode(PairingCrypto.sha256(built.toByteArray()))
            assertEquals(v["transcript_hash"], hash, "transcript_hash mismatch in ${v["name"]}")
        }
    }

    @Test
    fun `public keys match the private scalars`() {
        for (v in vectors()) {
            val mobileScalar = TestUtil.hexToBytes(v["mobile_private_scalar_hex"])
            val deviceScalar = TestUtil.hexToBytes(v["device_private_scalar_hex"])
            assertEquals(
                v["mobile_pub"],
                PairingCrypto.b64urlEncode(PairingCrypto.publicPoint65(mobileScalar)),
                "mobile_pub mismatch in ${v["name"]}",
            )
            assertEquals(
                v["device_pub"],
                PairingCrypto.b64urlEncode(PairingCrypto.publicPoint65(deviceScalar)),
                "device_pub mismatch in ${v["name"]}",
            )
        }
    }

    @Test
    fun `ecdh secret matches every vector`() {
        for (v in vectors()) {
            val deviceScalar = TestUtil.hexToBytes(v["device_private_scalar_hex"])
            val mobilePub = PairingCrypto.b64urlDecode(v["mobile_pub"])
            val secret = PairingCrypto.ecdhX(deviceScalar, mobilePub)
            assertEquals(v["ecdh_secret_hex"], secret.toHex(), "ecdh mismatch in ${v["name"]}")
        }
    }

    @Test
    fun `key schedule matches every vector`() {
        for (v in vectors()) {
            val ecdh = TestUtil.hexToBytes(v["ecdh_secret_hex"])
            val mobileNonce = PairingCrypto.b64urlDecode(v["mobile_nonce"])
            val deviceNonce = PairingCrypto.b64urlDecode(v["device_nonce"])
            val transcriptHash = PairingCrypto.b64urlDecode(v["transcript_hash"])
            val keys = PairingCrypto.deriveSessionKeys(ecdh, mobileNonce, deviceNonce, transcriptHash)
            assertEquals(v["mobile_tx_key_hex"], keys.mobileTxKey.toHex(), "mobile_tx mismatch in ${v["name"]}")
            assertEquals(v["mobile_rx_key_hex"], keys.mobileRxKey.toHex(), "mobile_rx mismatch in ${v["name"]}")
            assertEquals(v["session_id"], PairingCrypto.b64urlEncode(keys.sessionId), "session_id mismatch in ${v["name"]}")
        }
    }

    @Test
    fun `client_finished record decrypts and re-encrypts deterministically`() {
        for (v in vectors()) {
            val keys = deriveFor(v)
            val sessionIdB64 = v["session_id"]
            // AAD layout check (direction 0 = mobile->device, counter 0).
            val aad = PairingCrypto.recordAad(sessionIdB64, 0, 0)
            assertEquals(v["client_finished_aad"], aad.toString(Charsets.US_ASCII))
            val ct = PairingCrypto.b64urlDecode(v["client_finished_ciphertext"])
            val tag = PairingCrypto.b64urlDecode(v["client_finished_tag"])
            val plain = PairingCrypto.aesGcmOpen(
                keys.mobileTxKey,
                PairingCrypto.recordNonce(0, 0),
                aad,
                ct + tag,
            ).toString(Charsets.UTF_8)
            assertEquals(v["client_finished_plaintext"], plain, "decrypt mismatch in ${v["name"]}")
            assertEquals(
                "{\"action\":\"pairing_client_finished\"}",
                plain,
                "unexpected finished plaintext in ${v["name"]}",
            )
            // Deterministic re-encryption with the same nonce must reproduce the vector.
            val sealed = PairingCrypto.aesGcmSeal(
                keys.mobileTxKey,
                PairingCrypto.recordNonce(0, 0),
                aad,
                plain.toByteArray(Charsets.UTF_8),
            )
            val (ct2, tag2) = PairingCrypto.splitSealed(sealed)
            assertEquals(v["client_finished_ciphertext"], PairingCrypto.b64urlEncode(ct2))
            assertEquals(v["client_finished_tag"], PairingCrypto.b64urlEncode(tag2))
        }
    }

    private fun deriveFor(v: Vec): PairingCrypto.SessionKeys {
        val ecdh = TestUtil.hexToBytes(v["ecdh_secret_hex"])
        return PairingCrypto.deriveSessionKeys(
            ecdh,
            PairingCrypto.b64urlDecode(v["mobile_nonce"]),
            PairingCrypto.b64urlDecode(v["device_nonce"]),
            PairingCrypto.b64urlDecode(v["transcript_hash"]),
        )
    }

    @Test
    fun `b64url rejects what the firmware rejects`() {
        assertThrows<IllegalArgumentException> { PairingCrypto.b64urlDecode("") }
        assertThrows<IllegalArgumentException> { PairingCrypto.b64urlDecode("a") } // len % 4 == 1
        assertThrows<IllegalArgumentException> { PairingCrypto.b64urlDecode("ab*cd") }
        assertThrows<IllegalArgumentException> { PairingCrypto.b64urlDecode("x".repeat(4097)) }
        // round-trip stays unpadded
        val raw = ByteArray(32) { it.toByte() }
        val enc = PairingCrypto.b64urlEncode(raw)
        assertTrue('=' !in enc)
        assertTrue(PairingCrypto.b64urlDecode(enc).contentEquals(raw))
    }

    @Test
    fun `parseCounter rejects non-decimal and overflow`() {
        assertEquals(0L, PairingCrypto.parseCounter("0"))
        assertEquals(42L, PairingCrypto.parseCounter("42"))
        assertThrows<IllegalArgumentException> { PairingCrypto.parseCounter("12a") }
        assertThrows<IllegalArgumentException> { PairingCrypto.parseCounter("") }
        assertThrows<IllegalArgumentException> { PairingCrypto.parseCounter("18446744073709551616") } // 2^64
        // 2^64 - 1 is representable (bit pattern preserved)
        assertEquals(-1L, PairingCrypto.parseCounter("18446744073709551615"))
    }

    @Test
    fun `record nonce layout`() {
        val n = PairingCrypto.recordNonce(0, 0)
        assertEquals(12, n.size)
        assertEquals(0, n[0])
        assertTrue(n.copyOfRange(1, 12).all { it == 0.toByte() })
        val n2 = PairingCrypto.recordNonce(1, 1)
        assertEquals(1, n2[0])
        assertEquals(1, n2[11])
    }
}
