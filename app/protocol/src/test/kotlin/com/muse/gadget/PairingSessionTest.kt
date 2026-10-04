package com.muse.gadget

import com.muse.gadget.identity.Identity
import com.muse.gadget.pairing.PairingCrypto
import com.muse.gadget.pairing.PairingException
import com.muse.gadget.pairing.PairingSession
import com.muse.gadget.util.Json
import com.muse.gadget.util.field
import com.muse.gadget.util.strField
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * Pairing state machine tests with a fake clock and fixed keys
 * (mirrors `tests/test_pairing.py`, confirm_app path).
 */
class PairingSessionTest {
    // Fixed test key material: mobile scalar 1, device scalar 2, counter nonces.
    private val mobileScalar = ByteArray(32).also { it[31] = 1 }
    private val deviceScalar = ByteArray(32).also { it[31] = 2 }
    private val mobileNonce = ByteArray(16) { it.toByte() }
    private var nowMs = 1_000_000L

    private fun session(sdkToken: String? = null) = PairingSession(
        nodeId = "homelink-000001",
        deviceId = "hatch-link:02:00:00:00:00:01",
        mac = "02:00:00:00:00:01",
        firmwareVersion = "1.0.0",
        sdkToken = sdkToken,
        clock = { nowMs },
        generatePrivateScalar = { deviceScalar.copyOf() },
        randomBytes = { n -> ByteArray(n) { (it + 16).toByte() } },
    )

    private fun helloJson(): String {
        val mobilePub = PairingCrypto.b64urlEncode(PairingCrypto.publicPoint65(mobileScalar))
        return Json.stringify(
            Json.obj(
                "action" to Json.str("pairing_client_hello"),
                "version" to Json.num(5),
                "pairing_auth" to Json.str("none"),
                "pairing_policy" to Json.str("confirm_app"),
                "mobile_pub" to Json.str(mobilePub),
                "mobile_nonce" to Json.str(PairingCrypto.b64urlEncode(mobileNonce)),
            ),
        )
    }

    /** Mobile side: derive the session keys (mirrors the device's pairing flow). */
    private fun mobileKeys(): PairingCrypto.SessionKeys {
        val ecdh = PairingCrypto.ecdhX(mobileScalar, PairingCrypto.publicPoint65(deviceScalar))
        val deviceNonce = ByteArray(16) { (it + 16).toByte() }
        val transcript = PairingCrypto.buildTranscript(
            community = true, authEpoch = 0, policy = Identity.PAIRING_POLICY_APP,
            deviceId = "hatch-link:02:00:00:00:00:01", nodeId = "homelink-000001",
            mac = "02:00:00:00:00:01", firmwareVersion = "1.0.0",
            mobilePub = PairingCrypto.b64urlEncode(PairingCrypto.publicPoint65(mobileScalar)),
            devicePub = PairingCrypto.b64urlEncode(PairingCrypto.publicPoint65(deviceScalar)),
            mobileNonce = PairingCrypto.b64urlEncode(mobileNonce),
            deviceNonce = PairingCrypto.b64urlEncode(deviceNonce),
        )
        return PairingCrypto.deriveSessionKeys(
            ecdh, mobileNonce, deviceNonce,
            PairingCrypto.sha256(transcript.toByteArray()),
        )
    }

    /**
     * Mobile side: open a device->mobile envelope (mirrors Python
     * `mobile.open(...)`); returns the decrypted plaintext JSON object.
     */
    private fun mobileOpen(envelopeJson: String, sessionIdB64: String): com.muse.gadget.util.JsonValue.Obj {
        val keys = mobileKeys()
        val env = Json.parseObj(envelopeJson)
        val counter = env.strField("counter")!!.toLong()
        val ct = PairingCrypto.b64urlDecode(env.strField("ciphertext")!!)
        val tag = PairingCrypto.b64urlDecode(env.strField("tag")!!)
        val plain = PairingCrypto.aesGcmOpen(
            keys.mobileRxKey,
            PairingCrypto.recordNonce(1, counter),
            PairingCrypto.recordAad(sessionIdB64, 1, counter),
            ct + tag,
        ).toString(Charsets.UTF_8)
        return Json.parseObj(plain)
    }

    /** Mobile side: seal a record with the m2d key at [counter]. */
    private fun mobileEncrypt(plaintext: String, counter: Long, sessionIdB64: String): String {
        val keys = mobileKeys()
        val sealed = PairingCrypto.aesGcmSeal(
            keys.mobileTxKey,
            PairingCrypto.recordNonce(0, counter),
            PairingCrypto.recordAad(sessionIdB64, 0, counter),
            plaintext.toByteArray(),
        )
        val (ct, tag) = PairingCrypto.splitSealed(sealed)
        return Json.stringify(
            Json.obj(
                "type" to Json.str("pairing_encrypted"),
                "session_id" to Json.str(sessionIdB64),
                "counter" to Json.str(counter.toString()),
                "ciphertext" to Json.str(PairingCrypto.b64urlEncode(ct)),
                "tag" to Json.str(PairingCrypto.b64urlEncode(tag)),
            ),
        )
    }

    private fun readySession(): Pair<PairingSession, String> {
        val s = session()
        val ready = Json.parseObj(s.handleHello(helloJson()))
        return s to ready.strField("session_id")!!
    }

    @Test
    fun `hello produces pairing_ready and device info is correct`() {
        val s = session()
        val ready = Json.parseObj(s.handleHello(helloJson()))
        assertEquals("pairing_ready", ready.strField("type"))
        assertEquals(5L, (ready.field("version") as com.muse.gadget.util.JsonValue.Num).raw.toLong())
        assertEquals("hatch-link:02:00:00:00:00:01", ready.strField("device_id"))
        assertEquals("confirm_app", ready.strField("pairing_policy"))
        assertEquals(PairingSession.State.WAIT_CLIENT_FINISHED, s.currentState)
        val info = Json.parseObj(s.deviceInfoJson())
        assertEquals("hatch_link", info.strField("model"))
        assertEquals("none", info.strField("pairing_auth"))
    }

    @Test
    fun `hello rejects invalid input`() {
        val s = session()
        // bad version
        assertThrows<PairingException> {
            s.handleHello(helloJson().replace("\"version\":5", "\"version\":4"))
        }
        // bad auth
        assertThrows<PairingException> {
            s.handleHello(helloJson().replace("\"pairing_auth\":\"none\"", "\"pairing_auth\":\"x\""))
        }
        // bad policy
        assertThrows<PairingException> {
            s.handleHello(helloJson().replace("confirm_app", "confirm_press"))
        }
        // truncated pubkey
        assertThrows<PairingException> {
            s.handleHello("{\"action\":\"pairing_client_hello\",\"version\":5,\"pairing_auth\":\"none\"," +
                "\"pairing_policy\":\"confirm_app\",\"mobile_pub\":\"AA\",\"mobile_nonce\":\"AAECAwQFBgcICQoLDA0ODw\"}")
        }
        assertEquals(PairingSession.State.IDLE, s.currentState)
    }

    @Test
    fun `full confirm_app handshake`() {
        val (s, sessionId) = readySession()
        val env = mobileEncrypt("{\"action\":\"pairing_client_finished\"}", 0, sessionId)
        assertEquals("{\"action\":\"pairing_client_finished\"}", s.decryptEnvelope(env))
        val gen = s.handleClientFinished("{\"action\":\"pairing_client_finished\"}")
        assertTrue(gen != 0L)
        assertTrue(s.isCurrent(gen))
        assertEquals(PairingSession.State.READY, s.currentState)
        assertTrue(s.confirmed)
        // device counters start at zero
        val e1 = Json.parseObj(s.encryptJson("{\"hello\":1}", gen)!!)
        val e2 = Json.parseObj(s.encryptJson("{\"hello\":2}", gen)!!)
        assertEquals("0", e1.strField("counter"))
        assertEquals("1", e2.strField("counter"))
    }

    @Test
    fun `client_finished must be exactly the expected object`() {
        val (s, sessionId) = readySession()
        val env = mobileEncrypt("{\"action\":\"pairing_client_finished\",\"extra\":1}", 0, sessionId)
        assertEquals("{\"action\":\"pairing_client_finished\",\"extra\":1}", s.decryptEnvelope(env))
        assertEquals(0, s.handleClientFinished("{\"action\":\"pairing_client_finished\",\"extra\":1}"))
        assertEquals(PairingSession.State.IDLE, s.currentState)
    }

    @Test
    fun `client_finished only counts as the first record`() {
        val (s, sessionId) = readySession()
        s.decryptEnvelope(mobileEncrypt("{\"action\":\"noop\"}", 0, sessionId))
        s.decryptEnvelope(mobileEncrypt("{\"action\":\"pairing_client_finished\"}", 1, sessionId))
        assertEquals(0, s.handleClientFinished("{\"action\":\"pairing_client_finished\"}"))
        assertEquals(PairingSession.State.IDLE, s.currentState)
    }

    @Test
    fun `replayed record clears the session`() {
        val (s, sessionId) = readySession()
        val env = mobileEncrypt("{\"action\":\"pairing_client_finished\"}", 0, sessionId)
        s.decryptEnvelope(env)
        assertThrows<PairingException> { s.decryptEnvelope(env) }
        assertEquals(PairingSession.State.IDLE, s.currentState)
    }

    @Test
    fun `skipped counter clears the session`() {
        val (s, sessionId) = readySession()
        val env = mobileEncrypt("{\"action\":\"pairing_client_finished\"}", 1, sessionId)
        val ex = assertThrows<PairingException> { s.decryptEnvelope(env) }
        assertEquals(PairingSession.ERROR_DECRYPT, ex.status)
        assertEquals(PairingSession.State.IDLE, s.currentState)
    }

    @Test
    fun `tampered ciphertext clears the session`() {
        val (s, sessionId) = readySession()
        val env = Json.parseObj(mobileEncrypt("{\"action\":\"pairing_client_finished\"}", 0, sessionId))
        val ct = PairingCrypto.b64urlDecode(env.strField("ciphertext")!!)
        ct[0] = (ct[0].toInt() xor 0xFF).toByte()
        val tampered = Json.stringify(
            Json.obj(
                "type" to Json.str("pairing_encrypted"),
                "session_id" to Json.str(sessionId),
                "counter" to Json.str("0"),
                "ciphertext" to Json.str(PairingCrypto.b64urlEncode(ct)),
                "tag" to Json.str(env.strField("tag")!!),
            ),
        )
        assertThrows<PairingException> { s.decryptEnvelope(tampered) }
        assertEquals(PairingSession.State.IDLE, s.currentState)
    }

    @Test
    fun `wrong session id clears the session`() {
        val (s, sessionId) = readySession()
        val env = mobileEncrypt("{\"action\":\"pairing_client_finished\"}", 0, sessionId)
            .replace(sessionId, "AAAAAAAAAAAAAAAAAAAAAA")
        assertThrows<PairingException> { s.decryptEnvelope(env) }
        assertEquals(PairingSession.State.IDLE, s.currentState)
    }

    @Test
    fun `decrypt without session fails`() {
        val s = session()
        assertThrows<PairingException> {
            s.decryptEnvelope("{\"type\":\"pairing_encrypted\",\"session_id\":\"x\",\"counter\":\"0\",\"ciphertext\":\"AA\",\"tag\":\"AAAAAAAAAAAAAAAAAAAAAA\"}")
        }
    }

    @Test
    fun `client_finished times out after 60 seconds`() {
        val (s, _) = readySession()
        nowMs += 61_000
        // expiry is observed on next access
        assertEquals(PairingSession.State.IDLE, s.currentState)
    }

    @Test
    fun `confirmed session expires after 120 seconds`() {
        val (s, sessionId) = readySession()
        s.decryptEnvelope(mobileEncrypt("{\"action\":\"pairing_client_finished\"}", 0, sessionId))
        val gen = s.handleClientFinished("{\"action\":\"pairing_client_finished\"}")
        assertTrue(gen != 0L)
        nowMs += 121_000
        assertEquals(PairingSession.State.IDLE, s.currentState)
        // NB: matches the Python reference test — expiry clears the session
        // state but the generation counter is unchanged, so isCurrent stays true.
        assertTrue(s.isCurrent(gen))
        assertNull(s.encryptJson("{}", gen))
    }

    @Test
    fun `provisioning flow with generation checks`() {
        val (s, sessionId) = readySession()
        s.decryptEnvelope(mobileEncrypt("{\"action\":\"pairing_client_finished\"}", 0, sessionId))
        val genReady = s.handleClientFinished("{\"action\":\"pairing_client_finished\"}")
        val genProv = s.markProvisioning()
        assertTrue(genProv != 0L && genProv != genReady)
        assertEquals(PairingSession.State.PROVISIONING, s.currentState)
        // stale generation cannot commit
        assertFalse(s.commitProvisioning(genReady) { true })
        var committed = false
        assertTrue(s.commitProvisioning(genProv) { committed = true; true })
        assertTrue(committed)
        // extend keeps it alive past the original deadline
        nowMs += 119_000
        assertTrue(s.extendProvisioning(genProv))
        nowMs += 119_000
        assertEquals(PairingSession.State.PROVISIONING, s.currentState)
        nowMs += 2_000
        assertEquals(PairingSession.State.IDLE, s.currentState)
    }

    @Test
    fun `pairing_confirmed carries the sdk token`() {
        val (s, sessionId) = readySession()
        s.decryptEnvelope(mobileEncrypt("{\"action\":\"pairing_client_finished\"}", 0, sessionId))
        val gen = s.handleClientFinished("{\"action\":\"pairing_client_finished\"}")
        // session() was built without sdk token -> absent
        val st = mobileOpen(s.encryptStatus("pairing_confirmed", gen)!!, sessionId)
        assertEquals("pairing_confirmed", st.strField("status"))
        assertNull(st.field("sdk_token"))

        val s2 = session("mgst_test")
        val ready2 = Json.parseObj(s2.handleHello(helloJson()))
        val sid2 = ready2.strField("session_id")!!
        s2.decryptEnvelope(mobileEncrypt("{\"action\":\"pairing_client_finished\"}", 0, sid2))
        val gen2 = s2.handleClientFinished("{\"action\":\"pairing_client_finished\"}")
        val st2 = mobileOpen(s2.encryptStatus("pairing_confirmed", gen2)!!, sid2)
        assertEquals("mgst_test", st2.strField("sdk_token"))
    }

    @Test
    fun `new hello replaces the previous session`() {
        val (s, sessionId) = readySession()
        s.decryptEnvelope(mobileEncrypt("{\"action\":\"pairing_client_finished\"}", 0, sessionId))
        val gen1 = s.handleClientFinished("{\"action\":\"pairing_client_finished\"}")
        assertTrue(gen1 != 0L)
        // a fresh hello resets everything; the old generation is stale
        s.handleHello(helloJson())
        assertFalse(s.isCurrent(gen1))
        assertEquals(PairingSession.State.WAIT_CLIENT_FINISHED, s.currentState)
        assertNull(s.encryptJson("{}", gen1))
    }

    @Test
    fun `stale generation cannot encrypt`() {
        val (s, sessionId) = readySession()
        s.decryptEnvelope(mobileEncrypt("{\"action\":\"pairing_client_finished\"}", 0, sessionId))
        val gen = s.handleClientFinished("{\"action\":\"pairing_client_finished\"}")
        assertNotNull(s.encryptJson("{}", gen))
        assertNull(s.encryptJson("{}", gen + 99))
    }
}
