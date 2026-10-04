package com.muse.gadget.pairing

import com.muse.gadget.identity.Identity
import com.muse.gadget.util.Json
import com.muse.gadget.util.JsonValue
import com.muse.gadget.util.field
import com.muse.gadget.util.strField
import java.security.SecureRandom

/**
 * Device side of pairing v5, `confirm_app` policy (mirrors Python `PairingSession`).
 *
 * Thread-safe; methods advancing the handshake return a nonzero *generation*
 * token. Deferred work must check [isCurrent] before acting so abandoned
 * attempts cannot touch a newer session.
 *
 * Any decrypt/validation failure voids the whole session, like the firmware.
 */
class PairingSession(
    private val nodeId: String,
    private val deviceId: String,
    private val mac: String,
    firmwareVersion: String,
    private val sdkToken: String? = null,
    private val clock: () -> Long = { System.nanoTime() / 1_000_000 },
    private val generatePrivateScalar: () -> ByteArray = { ByteArray(32).also { SecureRandom().nextBytes(it) } },
    private val randomBytes: (Int) -> ByteArray = { n -> ByteArray(n).also { SecureRandom().nextBytes(it) } },
) {
    enum class State { IDLE, WAIT_CLIENT_FINISHED, READY, PROVISIONING }

    companion object {
        const val ERROR_INVALID_HELLO = "error_pairing_invalid_hello"
        const val ERROR_DECRYPT = "error_pairing_decrypt"
        const val CLIENT_FINISHED_ACTION = "pairing_client_finished"
        const val DIR_M2D = 0
        const val DIR_D2M = 1
    }

    private val firmwareVersion: String = firmwareVersion.ifEmpty { "unknown" }
    private val lock = Any()
    private var generation = 0L

    private var state = State.IDLE
    private var deadlineMs = 0L
    private var rxKey: ByteArray? = null
    private var txKey: ByteArray? = null
    private var sessionIdB64 = ""
    private var rxCounter = 0L
    private var txCounter = 0L

    val currentState: State
        get() = synchronized(lock) {
            expireLocked()
            state
        }

    val confirmed: Boolean
        get() {
            val s = currentState
            return s == State.READY || s == State.PROVISIONING
        }

    fun isCurrent(gen: Long): Boolean = synchronized(lock) {
        gen != 0L && gen == generation
    }

    fun reset() = synchronized(lock) { resetLocked() }

    /** Pairing fields for the `get_device_info` response. */
    fun deviceInfoJson(): String = synchronized(lock) {
        Json.stringify(
            Json.obj(
                "device_id" to Json.str(deviceId),
                "mac" to Json.str(mac),
                "model" to Json.str(Identity.PAIRING_MODEL),
                "pairing_protocol" to Json.num(Identity.PAIRING_VERSION),
                "pairing_auth" to Json.str(Identity.PAIRING_AUTH_COMMUNITY),
                "pairing_auth_epoch" to Json.num(0),
                "pairing_policy" to Json.str(Identity.PAIRING_POLICY_APP),
            ),
        )
    }

    /**
     * Starts a session from `pairing_client_hello`; returns the `pairing_ready`
     * JSON. Throws [PairingException] with `error_pairing_invalid_hello`.
     */
    fun handleHello(helloJson: String): String {
        val hello = try {
            Json.parseObj(helloJson)
        } catch (e: Exception) {
            throw PairingException(ERROR_INVALID_HELLO, e)
        }
        val version = hello.field("version")
        val versionOk = when (version) {
            is JsonValue.Num -> version.raw == "5" || version.raw == "5.0"
            else -> false
        }
        if (!versionOk ||
            hello.strField("pairing_auth") != Identity.PAIRING_AUTH_COMMUNITY ||
            hello.strField("pairing_policy") != Identity.PAIRING_POLICY_APP
        ) {
            throw PairingException(ERROR_INVALID_HELLO)
        }
        synchronized(lock) {
            resetLocked()
            val mobilePub: ByteArray
            val mobileNonce: ByteArray
            try {
                mobilePub = PairingCrypto.b64urlDecode(hello.strField("mobile_pub") ?: "")
                mobileNonce = PairingCrypto.b64urlDecode(hello.strField("mobile_nonce") ?: "")
                require(mobilePub.size == 65 && mobilePub[0] == 0x04.toByte())
                require(mobileNonce.size == 16)
            } catch (e: Exception) {
                resetLocked()
                throw PairingException(ERROR_INVALID_HELLO, e)
            }

            val deviceScalar = generatePrivateScalar()
            require(deviceScalar.size == 32) { "key generator must return 32 bytes" }
            val devicePub = PairingCrypto.publicPoint65(deviceScalar)
            val deviceNonce = randomBytes(16)
            val transcript = PairingCrypto.buildTranscript(
                community = true,
                authEpoch = 0,
                policy = Identity.PAIRING_POLICY_APP,
                deviceId = deviceId,
                nodeId = nodeId,
                mac = mac,
                firmwareVersion = firmwareVersion,
                mobilePub = PairingCrypto.b64urlEncode(mobilePub),
                devicePub = PairingCrypto.b64urlEncode(devicePub),
                mobileNonce = PairingCrypto.b64urlEncode(mobileNonce),
                deviceNonce = PairingCrypto.b64urlEncode(deviceNonce),
            )
            val transcriptHash = PairingCrypto.sha256(transcript.toByteArray())
            val ecdh = PairingCrypto.ecdhX(deviceScalar, mobilePub)
            val keys = PairingCrypto.deriveSessionKeys(ecdh, mobileNonce, deviceNonce, transcriptHash)

            rxKey = keys.mobileTxKey
            txKey = keys.mobileRxKey
            sessionIdB64 = PairingCrypto.b64urlEncode(keys.sessionId)
            rxCounter = 0
            txCounter = 0
            state = State.WAIT_CLIENT_FINISHED
            deadlineMs = clock() + Identity.CLIENT_FINISHED_TIMEOUT_S * 1000
            return Json.stringify(
                Json.obj(
                    "type" to Json.str("pairing_ready"),
                    "version" to Json.num(Identity.PAIRING_VERSION),
                    "device_id" to Json.str(deviceId),
                    "node_id" to Json.str(nodeId),
                    "mac" to Json.str(mac),
                    "model" to Json.str(Identity.PAIRING_MODEL),
                    "firmware_version" to Json.str(firmwareVersion),
                    "pairing_auth" to Json.str(Identity.PAIRING_AUTH_COMMUNITY),
                    "pairing_auth_epoch" to Json.num(0),
                    "pairing_policy" to Json.str(Identity.PAIRING_POLICY_APP),
                    "device_pub" to Json.str(PairingCrypto.b64urlEncode(devicePub)),
                    "device_nonce" to Json.str(PairingCrypto.b64urlEncode(deviceNonce)),
                    "transcript_hash" to Json.str(PairingCrypto.b64urlEncode(transcriptHash)),
                    "session_id" to Json.str(sessionIdB64),
                ),
            )
        }
    }

    /**
     * Opens one mobile->device `pairing_encrypted` record. Any failure
     * (wrong session, skipped/replayed counter, bad tag, expiry) voids the
     * session. Returns the plaintext.
     */
    fun decryptEnvelope(envelopeJson: String): String {
        synchronized(lock) {
            if (expireLocked() || state == State.IDLE) {
                resetLocked()
                throw PairingException(ERROR_DECRYPT)
            }
            val rx = rxKey ?: run {
                resetLocked()
                throw PairingException(ERROR_DECRYPT)
            }
            try {
                val env = Json.parseObj(envelopeJson)
                if (env.strField("session_id") != sessionIdB64) throw IllegalArgumentException("wrong session")
                val counter = PairingCrypto.parseCounter(env.strField("counter") ?: "")
                if (counter != rxCounter) throw IllegalArgumentException("unexpected counter")
                val ciphertext = PairingCrypto.b64urlDecode(
                    env.strField("ciphertext") ?: "", PairingCrypto.MAX_CIPHERTEXT_B64_CHARS,
                )
                val tag = PairingCrypto.b64urlDecode(env.strField("tag") ?: "")
                require(tag.size == 16) { "invalid tag length" }
                val nonce = PairingCrypto.recordNonce(DIR_M2D, counter)
                val aad = PairingCrypto.recordAad(sessionIdB64, DIR_M2D, counter)
                val plain = PairingCrypto.aesGcmOpen(rx, nonce, aad, ciphertext + tag)
                    .toString(Charsets.UTF_8)
                rxCounter++
                return plain
            } catch (e: PairingException) {
                resetLocked()
                throw e
            } catch (e: Exception) {
                resetLocked()
                throw PairingException(ERROR_DECRYPT, e)
            }
        }
    }

    /**
     * Confirms the session after the first decrypted record. The command must
     * be exactly `{"action":"pairing_client_finished"}` and must have been the
     * first record. Returns the new generation, or 0 after voiding the session.
     */
    fun handleClientFinished(commandJson: String): Long {
        synchronized(lock) {
            val ok = try {
                val cmd = Json.parseObj(commandJson)
                cmd.fields.size == 1 && cmd.strField("action") == CLIENT_FINISHED_ACTION &&
                    !expireLocked() &&
                    state == State.WAIT_CLIENT_FINISHED &&
                    rxCounter == 1L
            } catch (e: Exception) {
                false
            }
            if (!ok) {
                resetLocked()
                return 0
            }
            advanceGenerationLocked()
            state = State.READY
            deadlineMs = clock() + Identity.CONFIRMED_TIMEOUT_S * 1000
            return generation
        }
    }

    fun markProvisioning(): Long = synchronized(lock) {
        if (!expireLocked() && state == State.READY) {
            advanceGenerationLocked()
            state = State.PROVISIONING
            deadlineMs = clock() + Identity.PROVISIONING_TIMEOUT_S * 1000
        }
        if (state == State.PROVISIONING) generation else 0
    }

    fun extendProvisioning(gen: Long): Boolean = synchronized(lock) {
        val valid = provisioningLocked(gen)
        if (valid) deadlineMs = clock() + Identity.PROVISIONING_TIMEOUT_S * 1000
        valid
    }

    /** Runs [commit] under the session if it is the current provisioning session. */
    fun commitProvisioning(gen: Long, commit: () -> Boolean): Boolean = synchronized(lock) {
        provisioningLocked(gen) && commit()
    }

    /**
     * Seals a device->mobile record; returns the envelope JSON, or null when
     * there is no active session / the generation is stale.
     */
    fun encryptJson(plaintext: String, gen: Long = 0): String? {
        synchronized(lock) {
            if ((gen != 0L && gen != generation) || expireLocked() || state == State.IDLE) return null
            val tx = txKey ?: return null
            val counter = txCounter
            val sealed = PairingCrypto.aesGcmSeal(
                tx,
                PairingCrypto.recordNonce(DIR_D2M, counter),
                PairingCrypto.recordAad(sessionIdB64, DIR_D2M, counter),
                plaintext.toByteArray(Charsets.UTF_8),
            )
            txCounter++
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
    }

    fun encryptStatus(status: String, gen: Long = 0): String? {
        val fields = LinkedHashMap<String, JsonValue>()
        fields["type"] = Json.str("status")
        fields["status"] = Json.str(status)
        if (sdkToken != null && status == "pairing_confirmed") {
            fields["sdk_token"] = Json.str(sdkToken)
        }
        return encryptJson(Json.stringify(JsonValue.Obj(fields)), gen)
    }

    // -- internals ------------------------------------------------------------

    private fun provisioningLocked(gen: Long): Boolean =
        gen != 0L && gen == generation && !expireLocked() && state == State.PROVISIONING

    private fun advanceGenerationLocked() {
        generation++
    }

    private fun resetLocked() {
        advanceGenerationLocked()
        clearLocked()
    }

    private fun clearLocked() {
        state = State.IDLE
        deadlineMs = 0
        rxKey = null
        txKey = null
        sessionIdB64 = ""
        rxCounter = 0
        txCounter = 0
    }

    /** Returns true if the session expired (keys dropped, generation kept). */
    private fun expireLocked(): Boolean {
        if (state == State.IDLE || clock() <= deadlineMs) return false
        clearLocked()
        return true
    }
}
