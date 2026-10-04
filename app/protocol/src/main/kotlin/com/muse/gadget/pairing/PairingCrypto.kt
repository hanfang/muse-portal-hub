package com.muse.gadget.pairing

import com.muse.gadget.identity.Identity
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Pairing failure; [status] is the wire error string to report. */
class PairingException(val status: String, cause: Throwable? = null) :
    RuntimeException(status, cause)

/** Pure crypto for pairing v5 (P-256 ECDH -> transcript -> HKDF -> AES-256-GCM). */
object PairingCrypto {
    const val MAX_B64_CHARS = 4096
    const val MAX_CIPHERTEXT_B64_CHARS = 16384
    private val B64URL_RE = Regex("[A-Za-z0-9_-]+")
    private const val TAG_BYTES = 16

    // -- base64url ------------------------------------------------------------

    fun b64urlEncode(data: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(data)

    /**
     * Strict decode mirroring the firmware: unpadded base64url, charset
     * [A-Za-z0-9_-], length in (0, maxChars], length % 4 != 1.
     */
    fun b64urlDecode(text: String, maxChars: Int = MAX_B64_CHARS): ByteArray {
        require(text.isNotEmpty() && text.length <= maxChars) { "invalid base64url length" }
        require(text.length % 4 != 1 && B64URL_RE.matches(text)) { "invalid base64url" }
        val padded = text + "=".repeat((4 - text.length % 4) % 4)
        return Base64.getUrlDecoder().decode(padded)
    }

    /** Decimal counter string; rejects anything but [0-9]+ and values >= 2^64. */
    fun parseCounter(text: String): Long {
        require(text.isNotEmpty() && text.all { it in '0'..'9' }) { "invalid counter" }
        val big = BigInteger(text)
        require(big < BigInteger.ONE.shiftLeft(64)) { "counter overflow" }
        return big.toLong() // two's complement bit pattern preserved
    }

    // -- transcript -----------------------------------------------------------

    /**
     * Canonical v5 transcript; SHA-256 of it is the `transcript_hash`.
     * Line order and spelling must match the firmware byte-for-byte.
     */
    fun buildTranscript(
        community: Boolean,
        authEpoch: Int,
        policy: String,
        deviceId: String,
        nodeId: String,
        mac: String,
        firmwareVersion: String,
        mobilePub: String,
        devicePub: String,
        mobileNonce: String,
        deviceNonce: String,
    ): String {
        val button = policy == Identity.PAIRING_POLICY_BUTTON
        require(button || (community && policy == Identity.PAIRING_POLICY_APP)) {
            "unsupported pairing policy: $policy"
        }
        require(if (community) authEpoch == 0 else authEpoch > 0) {
            "invalid auth epoch: $authEpoch"
        }
        require(
            listOf(
                deviceId, nodeId, mac, firmwareVersion,
                mobilePub, devicePub, mobileNonce, deviceNonce,
            ).all { it.isNotEmpty() },
        ) { "transcript fields must be non-empty" }
        return listOf(
            Identity.TRANSCRIPT_FIRST_LINE,
            "version=${Identity.PAIRING_VERSION}",
            "initiator_role=mobile",
            "responder_role=link",
            "device_id=$deviceId",
            "node_id=$nodeId",
            "mac=$mac",
            "model=${Identity.PAIRING_MODEL}",
            "firmware_version=$firmwareVersion",
            "selected_cipher_suite=${Identity.PAIRING_SUITE}",
            "pairing_auth=${if (community) Identity.PAIRING_AUTH_COMMUNITY else Identity.PAIRING_AUTH_OFFICIAL}",
            "pairing_auth_epoch=$authEpoch",
            "pairing_policy=$policy",
            "confirm_timeout_seconds=${if (button) Identity.BUTTON_CONFIRM_TIMEOUT_S else 0}",
            "mobile_pub=$mobilePub",
            "device_pub=$devicePub",
            "mobile_nonce=$mobileNonce",
            "device_nonce=$deviceNonce",
        ).joinToString("\n")
    }

    fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    // -- ECDH -----------------------------------------------------------------

    private fun ecParams(): ECParameterSpec {
        val ap = AlgorithmParameters.getInstance("EC")
        ap.init(ECGenParameterSpec("secp256r1"))
        return ap.getParameterSpec(ECParameterSpec::class.java)
    }

    /**
     * P-256 ECDH; returns the 32-byte x coordinate (left-padded).
     * [peerPub] must be the 65-byte uncompressed point 0x04||x||y.
     */
    fun ecdhX(privateScalar32: ByteArray, peerPub: ByteArray): ByteArray {
        require(privateScalar32.size == 32) { "private scalar must be 32 bytes" }
        require(peerPub.size == 65 && peerPub[0] == 0x04.toByte()) { "invalid peer public key" }
        val params = ecParams()
        val kf = KeyFactory.getInstance("EC")
        val priv = kf.generatePrivate(
            ECPrivateKeySpec(BigInteger(1, privateScalar32), params),
        )
        val x = BigInteger(1, peerPub.copyOfRange(1, 33))
        val y = BigInteger(1, peerPub.copyOfRange(33, 65))
        val pub = kf.generatePublic(ECPublicKeySpec(ECPoint(x, y), params))
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(priv)
        ka.doPhase(pub, true)
        return leftPad32(ka.generateSecret())
    }

    /** 65-byte uncompressed P-256 point for a private scalar (used by tests). */
    fun publicPoint65(privateScalar32: ByteArray): ByteArray {
        require(privateScalar32.size == 32)
        val k = BigInteger(1, privateScalar32)
        require(k > BigInteger.ZERO && k < P256_N) { "scalar out of range" }
        val (x, y) = p256Multiply(k)
        val out = ByteArray(65)
        out[0] = 0x04
        copyPadded(x.toByteArray(), out, 1)
        copyPadded(y.toByteArray(), out, 33)
        return out
    }

    // -- secp256r1 scalar multiplication (dependency-free) ----------------------
    // Fixed curve params; double-and-add in affine coordinates. Verified
    // against the official pairing test vectors.

    private val P256_P = BigInteger(
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16,
    )
    private val P256_A = P256_P - BigInteger("3")
    private val P256_GX = BigInteger(
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16,
    )
    private val P256_GY = BigInteger(
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16,
    )
    private val P256_N = BigInteger(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3BFC0658CC51ECF", 16,
    )

    private data class Pt(val x: BigInteger, val y: BigInteger)

    private fun p256Double(p: Pt): Pt {
        val s = ((BigInteger("3") * p.x * p.x + P256_A).mod(P256_P) *
            ((BigInteger("2") * p.y).mod(P256_P)).modInverse(P256_P)).mod(P256_P)
        val x = (s * s - BigInteger("2") * p.x).mod(P256_P)
        val y = (s * (p.x - x) - p.y).mod(P256_P)
        return Pt(x, y)
    }

    private fun p256Add(p: Pt, q: Pt): Pt? {
        if (p.x == q.x) {
            if (p.y != q.y) return null // P + (-P) = infinity
            return p256Double(p)
        }
        val dx = (q.x - p.x).mod(P256_P)
        val s = ((q.y - p.y).mod(P256_P) * dx.modInverse(P256_P)).mod(P256_P)
        val x = (s * s - p.x - q.x).mod(P256_P)
        val y = (s * (p.x - x) - p.y).mod(P256_P)
        return Pt(x, y)
    }

    private fun p256Multiply(k: BigInteger): Pt {
        var r: Pt? = null
        var base = Pt(P256_GX, P256_GY)
        var kk = k
        while (kk > BigInteger.ZERO) {
            if (kk.testBit(0)) r = if (r == null) base else p256Add(r, base)!!
            base = p256Double(base)
            kk = kk.shiftRight(1)
        }
        return r ?: error("scalar multiplication by zero")
    }

    private fun copyPadded(src: ByteArray, dst: ByteArray, dstOff: Int) {
        // BigInteger.toByteArray may add a leading zero sign byte; keep last 32.
        val s = if (src.size > 32) src.copyOfRange(src.size - 32, src.size) else src
        s.copyInto(dst, dstOff + 32 - s.size)
    }

    private fun leftPad32(secret: ByteArray): ByteArray {
        if (secret.size == 32) return secret
        require(secret.size < 32) { "ECDH secret too long" }
        return ByteArray(32 - secret.size) + secret
    }

    // -- key schedule ----------------------------------------------------------

    data class SessionKeys(
        /** Decrypts mobile->device records. */
        val mobileTxKey: ByteArray,
        /** Encrypts device->mobile records. */
        val mobileRxKey: ByteArray,
        val sessionId: ByteArray,
    )

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** RFC 5869 HKDF-SHA256 extract+expand. */
    fun hkdf(salt: ByteArray, ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hmacSha256(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
        return hkdfExpand(prk, info, length)
    }

    fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * 32)
        val out = ByteArray(length)
        var t = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < length) {
            t = hmacSha256(prk, t + info + byteArrayOf(counter.toByte()))
            val n = minOf(t.size, length - pos)
            t.copyInto(out, pos, 0, n)
            pos += n
            counter++
        }
        return out
    }

    fun deriveSessionKeys(
        ecdhSecret: ByteArray,
        mobileNonce: ByteArray,
        deviceNonce: ByteArray,
        transcriptHash: ByteArray,
    ): SessionKeys {
        val salt = sha256(mobileNonce + deviceNonce + transcriptHash)
        val sessionSecret = hkdf(salt, ecdhSecret, Identity.RECORD_LABEL.toByteArray(), 32)
        val mobileTx = hkdfExpand(sessionSecret, "mobile->device".toByteArray(), 32)
        val mobileRx = hkdfExpand(sessionSecret, "device->mobile".toByteArray(), 32)
        val sessionId = sha256(
            Identity.SESSION_ID_LABEL.toByteArray() + transcriptHash + ecdhSecret,
        ).copyOf(16)
        return SessionKeys(mobileTx, mobileRx, sessionId)
    }

    // -- encrypted records ------------------------------------------------------

    /**
     * Nonce layout: [direction] || 00 00 00 || counter_be64.
     * direction: 0 = mobile->device, 1 = device->mobile.
     */
    fun recordNonce(direction: Int, counter: Long): ByteArray {
        require(direction == 0 || direction == 1)
        val out = ByteArray(12)
        out[0] = direction.toByte()
        for (i in 0 until 8) out[4 + i] = (counter ushr (56 - 8 * i)).toByte()
        return out
    }

    fun recordAad(sessionIdB64: String, direction: Int, counter: Long): ByteArray {
        val arrow = if (direction == 0) "m2d" else "d2m"
        val counterDec = java.lang.Long.toUnsignedString(counter)
        return "${Identity.RECORD_LABEL}|$sessionIdB64|$arrow|$counterDec"
            .toByteArray(Charsets.US_ASCII)
    }

    /** Returns ciphertext||tag (16-byte tag appended), like Python's AESGCM. */
    fun aesGcmSeal(
        key: ByteArray,
        nonce12: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce12))
        c.updateAAD(aad)
        return c.doFinal(plaintext)
    }

    /** Inverse of [aesGcmSeal]; throws [PairingException] on tag failure. */
    fun aesGcmOpen(
        key: ByteArray,
        nonce12: ByteArray,
        aad: ByteArray,
        sealed: ByteArray,
    ): ByteArray {
        try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce12))
            c.updateAAD(aad)
            return c.doFinal(sealed)
        } catch (e: Exception) {
            throw PairingException("error_pairing_decrypt", e)
        }
    }

    fun splitSealed(sealed: ByteArray): Pair<ByteArray, ByteArray> {
        require(sealed.size >= TAG_BYTES)
        return sealed.copyOf(sealed.size - TAG_BYTES) to sealed.copyOfRange(sealed.size - TAG_BYTES, sealed.size)
    }
}
