package com.muse.gadget.noise

import com.muse.gadget.identity.Identity
import com.muse.gadget.pairing.PairingCrypto
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.NamedParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement

class NoiseProtocolException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

/**
 * `Noise_XX_25519_AESGCM_SHA256`, ported from `noise/noise_xx.py`.
 *
 * Transport keys use AES-256-GCM with nonce `00*4 || counter_be64` and empty
 * AAD; counters start at 0 and increment strictly. Any decrypt failure
 * poisons the CipherState (the whole transport is then dead).
 */
object NoiseParams {
    const val DH_LEN = 32
    const val TAG_LEN = 16
    const val MIN_MSG2_LEN = DH_LEN + (DH_LEN + TAG_LEN) + TAG_LEN // 96
    const val MIN_MSG3_LEN = DH_LEN + TAG_LEN + TAG_LEN // 64
    const val MAX_SAFE_NONCE = (1L shl 53) - 1

    /** Rejected low-order X25519 points (copied from the reference). */
    val X25519_LOW_ORDER_POINTS: List<ByteArray> = listOf(
        ByteArray(32),
        byteArrayOf(1) + ByteArray(31),
        hexToBytes("e0eb7a7c3b41b8ae1656e3faf19fc46ada098de b9c32b1fd866205165f49b800".replace(" ", "")),
        hexToBytes("5f9c95bca3508c24b1d0b1559c83ef5b04445c c4581c8e86d8224eddd09f1157".replace(" ", "")),
        hexToBytes("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hexToBytes("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    )

    private fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0)
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}

fun buildNoiseNonceIv(nonce: Long): ByteArray {
    if (nonce < 0) throw NoiseProtocolException("nonce outside uint64 range")
    // Long is signed; full u64 range handled via unsigned shifts.
    return ByteArray(12).also { out ->
        for (i in 0 until 8) out[4 + i] = (nonce ushr (56 - 8 * i)).toByte()
    }
}

/** X25519 helpers over JCA ("XDH"). Raw 32-byte keys convert via fixed DER prefixes. */
object X25519 {
    private val PRIV_DER_PREFIX = byteArrayOf(
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
        0x04, 0x22, 0x04, 0x20,
    ).map { it.toByte() }.toByteArray()
    private val PUB_DER_PREFIX = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
    ).map { it.toByte() }.toByteArray()

    fun generateKeypair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("XDH")
        kpg.initialize(NamedParameterSpec("X25519"))
        return kpg.generateKeyPair()
    }

    fun privateKeyFromRaw(seed32: ByteArray): PrivateKey {
        require(seed32.size == 32)
        return KeyFactory.getInstance("XDH")
            .generatePrivate(PKCS8EncodedKeySpec(PRIV_DER_PREFIX + seed32))
    }

    fun publicKeyFromRaw(raw32: ByteArray): PublicKey {
        require(raw32.size == 32)
        return KeyFactory.getInstance("XDH")
            .generatePublic(X509EncodedKeySpec(PUB_DER_PREFIX + raw32))
    }

    fun rawPublicKey(pub: PublicKey): ByteArray {
        val enc = pub.encoded
        check(enc.size == PUB_DER_PREFIX.size + 32 &&
            enc.copyOf(PUB_DER_PREFIX.size).contentEquals(PUB_DER_PREFIX)) {
            "unexpected X25519 public key encoding"
        }
        return enc.copyOfRange(PUB_DER_PREFIX.size, enc.size)
    }

    fun dh(privateKey: PrivateKey, peerPublicRaw32: ByteArray): ByteArray {
        require(peerPublicRaw32.size == NoiseParams.DH_LEN) { "invalid public key length" }
        for (lo in NoiseParams.X25519_LOW_ORDER_POINTS) {
            if (peerPublicRaw32.contentEquals(lo)) {
                throw NoiseProtocolException("x25519: rejected low-order public key")
            }
        }
        val ka = KeyAgreement.getInstance("XDH")
        ka.init(privateKey)
        ka.doPhase(publicKeyFromRaw(peerPublicRaw32), true)
        val shared = ka.generateSecret()
        if (shared.all { it == 0.toByte() }) {
            throw NoiseProtocolException("x25519: DH produced all-zeros output")
        }
        return shared
    }
}

/** Noise CipherState: keyed AES-GCM with a strictly increasing nonce. */
class CipherState {
    private var key: ByteArray? = null
    private var nonce: Long = 0
    private var poisoned = false
    private val lock = Any()

    private fun assertAlive() {
        if (poisoned) throw NoiseProtocolException("CipherState: poisoned after prior failure")
    }

    fun initializeKey(k: ByteArray) = synchronized(lock) {
        assertAlive()
        require(k.size == 32) { "CipherState: AES-GCM key must be 32 bytes" }
        key = k.copyOf()
        nonce = 0
    }

    fun hasKey(): Boolean = synchronized(lock) { key != null }

    fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): ByteArray = synchronized(lock) {
        assertAlive()
        val k = key ?: return plaintext.copyOf()
        if (nonce >= NoiseParams.MAX_SAFE_NONCE) {
            poisoned = true
            throw NoiseProtocolException("CipherState: nonce exhausted")
        }
        val n = nonce++
        try {
            PairingCrypto.aesGcmSeal(k, buildNoiseNonceIv(n), ad, plaintext)
        } catch (e: Exception) {
            poisoned = true
            throw NoiseProtocolException("CipherState: encrypt failed", e)
        }
    }

    fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): ByteArray = synchronized(lock) {
        assertAlive()
        val k = key ?: return ciphertext.copyOf()
        if (nonce >= NoiseParams.MAX_SAFE_NONCE) {
            poisoned = true
            throw NoiseProtocolException("CipherState: nonce exhausted")
        }
        val n = nonce++
        try {
            PairingCrypto.aesGcmOpen(k, buildNoiseNonceIv(n), ad, ciphertext)
        } catch (e: Exception) {
            poisoned = true
            throw NoiseProtocolException("CipherState: decrypt failed", e)
        }
    }
}

private class SymmetricState {
    private var ck = ByteArray(32)
    private var h = ByteArray(32)
    private var cipher = CipherState()

    fun initialize() {
        val padded = ByteArray(32)
        val name = Identity.NOISE_PROTOCOL_NAME.toByteArray()
        name.copyInto(padded, 0, 0, minOf(name.size, 32))
        h = padded
        ck = h.copyOf()
        mixHash(ByteArray(0))
    }

    fun mixHash(data: ByteArray) {
        h = PairingCrypto.sha256(h + data)
    }

    fun mixKey(ikm: ByteArray) {
        val (newCk, tempK) = noiseHkdf(ck, ikm, 2)
        ck = newCk
        cipher = CipherState()
        cipher.initializeKey(tempK)
    }

    fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val ct = cipher.encryptWithAd(h, plaintext)
        mixHash(ct)
        return ct
    }

    fun decryptAndHash(ciphertext: ByteArray): ByteArray {
        val pt = cipher.decryptWithAd(h, ciphertext)
        mixHash(ciphertext)
        return pt
    }

    /** Returns (c1, c2); initiator sends with c1, responder sends with c2. */
    fun split(): Pair<CipherState, CipherState> {
        val (t1, t2) = noiseHkdf(ck, ByteArray(0), 2)
        ck = ByteArray(32)
        h = ByteArray(32)
        val c1 = CipherState().also { it.initializeKey(t1) }
        val c2 = CipherState().also { it.initializeKey(t2) }
        return c1 to c2
    }

    fun handshakeHash(): ByteArray = h.copyOf()

    companion object {
        /** Noise HKDF: temp = HMAC(ck, ikm); out_i = HMAC(temp, out_{i-1} || i). */
        fun noiseHkdf(chainingKey: ByteArray, ikm: ByteArray, numOutputs: Int): List<ByteArray> {
            require(numOutputs in 2..3)
            val tempKey = PairingCrypto.hmacSha256(chainingKey, ikm)
            val outs = ArrayList<ByteArray>(numOutputs)
            var prev = ByteArray(0)
            for (i in 1..numOutputs) {
                prev = PairingCrypto.hmacSha256(tempKey, prev + byteArrayOf(i.toByte()))
                outs.add(prev)
            }
            return outs
        }
    }
}

/** Device side of the Noise XX handshake (initiator). */
class NoiseXXInitiator {
    private enum class Phase { CREATED, INITIALIZED, MSG1_SENT, MSG2_READ, MSG3_SENT, SPLIT, DEAD }

    private val ss = SymmetricState()
    private var e: KeyPair? = null
    private var s: KeyPair? = null
    private var re: ByteArray? = null
    private var rs: ByteArray? = null
    private var phase = Phase.CREATED
    private val ephKeyFactory: () -> KeyPair

    /** [ephKeyFactory] injectable for deterministic tests. */
    constructor(ephKeyFactory: () -> KeyPair = { X25519.generateKeypair() }) {
        this.ephKeyFactory = ephKeyFactory
    }

    private fun requirePhase(expected: Phase, method: String) {
        if (phase == Phase.DEAD) throw NoiseProtocolException("NoiseXX: $method called on dead handshake")
        if (phase != expected) throw NoiseProtocolException(
            "NoiseXX: $method called in wrong phase (expected $expected, got $phase)",
        )
    }

    private fun fail(e: Exception): Nothing {
        phase = Phase.DEAD
        throw e
    }

    fun initialize() {
        requirePhase(Phase.CREATED, "initialize")
        ss.initialize()
        phase = Phase.INITIALIZED
    }

    /** msg1: e_pub (32B). */
    fun writeMessage1(): ByteArray {
        requirePhase(Phase.INITIALIZED, "writeMessage1")
        return try {
            e = ephKeyFactory()
            val ePub = X25519.rawPublicKey(e!!.public)
            ss.mixHash(ePub)
            ss.encryptAndHash(ByteArray(0))
            phase = Phase.MSG1_SENT
            ePub
        } catch (e: Exception) {
            fail(e)
        }
    }

    /** msg2: e_pub_r(32) || enc(s_pub)(48) || enc(payload); returns the payload. */
    fun readMessage2(msg: ByteArray): ByteArray {
        requirePhase(Phase.MSG1_SENT, "readMessage2")
        if (msg.size < NoiseParams.MIN_MSG2_LEN) {
            fail(NoiseProtocolException("NoiseXX: message 2 too short (${msg.size} < ${NoiseParams.MIN_MSG2_LEN})"))
        }
        return try {
            var off = 0
            re = msg.copyOfRange(off, off + NoiseParams.DH_LEN).also { ss.mixHash(it) }
            off += NoiseParams.DH_LEN
            val eKp = e ?: throw NoiseProtocolException("NoiseXX: missing initiator ephemeral key")
            ss.mixKey(X25519.dh(eKp.private, re!!))
            rs = ss.decryptAndHash(msg.copyOfRange(off, off + NoiseParams.DH_LEN + NoiseParams.TAG_LEN))
            off += NoiseParams.DH_LEN + NoiseParams.TAG_LEN
            ss.mixKey(X25519.dh(eKp.private, rs!!))
            val payload = ss.decryptAndHash(msg.copyOfRange(off, msg.size))
            phase = Phase.MSG2_READ
            payload
        } catch (e: Exception) {
            fail(e)
        }
    }

    /** msg3: enc(s_pub)(48) || enc(b"")(16); payload is empty (bearer header authenticated us). */
    fun writeMessage3(): ByteArray {
        requirePhase(Phase.MSG2_READ, "writeMessage3")
        return try {
            s = ephKeyFactory()
            val encS = ss.encryptAndHash(X25519.rawPublicKey(s!!.public))
            val reKp = re ?: throw NoiseProtocolException("NoiseXX: missing responder ephemeral key")
            ss.mixKey(X25519.dh(s!!.private, reKp))
            val encPayload = ss.encryptAndHash(ByteArray(0))
            phase = Phase.MSG3_SENT
            encS + encPayload
        } catch (e: Exception) {
            fail(e)
        }
    }

    /** Returns (send, recv) cipher states for the initiator. */
    fun split(): Pair<CipherState, CipherState> {
        requirePhase(Phase.MSG3_SENT, "split")
        phase = Phase.SPLIT
        val (c1, c2) = ss.split()
        e = null; s = null; re = null; rs = null
        return c1 to c2
    }

    fun handshakeHash(): ByteArray = ss.handshakeHash()
}

/** Test responder for protocol verification (mirrors Python's NoiseXXResponder). */
class NoiseXXResponder(
    private val payload: ByteArray = ByteArray(0),
    ephKeyFactory: () -> KeyPair = { X25519.generateKeypair() },
) {
    private enum class Phase { CREATED, INITIALIZED, MSG2_SENT, MSG3_READ, SPLIT, DEAD }

    private val ss = SymmetricState()
    private var e: KeyPair? = null
    private var s: KeyPair? = null
    private var re: ByteArray? = null
    private var phase = Phase.CREATED
    private val ephKeyFactory: () -> KeyPair = ephKeyFactory

    private fun requirePhase(expected: Phase, method: String) {
        if (phase == Phase.DEAD) throw NoiseProtocolException("NoiseXX: $method called on dead handshake")
        if (phase != expected) throw NoiseProtocolException(
            "NoiseXX: $method called in wrong phase (expected $expected, got $phase)",
        )
    }

    private fun fail(e: Exception): Nothing {
        phase = Phase.DEAD
        throw e
    }

    fun initialize() {
        requirePhase(Phase.CREATED, "initialize")
        ss.initialize()
        phase = Phase.INITIALIZED
    }

    fun readMessage1AndWriteMessage2(msg1: ByteArray): ByteArray {
        requirePhase(Phase.INITIALIZED, "readMessage1AndWriteMessage2")
        if (msg1.size < NoiseParams.DH_LEN) {
            fail(NoiseProtocolException("NoiseXX: message 1 too short"))
        }
        return try {
            re = msg1.copyOfRange(0, NoiseParams.DH_LEN).also { ss.mixHash(it) }
            ss.decryptAndHash(msg1.copyOfRange(NoiseParams.DH_LEN, msg1.size))
            e = ephKeyFactory()
            val ePub = X25519.rawPublicKey(e!!.public)
            ss.mixHash(ePub)
            ss.mixKey(X25519.dh(e!!.private, re!!))
            s = ephKeyFactory()
            val encS = ss.encryptAndHash(X25519.rawPublicKey(s!!.public))
            ss.mixKey(X25519.dh(s!!.private, re!!))
            val encPayload = ss.encryptAndHash(payload)
            phase = Phase.MSG2_SENT
            ePub + encS + encPayload
        } catch (e: Exception) {
            fail(e)
        }
    }

    fun readMessage3(msg3: ByteArray) {
        requirePhase(Phase.MSG2_SENT, "readMessage3")
        if (msg3.size < NoiseParams.MIN_MSG3_LEN) {
            fail(NoiseProtocolException("NoiseXX: message 3 too short"))
        }
        try {
            var off = 0
            val rs = ss.decryptAndHash(msg3.copyOfRange(off, off + NoiseParams.DH_LEN + NoiseParams.TAG_LEN))
            off += NoiseParams.DH_LEN + NoiseParams.TAG_LEN
            val eKp = e ?: throw NoiseProtocolException("NoiseXX: missing responder ephemeral key")
            ss.mixKey(X25519.dh(eKp.private, rs))
            ss.decryptAndHash(msg3.copyOfRange(off, msg3.size))
            phase = Phase.MSG3_READ
        } catch (e: Exception) {
            fail(e)
        }
    }

    /**
     * Returns (send, recv) for the responder. Note the swap: the responder's
     * send key is c2, matching Python's `return c2, c1`.
     */
    fun split(): Pair<CipherState, CipherState> {
        requirePhase(Phase.MSG3_READ, "split")
        phase = Phase.SPLIT
        val (c1, c2) = ss.split()
        e = null; s = null; re = null
        return c2 to c1
    }

    fun handshakeHash(): ByteArray = ss.handshakeHash()
}
