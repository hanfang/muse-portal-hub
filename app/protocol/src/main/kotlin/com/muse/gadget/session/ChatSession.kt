package com.muse.gadget.session

import com.muse.gadget.api.VmInfo
import com.muse.gadget.noise.DecryptedFrame
import com.muse.gadget.noise.NoiseTransport
import com.muse.gadget.noise.NoiseXXInitiator

/**
 * Connection lifecycle: WS upgrade -> Noise XX -> keepalive / reconnect /
 * token refresh (spec §4). Fully deterministic: time comes from [clockMs] and
 * all socket I/O goes through [Listener], so tests drive it with a fake.
 *
 * Stream multiplexing (chat/subscribe) is the owner's job via [transport];
 * this class owns the socket, the handshake and the timers.
 */
class ChatSession(
    private val clockMs: () -> Long = { System.currentTimeMillis() },
    private val listener: Listener,
    private val config: Config = Config(),
) {
    data class Config(
        val pingIntervalMs: Long = 20_000,
        val deadTimeoutMs: Long = 60_000,
        val handshakeTimeoutMs: Long = 20_000,
        val idleCloseMs: Long = 10 * 60_000,
        val backoffBaseMs: Long = 5_000,
        val backoffMaxMs: Long = 120_000,
        /** Proactive device-token rotation (spec: ~3h of ~4h lifetime). */
        val tokenRotateMs: Long = 3 * 3600_000,
    )

    interface Listener {
        fun openSocket()
        fun sendBytes(bytes: ByteArray)
        fun sendPing()
        fun closeSocket()
        fun onEvent(event: Event)
        fun requestTokenRefresh()
        fun requestFetchVms()
        fun onFrame(frame: DecryptedFrame)
    }

    sealed interface Event {
        data object Connected : Event
        data class Disconnected(val reason: String) : Event
        data object NeedPairing : Event
        data object TokenRefreshed : Event
    }

    enum class State {
        IDLE, CONNECTING, HANDSHAKE, CONNECTED, BACKOFF,
        REFRESHING_TOKEN, FETCHING_VMS, NEED_PAIRING,
    }

    var state: State = State.IDLE
        private set

    /** Credentials from pairing; refreshed in place. */
    var accessToken: String? = null
    var refreshToken: String? = null
    var vmId: String = ""
    var vmAuthToken: String = ""
    var noiseHost: String = com.muse.gadget.identity.Identity.DEFAULT_NOISE_HOST

    private var initiator: NoiseXXInitiator? = null
    private var transport: NoiseTransport? = null
    private var lastRxMs: Long = 0
    private var lastPingSentMs: Long = 0
    private var lastActivityMs: Long = 0
    private var tokenAcquiredAtMs: Long = 0
    private var handshakeStartMs: Long = 0
    private var backoffAtMs: Long = 0
    private var backoffMs: Long = config.backoffBaseMs
    private var stopped = false

    fun transport(): NoiseTransport? = transport

    // -- driven by the owner ---------------------------------------------------

    fun start() {
        if (state != State.IDLE) return
        stopped = false
        connect()
    }

    fun stop() {
        stopped = true
        transport = null
        state = State.IDLE
        listener.closeSocket()
    }

    /** Credentials changed (fresh pairing); usable from NEED_PAIRING/IDLE. */
    fun setCredentials(access: String, refresh: String) {
        accessToken = access
        refreshToken = refresh
        tokenAcquiredAtMs = clockMs()
        if (state == State.NEED_PAIRING) {
            state = State.IDLE
            start()
        }
    }

    fun onSocketOpened() {
        if (state != State.CONNECTING) return
        state = State.HANDSHAKE
        handshakeStartMs = clockMs()
        initiator = NoiseXXInitiator().also { it.initialize() }
        listener.sendBytes(initiator!!.writeMessage1())
    }

    fun onSocketBytes(data: ByteArray) {
        when (state) {
            State.HANDSHAKE -> {
                val init = initiator ?: return
                try {
                    init.readMessage2(data)
                    listener.sendBytes(init.writeMessage3())
                    val (send, recv) = init.split()
                    transport = NoiseTransport(send, recv)
                    initiator = null
                    state = State.CONNECTED
                    val now = clockMs()
                    lastRxMs = now
                    lastPingSentMs = now
                    lastActivityMs = now
                    backoffMs = config.backoffBaseMs
                    listener.onEvent(Event.Connected)
                } catch (e: Exception) {
                    drop("handshake failed: ${e.message}")
                }
            }
            State.CONNECTED -> {
                val t = transport ?: return
                try {
                    val frame = t.decryptFrame(data)
                    lastRxMs = clockMs()
                    lastActivityMs = lastRxMs
                    if (frame != null) listener.onFrame(frame)
                } catch (e: Exception) {
                    drop("transport failed: ${e.message}")
                }
            }
            else -> Unit
        }
    }

    fun onSocketClosed() {
        if (state == State.CONNECTED || state == State.HANDSHAKE || state == State.CONNECTING) {
            drop("socket closed")
        }
    }

    /** The WS upgrade was rejected with an HTTP status. */
    fun onUpgradeRejected(status: Int) {
        if (state != State.CONNECTING && state != State.HANDSHAKE) return
        transport = null
        if (status == 401 || status == 403) {
            state = State.REFRESHING_TOKEN
            listener.requestTokenRefresh()
        } else {
            scheduleBackoff()
        }
    }

    fun completeTokenRefresh(ok: Boolean, access: String?, refresh: String?) {
        if (state != State.REFRESHING_TOKEN) return
        if (ok && access != null && refresh != null) {
            accessToken = access
            refreshToken = refresh
            tokenAcquiredAtMs = clockMs()
            state = State.FETCHING_VMS
            listener.onEvent(Event.TokenRefreshed)
            listener.requestFetchVms()
        } else {
            accessToken = null
            refreshToken = null
            transport = null
            state = State.NEED_PAIRING
            listener.onEvent(Event.NeedPairing)
        }
    }

    fun completeFetchVms(vms: List<VmInfo>) {
        if (state != State.FETCHING_VMS) return
        val vm = vms.firstOrNull { it.isDefault } ?: vms.firstOrNull()
        if (vm == null) {
            scheduleBackoff()
            return
        }
        vmId = vm.vmId
        vmAuthToken = vm.authToken
        connect()
    }

    /** Advances timers: keepalive pings, dead detection, backoff, rotation. */
    fun poll() {
        val now = clockMs()
        when (state) {
            State.CONNECTED -> {
                // Idle-close is checked first: a deliberate graceful shutdown
                // after user inactivity wins over dead-timeout when both fire.
                if (now - lastActivityMs >= config.idleCloseMs) {
                    transport = null
                    state = State.IDLE
                    listener.closeSocket()
                    listener.onEvent(Event.Disconnected("idle"))
                } else if (now - lastRxMs >= config.deadTimeoutMs) {
                    drop("dead: no data for ${config.deadTimeoutMs}ms")
                } else {
                    if (now - lastPingSentMs >= config.pingIntervalMs) {
                        lastPingSentMs = now
                        listener.sendPing()
                    }
                    if (now - tokenAcquiredAtMs >= config.tokenRotateMs &&
                        refreshToken != null
                    ) {
                        state = State.REFRESHING_TOKEN
                        listener.requestTokenRefresh()
                    }
                }
            }
            State.HANDSHAKE -> {
                if (now - handshakeStartMs >= config.handshakeTimeoutMs) {
                    drop("handshake timeout")
                }
            }
            State.BACKOFF -> {
                if (!stopped && now >= backoffAtMs) connect()
            }
            else -> Unit
        }
    }

    // -- internals ---------------------------------------------------------------

    private fun connect() {
        if (stopped) return
        transport = null
        initiator = null
        state = State.CONNECTING
        listener.openSocket()
    }

    private fun drop(reason: String) {
        transport = null
        initiator = null
        listener.closeSocket()
        listener.onEvent(Event.Disconnected(reason))
        scheduleBackoff()
    }

    private fun scheduleBackoff() {
        if (stopped) {
            state = State.IDLE
            return
        }
        state = State.BACKOFF
        backoffAtMs = clockMs() + backoffMs
        backoffMs = minOf(backoffMs * 2, config.backoffMaxMs)
    }
}
