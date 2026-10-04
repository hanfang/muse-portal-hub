package com.muse.gadget

import com.muse.gadget.api.VmInfo
import com.muse.gadget.noise.ApplicationResponse
import com.muse.gadget.noise.DecryptedFrame
import com.muse.gadget.noise.NoiseTransport
import com.muse.gadget.noise.NoiseXXResponder
import com.muse.gadget.noise.ServiceFrame
import com.muse.gadget.session.ChatSession
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Session lifecycle with a fake clock and an in-process fake VM
 * (mirrors `test_link_client.py`'s FakeVm, which does a real Noise handshake):
 * pairing-timeout is covered in [PairingSessionTest]; here we cover the WS
 * keepalive, dead detection, backoff and the token-invalid -> refresh ->
 * re-pair branches.
 */
class ChatSessionTest {
    private class FakeListener : ChatSession.Listener {
        val sentBytes = ArrayList<ByteArray>()
        var pings = 0
        var opens = 0
        var closes = 0
        val events = ArrayList<ChatSession.Event>()
        var refreshRequests = 0
        var fetchVmsRequests = 0
        val frames = ArrayList<DecryptedFrame>()
        override fun openSocket() { opens++ }
        override fun sendBytes(bytes: ByteArray) { sentBytes.add(bytes) }
        override fun sendPing() { pings++ }
        override fun closeSocket() { closes++ }
        override fun onEvent(event: ChatSession.Event) { events.add(event) }
        override fun requestTokenRefresh() { refreshRequests++ }
        override fun requestFetchVms() { fetchVmsRequests++ }
        override fun onFrame(frame: DecryptedFrame) { frames.add(frame) }
    }

    private var now = 0L
    private lateinit var listener: FakeListener
    private lateinit var session: ChatSession

    private fun newSession(
        pingMs: Long = 20_000,
        deadMs: Long = 60_000,
        backoffBaseMs: Long = 5_000,
        backoffMaxMs: Long = 120_000,
        rotateMs: Long = 3 * 3600_000,
        idleMs: Long = 10 * 60_000,
    ): ChatSession {
        listener = FakeListener()
        session = ChatSession(
            clockMs = { now },
            listener = listener,
            config = ChatSession.Config(
                pingIntervalMs = pingMs,
                deadTimeoutMs = deadMs,
                backoffBaseMs = backoffBaseMs,
                backoffMaxMs = backoffMaxMs,
                tokenRotateMs = rotateMs,
                idleCloseMs = idleMs,
            ),
        )
        session.accessToken = "access-1"
        session.refreshToken = "refresh-1"
        return session
    }

    /** Completes a real Noise handshake against an in-process responder. */
    private fun handshake(): NoiseXXResponder {
        val responder = NoiseXXResponder()
        responder.initialize()
        session.start()
        assertEquals(1, listener.opens)
        session.onSocketOpened()
        assertEquals(1, listener.sentBytes.size)
        assertEquals(32, listener.sentBytes[0].size) // msg1
        val msg2 = responder.readMessage1AndWriteMessage2(listener.sentBytes[0])
        session.onSocketBytes(msg2)
        assertEquals(2, listener.sentBytes.size)
        assertEquals(64, listener.sentBytes[1].size) // msg3
        responder.readMessage3(listener.sentBytes[1])
        assertEquals(ChatSession.State.CONNECTED, session.state)
        assertTrue(listener.events.contains(ChatSession.Event.Connected))
        assertNotNull(session.transport())
        return responder
    }

    @Test
    fun `full handshake against in-process fake vm`() {
        newSession()
        val responder = handshake()
        // exchange an application frame both ways through the real transport
        val t = session.transport()!!
        val (rSend, _) = responder.split()
        val req = t.encryptHttpRequest("POST", "/chat/stream", "{}".toByteArray())
        assertTrue(req.streamId >= 1)
        assertTrue(req.frames.isNotEmpty())
        // server -> device direction through the session path
        val replyFrame = ServiceFrame.response(1, ApplicationResponse(status = 200, endBody = true))
        val wire = NoiseTransport.encodeResponseEnvelope(replyFrame)
        for (chunk in com.muse.gadget.noise.Framing.encodeNoiseFrames(wire)) {
            session.onSocketBytes(rSend.encryptWithAd(ByteArray(0), chunk))
        }
        assertEquals(1, listener.frames.size)
        assertEquals(DecryptedFrame.Kind.RESPONSE, listener.frames[0].kind)
    }

    @Test
    fun `keepalive pings then dead detection and backoff`() {
        newSession(pingMs = 1_000, deadMs = 3_000, backoffBaseMs = 5_000)
        handshake()
        assertEquals(0, listener.pings)
        now = 1_500
        session.poll()
        assertEquals(1, listener.pings)
        // silence past the dead timeout drops the connection and backs off
        now = 61_000 // lastRx was 0
        session.poll()
        assertEquals(ChatSession.State.BACKOFF, session.state)
        assertTrue(listener.events.any { it is ChatSession.Event.Disconnected })
        val opensBefore = listener.opens
        now += 4_999
        session.poll()
        assertEquals(opensBefore, listener.opens) // not yet
        now += 1
        session.poll()
        assertEquals(opensBefore + 1, listener.opens) // reconnect
        assertEquals(ChatSession.State.CONNECTING, session.state)
    }

    @Test
    fun `server data resets the dead timer`() {
        newSession(pingMs = 1_000, deadMs = 3_000)
        val responder = handshake()
        val (rSend, _) = responder.split()
        // server sends an (empty-body) encrypted frame; any valid frame counts as data
        val replyFrame = ServiceFrame.response(1, ApplicationResponse(status = 200, endBody = true))
        val wire = NoiseTransport.encodeResponseEnvelope(replyFrame)
        now = 2_500
        for (chunk in com.muse.gadget.noise.Framing.encodeNoiseFrames(wire)) {
            session.onSocketBytes(rSend.encryptWithAd(ByteArray(0), chunk))
        }
        now = 5_000 // 2.5s after the last data: still alive
        session.poll()
        assertEquals(ChatSession.State.CONNECTED, session.state)
    }

    @Test
    fun `upgrade 401 triggers refresh then fetch_vms then reconnect`() {
        newSession()
        session.start()
        session.onUpgradeRejected(401)
        assertEquals(ChatSession.State.REFRESHING_TOKEN, session.state)
        assertEquals(1, listener.refreshRequests)

        session.completeTokenRefresh(true, "access-2", "refresh-2")
        assertEquals("access-2", session.accessToken)
        assertEquals(ChatSession.State.FETCHING_VMS, session.state)
        assertEquals(1, listener.fetchVmsRequests)
        assertTrue(listener.events.contains(ChatSession.Event.TokenRefreshed))

        val opensBefore = listener.opens
        session.completeFetchVms(
            listOf(
                VmInfo("vm-a", "wss://a", "tok-a", false),
                VmInfo("vm-b", "wss://b", "tok-b", true),
            ),
        )
        assertEquals("vm-b", session.vmId) // default wins
        assertEquals("tok-b", session.vmAuthToken)
        assertEquals(ChatSession.State.CONNECTING, session.state)
        assertEquals(opensBefore + 1, listener.opens)
    }

    @Test
    fun `failed refresh clears credentials and needs pairing`() {
        newSession()
        session.start()
        session.onUpgradeRejected(403)
        session.completeTokenRefresh(false, null, null)
        assertEquals(ChatSession.State.NEED_PAIRING, session.state)
        assertNull(session.accessToken)
        assertNull(session.refreshToken)
        assertTrue(listener.events.contains(ChatSession.Event.NeedPairing))
        // fresh pairing credentials resume the loop
        session.setCredentials("access-9", "refresh-9")
        assertEquals(ChatSession.State.CONNECTING, session.state)
    }

    @Test
    fun `non-auth upgrade rejection backs off`() {
        newSession(backoffBaseMs = 5_000)
        session.start()
        val opensBefore = listener.opens
        session.onUpgradeRejected(500)
        assertEquals(ChatSession.State.BACKOFF, session.state)
        assertEquals(0, listener.refreshRequests)
        now += 5_000
        session.poll()
        assertEquals(opensBefore + 1, listener.opens)
    }

    @Test
    fun `idle close does not auto reconnect`() {
        newSession()
        handshake()
        now = 10 * 60_000 + 1
        session.poll()
        assertEquals(ChatSession.State.IDLE, session.state)
        assertTrue(listener.events.any {
            it is ChatSession.Event.Disconnected && it.reason == "idle"
        })
        val opensBefore = listener.opens
        now += 120_000
        session.poll()
        assertEquals(opensBefore, listener.opens)
    }

    @Test
    fun `proactive token rotation at 3h`() {
        // dead/idle timers pushed out so rotation is what fires
        newSession(rotateMs = 3 * 3600_000, deadMs = 4 * 3600_000, idleMs = 4 * 3600_000)
        handshake()
        now = 3 * 3600_000L
        session.poll()
        assertEquals(ChatSession.State.REFRESHING_TOKEN, session.state)
        assertEquals(1, listener.refreshRequests)
    }

    @Test
    fun `stop is terminal`() {
        newSession()
        handshake()
        session.stop()
        assertEquals(ChatSession.State.IDLE, session.state)
        session.start()
        // start() after stop() works again (fresh user intent)
        assertEquals(ChatSession.State.CONNECTING, session.state)
    }
}
