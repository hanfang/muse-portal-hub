package com.muse.gadget.portal

import android.app.Application

/** Application entry point; owns the long-lived voice-satellite components. */
class PortalApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // TODO: start the foreground VoiceService (mic + ChatSession) here.
    }
}
