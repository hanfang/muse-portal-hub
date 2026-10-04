package com.muse.gadget.portal

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Restarts the voice service after reboot (mirrors portal-room-os BootReceiver). */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            // TODO: start VoiceService as a foreground service.
        }
    }
}
