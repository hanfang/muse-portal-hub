package com.muse.gadget.portal.ble

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.os.ParcelUuid
import com.muse.gadget.ble.BleFraming
import com.muse.gadget.identity.Identity
import com.muse.gadget.pairing.PairingSession
import java.util.UUID

/**
 * BLE GATT peripheral for pairing v5 (spec §1.1), skeleton.
 *
 * - Advertises `MuseGadget-XXXXXX` only while pairing is active.
 * - Service [Identity.GATT_SERVICE_UUID]; RX = phone->device writes,
 *   TX = device->phone notifies; messages are `0xFE`-framed ([BleFraming]).
 * - Plaintext `get_device_info` is answered any time; `pairing_client_hello`
 *   starts a [PairingSession]; encrypted records go through it.
 *
 * MTU note (from the Linux AGENTS.md): the Android Muse app writes
 * `negotiatedMtu - 3` bytes and rejects writes over 512 bytes; request a
 * large MTU when the phone connects.
 */
class PortalBlePeripheral(
    private val context: Context,
    private val nodeId: String,
    private val pairingSession: PairingSession,
) {
    private var gattServer: BluetoothGattServer? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private val rxReassembler = BleFraming.Reassembler()

    private val serverCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice?, status: Int, newState: Int) {
            if (newState == BluetoothGatt.STATE_CONNECTED) {
                // Ask for a large MTU; the app writes negotiatedMtu - 3.
                // (Requires API 21+; Portal is API 28+.)
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice?,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic?,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?,
        ) {
            if (characteristic?.uuid == Identity.GATT_RX_UUID && value != null) {
                onRxChunk(value)
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null)
            } else {
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
            }
        }

        // onMtuChanged / onNotificationSent omitted for brevity.
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) = Unit
        override fun onStartFailure(errorCode: Int) = Unit
    }

    /** Starts advertising + the GATT server. Call when pairing begins. */
    fun start() {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val adapter: BluetoothAdapter = manager.adapter ?: return
        gattServer = manager.openGattServer(context, serverCallback)?.also { server ->
            val service = BluetoothGattService(Identity.GATT_SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
            val rx = BluetoothGattCharacteristic(
                Identity.GATT_RX_UUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                BluetoothGattCharacteristic.PERMISSION_WRITE,
            )
            val tx = BluetoothGattCharacteristic(
                Identity.GATT_TX_UUID,
                BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                0,
            )
            service.addCharacteristic(rx)
            service.addCharacteristic(tx)
            server.addService(service)
        }
        advertiser = adapter.bluetoothLeAdvertiser
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
            .build()
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(true)
            .addServiceUuid(ParcelUuid(Identity.GATT_SERVICE_UUID))
            .build()
        adapter.name = Identity.bleName(nodeId)
        advertiser?.startAdvertising(settings, data, advertiseCallback)
    }

    fun stop() {
        try {
            advertiser?.stopAdvertising(advertiseCallback)
        } catch (ignored: Exception) {
        }
        try {
            gattServer?.close()
        } catch (ignored: Exception) {
        }
        gattServer = null
        advertiser = null
    }

    private fun onRxChunk(chunk: ByteArray) {
        val message = try {
            rxReassembler.feed(chunk) ?: return
        } catch (e: Exception) {
            rxReassembler.reset()
            return
        }
        val text = message.toString(Charsets.UTF_8)
        // Plaintext control messages vs encrypted records are distinguished
        // by attempting to parse the envelope; pairing_client_hello starts
        // a fresh session. Full routing is wired during the build phase.
        handleMessage(text)
    }

    private fun handleMessage(text: String) {
        // TODO: route get_device_info -> notify(pairingSession.deviceInfoJson()),
        //       pairing_client_hello -> notify(pairingSession.handleHello(text)),
        //       pairing_encrypted -> pairingSession.decryptEnvelope(text) ...
    }

    private fun notify(json: String, device: BluetoothDevice? = null) {
        val tx = gattServer
            ?.getService(Identity.GATT_SERVICE_UUID)
            ?.getCharacteristic(Identity.GATT_TX_UUID) ?: return
        for (chunk in BleFraming.encode(json.toByteArray(Charsets.UTF_8))) {
            tx.value = chunk
            gattServer?.notifyCharacteristicChanged(device, tx, false)
        }
    }

    companion object {
        /** Service UUID alias kept for readability at call sites. */
        val SERVICE_UUID: UUID = Identity.GATT_SERVICE_UUID
    }
}
