package com.muse.gadget.api

import com.muse.gadget.identity.Identity
import com.muse.gadget.util.Json
import com.muse.gadget.util.JsonValue
import com.muse.gadget.util.boolField
import com.muse.gadget.util.field
import com.muse.gadget.util.strField

/** One leased VM entry from `fetch_vms`. */
data class VmInfo(
    val vmId: String,
    val wsUrl: String,
    val authToken: String,
    val isDefault: Boolean,
)

/** `fetch_vms` / `device_token/refresh` URL builders and body parsers (spec §2.1-2.2). */
object MuseAccountApi {
    fun apiRoot(apiUrlV2: String = ""): String =
        (apiUrlV2.ifEmpty { Identity.API_BASE }).trimEnd('/')

    fun fetchVmsUrl(root: String): String = root + Identity.FETCH_VMS_PATH

    fun refreshUrl(root: String): String = root + Identity.REFRESH_PATH

    /**
     * Strips an existing `xxx:` prefix: `rsplit(":",1)[-1]`.
     * The refresh Authorization header is `Bearer hatch_refresh:<raw>`.
     */
    fun stripRefreshPrefix(refreshToken: String): String =
        refreshToken.substringAfterLast(':')

    fun refreshAuthHeader(refreshToken: String): String =
        "Bearer ${Identity.REFRESH_AUTH_PREFIX}${stripRefreshPrefix(refreshToken)}"

    fun refreshBody(deviceId: String, sdkToken: String?): String {
        val fields = LinkedHashMap<String, JsonValue>()
        fields["device_id"] = Json.str(deviceId)
        if (sdkToken != null) fields["sdk_token"] = Json.str(sdkToken)
        return Json.stringify(JsonValue.Obj(fields))
    }

    /** Parses the refresh response; returns (access_token, refresh_token) or null. */
    fun parseRefreshResponse(body: String): Pair<String, String>? {
        val root = try {
            Json.parseObj(body)
        } catch (e: Exception) {
            return null
        }
        val payload = (root.field("payload") as? JsonValue.Obj) ?: root
        val access = payload.strField("access_token") ?: return null
        val refresh = payload.strField("refresh_token") ?: return null
        return access to refresh
    }

    /** Parses `vm_list`; entries missing url+token are skipped. */
    fun parseVmList(body: String): List<VmInfo> {
        val root = try {
            Json.parseObj(body)
        } catch (e: Exception) {
            return emptyList()
        }
        if (root.strField("error_title") != null || root.strField("backend_error_code") != null) {
            return emptyList()
        }
        val list = root.field("vm_list") as? JsonValue.Arr ?: return emptyList()
        return list.items.mapNotNull { item ->
            val obj = item as? JsonValue.Obj ?: return@mapNotNull null
            val url = obj.strField("vm_ws_url") ?: obj.strField("vm_url") ?: return@mapNotNull null
            val token = obj.strField("vm_auth_token") ?: return@mapNotNull null
            var vmId = obj.strField("vm_id") ?: ""
            if (vmId.isEmpty()) vmId = vmIdFromUrl(url)
            VmInfo(vmId, url, token, obj.boolField("default") == true)
        }
    }

    /** Selects the `default` VM, else the first. */
    fun selectVm(vms: List<VmInfo>): VmInfo? =
        vms.firstOrNull { it.isDefault } ?: vms.firstOrNull()

    /** vm_id fallback: first DNS label of the ws URL host. */
    fun vmIdFromUrl(url: String): String {
        val noScheme = url.substringAfter("://", url)
        val host = noScheme.substringBefore('/').substringBefore(':')
        return host.substringBefore('.')
    }
}
