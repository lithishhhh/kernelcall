package com.kernelcall.app.engines.staticengine

/**
 * Static knowledge about Android permission strings. Declaring a permission is
 * a CONFIRMED observation; the note here is only advisory wording.
 */
object PermissionRisk {

    private val NOTES: Map<String, String> = mapOf(
        "android.permission.RECORD_AUDIO"
            to "Can capture microphone audio once granted (runtime permission).",
        "android.permission.CAMERA"
            to "Can capture images/video once granted (runtime permission).",
        "android.permission.ACCESS_FINE_LOCATION"
            to "Can read precise user location once granted (runtime permission).",
        "android.permission.ACCESS_COARSE_LOCATION"
            to "Can read approximate user location once granted (runtime permission).",
        "android.permission.READ_CONTACTS"
            to "Can read the device contact list.",
        "android.permission.WRITE_CONTACTS"
            to "Can modify the device contact list.",
        "android.permission.READ_PHONE_STATE"
            to "Can access phone identity and call state.",
        "android.permission.READ_CALL_LOG"
            to "Can read call history metadata.",
        "android.permission.READ_SMS"
            to "Can read SMS content on the device.",
        "android.permission.SEND_SMS"
            to "Can send SMS on behalf of the user.",
        "android.permission.RECEIVE_SMS"
            to "Can receive SMS content in the background.",
        "android.permission.RECEIVE_BOOT_COMPLETED"
            to "Code can start automatically after device reboot.",
        "android.permission.SYSTEM_ALERT_WINDOW"
            to "Can draw over other apps (a known tapjacking primitive).",
        "android.permission.QUERY_ALL_PACKAGES"
            to "Can enumerate all installed apps; rarely needed legitimately.",
        "android.permission.WRITE_SETTINGS"
            to "Can modify system settings.",
        "android.permission.INSTALL_PACKAGES"
            to "Signature-level install capability; unusual outside app stores.",
        "android.permission.FOREGROUND_SERVICE"
            to "Declares foreground services; confirm the use case is user-visible.",
    )

    /** Short user-facing note when the permission deserves attention, else null. */
    fun noteFor(permission: String): String? = NOTES[permission]
}
