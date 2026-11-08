# Migration notes: 1.2.3-grok → 1.3.0-C

## Installing
The APK is **debug-signed** with a keystore generated during this build
(CN=Latchkey Debug; cert SHA-256 2c70688041ceaa9e6784feed536020cb8dc4d170f47d1c65e0b845996ec60255).
It is NOT signed with the 1.2.3-grok or 1.2.2 key, so Android will refuse to install it
as an update. **Uninstall the existing Latchkey first.** Uninstalling clears paired
clients and the legacy key: re-pair assistants afterwards
(`node client/latchkey.mjs pair --clipboard`). The keystore is not shipped; rebuilding
from source generates a new key (another uninstall needed).

## For developers
- UI lives in `MainActivity.java` (shell + pages + state refresh) and `Ui.java`
  (design tokens + components). There is no layout XML.
- Business actions (pairAssistant, confirmRevokeClients, copyKey, confirmRegenerate,
  showLog, exportLog, clearLog, startServer, openAllFilesSettings,
  requestBatteryExemption, hasAllFilesAccess) are byte-for-byte the 1.2.3 methods.
- Layout preference: SharedPreferences `latchkey_ui`, key `layout_mode` = `tabs` | `drawer`.
- Not ported from LocalKey (backend/scope): per-client single revoke, versioned audit
  schema, "Copy visible" audit, LocalKey service/RPC/PathGuard, notification-intent
  routing to the Connect page.
