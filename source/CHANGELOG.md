# Changelog

## 1.3.0-C (versionCode 20) — UI/UX migration to LocalKey 1.3.0 variant C

Base: Latchkey 1.2.3-grok (versionCode 19), from `LatchKey_v1.2.3_grok-source-and-apk.tar.gz`
in DroidSpectre/Latchkey @ f10123b7ec0ea67370d37f582fd05f9bef82e49a.
Reference: `LocalKey-1.3.0-source-and-apks.zip` in the same commit, `flavors/C/Flavor.java`
(VARIANT=C, DEFAULT_LAYOUT=tabs, LAYOUT_SWITCH=true).

### Changed (UI only)
- Single scrolling `activity_main.xml` screen replaced by a code-built four-page shell:
  **Home / Connect / Audit / Settings**, ported from LocalKey `MainActivity` (buildShell,
  buildTabShell, buildDrawerShell, appBar, bottomNav, buildDrawer, selectPage, open/closeDrawer).
- Navigation: bottom tabs by default; Settings → "Navigation layout" switches to a slide-in
  navigation drawer (scrim, 220 ms animation). Choice persists in SharedPreferences
  `latchkey_ui/layout_mode`. Back closes drawer, then returns to Home, then exits.
  Active page survives rotation (`onSaveInstanceState`).
- Theme: LocalKey teal palette (`#070B12` bg, `#2DD4BF` teal, `#9B7CFF` violet), `AppTheme`
  updated, new `LatchkeyDialog` alert theme with `lk_dialog_bg`. `values-night` removed
  (app was already dark-only; the single theme is used in both modes).
- Components: new `Ui.java` (verbatim port of LocalKey `Ui.java`, package-private):
  cards, gradients, pills, icon boxes, ripple buttons (primary/secondary/danger/muted).
- Icons: LocalKey vector drawables ic_battery, ic_bell, ic_check, ic_chevron, ic_close,
  ic_folder, ic_home, ic_key, ic_link, ic_log, ic_menu, ic_settings, ic_shield.
  Removed unused `bg_*` drawables and `layout/activity_main.xml`. Launcher icon unchanged.

### Page mapping (all actions call the unchanged 1.2.3 code paths)
- **Home**: server status card (dot, ONLINE/OFFLINE/ERROR pill, endpoint + uptime,
  Start/Stop, request/byte/auth-fail stats); Device readiness card (file access → all-files
  settings; notifications → permission request / app notification settings [new UI entry
  point]; battery → battery-optimization exemption) with an N/3 / READY pill.
- **Connect**: Pair assistant (single-use 2-min link copied to clipboard, unchanged);
  paired clients card (count, name / fingerprint prefix / date list read from
  `PairStore.list`, "Revoke all & rotate key" with the existing confirmation);
  legacy key card (fingerprint, masked key, Reveal/Hide, Copy, Rotate with confirmation).
- **Audit**: activity log card (View log dialog, Export JSONL, Clear with confirmation)
  and inline "Recent events" (latest 80 via `EventLog.snapshotText`).
- **Settings**: navigation layout chooser (A tabs / B drawer) and About (version, code,
  UI variant, endpoint, package).

### Accessibility / insets
- Root shell padded for system bars **and display cutout** on all four edges
  (API 30+ `WindowInsets.Type`, legacy system-window insets below).
- 48dp minimum touch targets for actions, nav icon buttons, readiness actions.
- Content descriptions on nav items ("…, selected"), menu/close buttons, key view,
  copy/rotate buttons, layout choices; decorative icons hidden from TalkBack;
  page titles marked as accessibility headings (API 28+); live regions for server
  status and pairing hint; page content hidden from accessibility while the drawer is open.
- Tapjacking guard: `setFilterTouchesWhenObscured(true)` on the whole view tree (from LocalKey).
- Key is re-masked when the activity pauses (LocalKey behavior).

### Not changed
- Package `io.latchkey.bridge`, app name "Latchkey", minSdk 26, targetSdk 35, permissions,
  service, notification actions, RPC protocol, `LATCHKEY/1` AAD, pairing, PairStore,
  KeyStoreManager, FileApi, EventLog, RpcServer/RpcHandler. Only `ServerRuntime.VERSION`
  and the client `CLIENT_VERSION` string were bumped to `1.3.0-C`.

### Version
- versionName `1.3.0-C`, versionCode **20** (was 19). `next-version.properties`,
  `AndroidManifest.xml`, `ServerRuntime.VERSION` and `client/latchkey.mjs` agree.
