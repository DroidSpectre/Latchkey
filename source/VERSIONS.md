# Latchkey versioning and build ledger

## Rule

- **Build number**: one per produced APK. `v1.0.0+1` is build 1.
- **versionCode**: equals the build number; it is Android's update counter and
  must always increase. A code is never reused.
- **versionName**: semantic version of the app, bumped for behavior changes.
- **Tag / folder / APK name**: `v<versionName>+<versionCode>`.
- The build script refuses to publish an existing `versionCode`; there are no
  silent `-rN` rebuild suffixes.

## Ledger

| Build | Tag | versionName | versionCode | SHA-256 | Notes |
|---|---|---|---|---|---|
| 1 | `v1.0.0+1` | 1.0.0 | 1 | `71e208eb69cf7a0f8918693569bddadd0ac89853032f3a56edb3d1e12138fb4d` | initial build |
| 2 | `v1.0.1+2` | 1.0.1 | 2 | `68ae1908b0433c38a4c7e7387d05de3a18fde90d2c0f7623d4060a97a43f3aca` | first 1.0.1 |
| 3 | `v1.0.1+2-r2` | 1.0.1 | 2 | `3a7fd7083bf141f5d9c7821e781b8d34e7f2292440ac49678aec09a14ce2242b` | hardened rebuild; code was not bumped |
| 4 | `v1.0.1+2-r3` | 1.0.1 | 2 | `21291d068ce8cabf21e0a6cd0a9455b66250459a28d590b25c8f1542aed992c2` | UI/log page rebuild; code was not bumped |
| 5 | `v1.0.1+2-r4` | 1.0.1 | 2 | `d89b527daf41d63741880af0ef9232e5b5b015725581ac6140db8117550e6ab8` | notification restart fix; code was not bumped |
| 6 | `v1.0.1+2-r5` | 1.0.1 | 2 | `b5e8cb7763339a0cac78afa6e9678f1d33702e3395a4fd2e0e96e8c1d0fff1e6` | scrollable main page restored; code was not bumped |
| 7 | `v1.0.1+2-r6` | 1.0.1 | 2 | `6ec2d5e303e03cea0889ef067e73d2b90edeea1ae2cf663272802fe4291162b9` | log-spam fix; superseded and deleted |
| 8 | `v1.0.2+8` | 1.0.2 | 8 | `5cb4c78e79e393db65cc7f4f2df75128736b2921f2f4d71c5c0b9be25ef5d3e7` | versioning fix + log-spam fix; previous |
| 9 | `v1.0.3+9` | 1.0.3 | 9 | `310635829f8523d1d64550c96fa2f2820869ef472f1c2f71ae14133a3101ad7c` | screenshots allowed; key masked by default; previous |
| 10 | `v1.0.4+10` | 1.0.4 | 10 | `894b2f40012cbe966114e226540f01f50b96dfb67593bb707d66c351c4e07f99` | tighter spacing so footer clears the nav bar; previous |
| 11 | `v1.0.5+11` | 1.0.5 | 11 | `8b5bd163c2f786cdedc4aa40e275bd4cf27c51f55f3082b0fde7c54ab24219de` | log session/update entries, per-entry app version, device metadata; previous |
| 12 | `v1.1.0+12` | 1.1.0 | 12 | `f11b237ca1ab4af15f7cb3317625aef29a11542b815073ddfb0bbe09b4cafee2` | loopback pairing, per-client keys, modern UI; superseded before install by 13 |
| 13 | `v1.1.0+13` | 1.1.0 | 13 | `a46fd785350becde0b00cf07b7149077b6a85571e7634b65b2352ce8606833f0` | disables platform button tint so custom palette renders; superseded before install by 14 |
| 14 | `v1.1.0+14` | 1.1.0 | 14 | `bd2858f2dba37dbef1971bef2b7ec7674aae2a50a11a4977390b63d4acf201c1` | darkens primary/violet/stop gradients for WCAG text contrast |
| 15 | `v1.2.0+15` | 1.2.0 | 15 | `07ddda58050266435ea2856d8546cbcc9b48f85acf28ebf2dd76b7420900cc15` | notification actions (Pair/Revoke) with status only, no key; revoke rotates legacy key and revokes paired clients; probes 24 and 26-29 verified on-device, 25 pending |
| 16 | `v1.2.0+16` | 1.2.0 | 16 | `59d09f8922d4733e56b997904ee545f144e4a4916eaca0a046804e9fd7125a58` | notification refreshes client count immediately after a successful pair |
| 18 | `v1.2.2+18` | 1.2.2 | 18 | `6badca3225006c26a2f8f973eeda600d019a86db8336dafca16d36adcdfa39cd` | adds a **Clear log** action (UI button + `logs --clear` RPC) that deletes the stored JSONL and resets the in-memory ring |
| 19 | `v1.2.3-grok+19` | 1.2.3-grok | 19 | `736e8930899514610dcb9dd984f00d784fcc8fc240c454935326560b5224cb54` | review snapshot: path-agnostic build, `Dockerfile`, `GROK_NOTES.md`; no protocol or UI behavior change; current |
| 17 | `v1.2.1+17` | 1.2.1 | 17 | `29340fcaaa22255b8bc086cbb3f0bd3fe9684ee9cf8cb50d7bda95606f19d0e0` | Stop keeps the foreground notification as `Key · Stale · N clients` with Start/Revoke; start restores Pair |

Starting with build 16, each release directory also contains
`Latchkey-<tag>-source.tar.gz`, a complete source snapshot excluding the debug
keystore, bundled build tools, and build output. Builds 1-15 were APK-only;
their directories carry `SOURCE_UNAVAILABLE.txt` because their exact source was
not preserved.

Build 8 replaces an intermediate `v1.0.2+3` mis-stamp (versionCode 3, SHA-256
`be6a7cc948a8ad3af925bb2f13583d457a6bdb0518fd6cd63f6be309b701d26d`), which was
discarded before installation.

## Why builds 3-7 shared `versionCode=2`

They were rebuilds published while the version fields were left untouched; the
`-rN` suffix was only added to the release folder name, so Android and the app
still saw every one as `1.0.1 (2)`. Build 8 is the first artifact stamped with
its true ordinal.
| 20 | `v1.3.0-C+20` | 1.3.0-C | 20 | `f5aa7ff874592de0d197d86405b927c6258d87a4766be1038bac0975eb69f855` | LocalKey 1.3.0 variant C UI/UX migration (4 pages, tabs + switchable drawer, teal theme); backend unchanged; debug-signed with a new key |
