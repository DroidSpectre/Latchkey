# Latchkey Protocol v1

## Transport

- Server: `127.0.0.1:39401` (loopback only, IPv4).
- `GET /health` — plaintext JSON, no key.
- `POST /pair` — plaintext pairing exchange for loopback clients.
- `POST /rpc` — encrypted request and response.
- `Content-Length` is required on `/rpc` and `/pair`. RPC requests larger than
  8 MiB and pairing requests larger than 16 KiB are rejected with HTTP 413.
- Every connection is closed after one request (`Connection: close`).
- The server rejects non-loopback `Host` headers (403), `Transfer-Encoding`,
  duplicate headers, and requires no `Expect` header; it enforces a
  30 s read timeout and a 60 s absolute connection deadline.

## Envelope

```
request/response = nonce[12] || ciphertext[n] || tag[16]
```

- Cipher: AES-256-GCM
- AAD for the legacy key: ASCII `LATCHKEY/1`
- AAD for a paired client: ASCII `LATCHKEY/1|client:<clientId>`
- Nonce: 12 random bytes
- Tag: 16 bytes, appended after the ciphertext
- Key: 32 random bytes, encoded as 43 base64url characters without padding

The same key and AAD encrypt the response. A response that cannot be decrypted
means the key is wrong, the client id is wrong, or the response was tampered
with.

The encoded form must round-trip exactly: a decoded `base64url` string must be
its own canonical encoding; trailing or extra characters are rejected.

## Paired-client authentication

A paired client sends its random client id in an HTTP header:

```
X-Latchkey-Client: <16-64 lowercase hex characters>
```

The server looks up the wrapped per-client key in `latchkey-pairing`
SharedPreferences, unwraps it with the Android Keystore key
`latchkey_client_kek_v1` (AAD = the client id), and uses
`LATCHKEY/1|client:<clientId>` as the envelope AAD. Revocation removes the
record; the next request with that header returns HTTP 401. The legacy key
continues to use `LATCHKEY/1` and needs no header.

Client ids are chosen by the client (16 random bytes, lowercase hex). They are
identifiers, not secrets.

## Pairing

`POST /pair` is a plaintext JSON exchange available only on the loopback
listener. It is used once to obtain a per-client key. The request is:

```json
{
  "v": 1,
  "token": "<43 base64url characters>",
  "client": {
    "id": "<32 lowercase hex characters>",
    "name": "Assistant name",
    "platform": "linux"
  }
}
```

The token comes from a link created by the app's **Pair assistant** button:

```
latchkey://pair?scope=loopback&v=1&id=<hostId>&name=<device>&host=127.0.0.1
  &port=39401&fp=<app-cert-fingerprint>&tok=<token>&exp=<unix-ms>
```

- The token is 32 random bytes, valid for 120 seconds, single-use, and stored
  in memory only as a SHA-256 hash.
- Five bad attempts lock pairing for 60 seconds and invalidate the token.
- Request bodies are capped at 16 KiB.
- The link itself is a bearer secret until it is consumed or expires. The app
  copies it to the clipboard as a sensitive clip; it is never logged.

Success returns:

```json
{
  "ok": true,
  "v": 1,
  "clientId": "<32 lowercase hex characters>",
  "clientName": "Assistant name",
  "key": "<base64url nonce||ciphertext||tag>",
  "fingerprint": "0123456789ABCDEF",
  "serverTime": 1762345679000
}
```

`key` decrypts to the raw 32-byte client key. It is encrypted with
`SHA-256(token)` as the AES-256-GCM key and
`LATCHKEY/PAIR/1|<clientId>` as AAD. The client verifies `clientId` and the
short fingerprint before storing the key in
`~/.config/latchkey/credentials.json` (mode 0600). Later RPC calls load that
file automatically.

Pairing errors use HTTP 400, 403 (`NO_LINK`, `EXPIRED`, `BAD_TOKEN`), 409
(`ALREADY_PAIRED`), or 429 (`PAIR_LOCKED`). Error bodies are plaintext JSON and
never contain the token or key.

## Request JSON

```json
{
  "v": 1,
  "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "ts": 1762345678901,
  "op": "list",
  "path": "/sdcard/Download"
}
```

- `v` must be `1`.
- `id` must be 8–64 characters and unique within the replay window.
- `ts` is milliseconds since the Unix epoch. The server allows ±5 minutes.
- The server remembers IDs for 5 minutes. A duplicate returns `REPLAY`.
- `op` selects the operation. Additional fields are operation parameters.
- Paired clients include `X-Latchkey-Client`; legacy clients do not.

## Response JSON

Success:

```json
{
  "ok": true,
  "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "serverTime": 1762345679000,
  "...": "operation-specific fields"
}
```

**Responses also bind to the request:** the `id` field must match the
request's `id`, and `serverTime` must be within ±5 minutes of `ts`. A mismatch
is treated as an authentication failure (HTTP 401).

RPC-level failure (still HTTP 200, still encrypted):

```json
{
  "ok": false,
  "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "code": "NOT_FOUND",
  "error": "no such path: /sdcard/nope",
  "serverTime": 1762345679000
}
```

HTTP 401 is returned when the request body cannot be decrypted. It has a
plaintext JSON body `{"ok":false,"error":"unauthorized"}`.

## Health

`GET /health` returns:

```json
{
  "app": "latchkey",
  "ok": true,
  "version": "1.1.0",
  "port": 39401,
  "uptimeMs": 123456,
  "requests": 42
}
```

The request counter is incremented for health calls as well; the value shown is
the count before the current health call is recorded.

## Operations

### `ping`

No parameters.

Response adds: `app`, `version`, `time`, `port`, `uptimeMs`,
`keyFingerprint`.

### `info`

No parameters.

Response adds:

- `versionName`, `versionCode`
- `device`: `manufacturer`, `model`, `release`, `sdk`
- `storage`: `path`, `totalBytes`, `freeBytes`, `availableBytes`
- `roots`: array of `{label, path, canonical, readable, writable}`
- `access`: `allFiles`, `read`, `write`
- `server`: `uptimeMs`, `requests`, `bytesIn`, `bytesOut`, `authFailures`,
  `keyFingerprint`

### `list`

Parameters: `path`, optional `offset` (default 0), optional `limit` (default
2000, max 20000).

Response: `path`, `total`, `offset`, `limit`, `truncated`, `entries`.

Each entry: `name`, `path`, `type` (`dir`/`file`/`link`/`other`), `symlink`,
`size`, `mtime`, `hidden`, `canRead`, `canWrite`, `canExecute`, `canonical`.
Symlinks also include `target` and `targetType`. Directories sort before files,
then case-insensitive name.

### `stat`

Parameters: `path`.

Response: the same fields as a list entry, plus `created`, `accessed`,
`modified` when available.

### `read`

Parameters: `path`, optional `offset` (default 0), optional `length` (default
1 MiB, max 4 MiB).

Response: `path`, `offset`, `nextOffset`, `eof`, `size`, `mtime`, `data`
(base64 of the requested slice).

An offset beyond EOF returns an empty `data` with `eof: true`. Reading a
directory returns `IS_DIRECTORY`.

### `write`

Parameters: `path`, `data` (base64), optional `offset` (default 0), `append`,
`truncate`, `mkdirs`, `fsync`.

Semantics:

- `truncate=true` sets the file length to zero before writing.
- `append=true` writes at the current end of file.
- Otherwise writes at `offset`.
- A write without `truncate` or `append` overwrites in place and leaves any
  trailing bytes.

Response: `path`, `offset`, `written`, `size`, `mtime`.

### `mkdir`

Parameters: `path`.

Creates the directory and missing parents. Response: `path`, `created`.

### `delete`

Parameters: `path`, optional `recursive`, optional `force`.

- Non-empty directories require `recursive=true`.
- Immutable protected roots (`/`, `/sdcard`, `/storage`, `/data`, `/system`,
  `/vendor`, `/product`, `/apex`, `/proc`, `/sys`, `/dev`, `/mnt`, `/metadata`)
  and app-private prefixes refuse any destructive operation unless
  `force=true`.
- Force-only protected roots (`/sdcard/Android`, `/sdcard/Android/data`,
  `/sdcard/Android/obb`, `/sdcard/emulated`) require `force=true`.

Response: `path`, `deleted` (number of paths removed).

### `move`

Parameters: `from`, `to`, optional `overwrite`, `mkdirs` (default true),
`force`.

Uses an atomic rename when possible and falls back to copy + delete across
filesystems. Rejects a destination that is the source or inside the source.
Protected source and destination roots require `force=true`.

Response: `from`, `to`.

### `copy`

Parameters: `from`, `to`, optional `overwrite`, `mkdirs` (default true),
`force`.

Recursively copies directories. Rejects a destination that is the source or
inside the source. Force is required to write into force-only protected roots.

Response: `from`, `to`, `copied` (number of files copied).

### `search`

Parameters: `path`, optional `name` (case-insensitive substring), `glob`,
`caseSensitive`, `dirs` (default true), `files` (default true), `hidden`
(default true), `maxDepth` (default 16, max 64), `limit` (default 200, max
5000).

Response: `root`, `matches`, `truncated`, `timedOut`, `limit`.

Search does not follow symlinks. It honors `--maxDepth` (`maxDepth` 1–64) and
hijacks the 15 s time budget; if exceeded it reports `timedOut` and stops.

### `logs`

Parameters: `tail` (integer 1–5000, default 500), optional `since`
(millisecond timestamp), `minLevel` (DEBUG/INFO/WARN/ERROR, default all),
`cat` (category filter). Optional positional `-o <file>` writes raw JSONL to a
file instead of printing formatted lines.

Response: `entries` (array of `{t, level, cat, event, msg, v, data}`), `count`,
`matched`, `tail`, `since`, `nextSince`, `truncated`, `files` (files
participating in the log), and the current log file inventory.

Each entry carries its event time (`t`), `level`, `category` (`cat`), event
name (`event`), free text message (`msg`), and up to `data` metadata only.
Entries written by 1.0.5+ also carry the app version tag (`v`, for example
`1.0.5+11`). No file contents or keys are logged. Each app process start
records an `app/session` entry with versionName, versionCode, package, device
model/manufacturer, Android release, and SDK; the first start after an update
also records an `app/update` entry with the from/to versions.

## Error Codes

| Code | Meaning |
|---|---|
| `BAD_VERSION` | `v` is not 1 |
| `BAD_REQUEST` | missing/invalid `id` |
| `BAD_CLOCK` | missing timestamp or outside ±5 minutes |
| `REPLAY` | duplicate `id` inside the replay window |
| `BAD_OP` | unknown operation |
| `BAD_ARGUMENT` | missing or invalid parameter |
| `NOT_FOUND` | path does not exist |
| `NOT_DIRECTORY` | expected a directory |
| `IS_DIRECTORY` | expected a file |
| `ALREADY_EXISTS` | destination exists and overwrite is false |
| `NOT_EMPTY` | directory not empty and recursive is false |
| `PERMISSION_DENIED` | filesystem/all-files access denied |
| `PROTECTED_PATH` | destructive operation on an immutable/protected root without force |
| `INTERNAL` | unexpected server-side failure |

HTTP codes returned by the server: 200 success, 201 service unavailable (pool
full), 400 malformed request, 401 unauthorized, 403 forbidden (non-loopback host
or bad method), 404 not found, 408 timeout, 411 length required, 413 too
large, 414 target too long, 417 expectation unsupported, 431 headers too large.

## Client Key Handling

- `--key <key>` or `LATCHKEY_KEY`
- `--key-file <file>` reads the key from a file and warns if the file is
  group/world-readable; it never prints the key itself.
- Only `127.0.0.1` or `localhost` may be used as the loopback address.
- The client verifies that every server response carries the matching `id` and a
  `serverTime` within ±5 minutes of the request timestamp; otherwise it treats
  it as an auth failure.
- Key form is validated strictly: exactly 43 base64url characters that decode
  canonically to 32 bytes. No plaintext fallback exists anywhere.

The Node client uses `crypto.randomUUID()` for `id` and `Date.now()` for `ts`.
It does not retry a failed request with the same ID.
